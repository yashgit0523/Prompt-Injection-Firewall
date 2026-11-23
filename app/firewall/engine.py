"""The input firewall engine.

Orchestrates every detection layer for one piece of content and returns a
fully explainable ``AnalysisResult``::

    Input gateway (size limit)
      -> Normalization
      -> Unicode analysis      (on ORIGINAL text: normalization removes the evidence)
      -> Pattern detection     (on NORMALIZED text)
      -> Context analysis      (discussing vs. performing)
      -> Encoding analysis     (decode -> rescan, depth-limited)
      -> Heuristic analysis
      -> Threat scoring
      -> Policy engine         (mode + severity -> decision)

Fail-closed: if any layer raises an exception, the error is recorded as an
invariant violation, and in ENFORCE mode the request is blocked. "Nothing was
detected" must never be confused with "the detector did not run".
"""

from __future__ import annotations

from time import perf_counter
from typing import Callable, TypeVar

from app.config import Settings, get_settings
from app.detection.context import assess_context
from app.detection.encoding import EncodingScanner
from app.detection.heuristics import run_heuristics
from app.detection.normalizer import normalize
from app.detection.patterns import PatternEngine
from app.detection.unicode_security import scan_unicode
from app.firewall.explain import build_explanation
from app.firewall.policy import PolicyEngine
from app.firewall.scoring import ThreatScorer
from app.models.schemas import (
    AnalysisResult,
    ContextAssessment,
    EncodingAnalysis,
    Mode,
    NormalizationResult,
    RuleMatch,
    SourceType,
    StageResult,
    UnicodeAnalysis,
    UNTRUSTED_SOURCES,
)

T = TypeVar("T")


class FirewallEngine:
    """Input firewall: detection + scoring + policy for a single content block."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.patterns = PatternEngine()
        self.encoding_scanner = EncodingScanner(
            self.patterns,
            max_depth=self.settings.max_decode_depth,
            max_candidates=self.settings.max_decode_candidates,
            max_decoded_chars=self.settings.max_decoded_chars,
        )
        self.scorer = ThreatScorer(self.settings)
        self.policy = PolicyEngine(self.settings)

    def analyze(self, text: str, source: SourceType = SourceType.USER_INPUT, mode: Mode | None = None) -> AnalysisResult:
        started = perf_counter()
        mode = mode or Mode(self.settings.mode)
        stages: list[StageResult] = []
        invariants: list[str] = []

        def run(stage: str, fn: Callable[[], T], default: T) -> T:
            """Run one layer; on failure record an invariant and fail closed."""
            try:
                return fn()
            except Exception as exc:  # noqa: BLE001 - deliberately broad: fail closed
                invariants.append(f"layer_error:{stage}")
                stages.append(StageResult(stage=stage, status="ERROR",
                                          summary=f"{type(exc).__name__} in {stage}; failing closed."))
                return default

        # ---- 0. Input gateway: hard size limit -----------------------------
        limit = self.settings.max_document_chars if source in UNTRUSTED_SOURCES else self.settings.max_input_chars
        scan_text = text
        if len(text) > limit:
            invariants.append("input_size_limit")
            scan_text = text[:limit]
            stages.append(StageResult(stage="Input Gateway", status="BLOCK",
                                      summary=f"Input is {len(text)} chars; limit is {limit}. Only the first {limit} were scanned."))
        else:
            stages.append(StageResult(stage="Input Gateway", status="PASS",
                                      summary=f"{len(text)} chars from {source.value} (limit {limit}).",
                                      details={"source": source.value, "length": len(text)}))

        # ---- 1. Normalization ---------------------------------------------
        norm = run("Normalization", lambda: normalize(scan_text),
                   NormalizationResult(original=scan_text, normalized=scan_text))
        if "layer_error:Normalization" not in invariants:
            stages.append(StageResult(
                stage="Normalization", status="INFO" if norm.changed else "PASS",
                summary="; ".join(norm.steps) if norm.steps else "No normalization needed.",
                details={"steps": norm.steps},
            ))

        # ---- 2. Unicode analysis (original text) ---------------------------
        uni = run("Unicode Analysis", lambda: scan_unicode(scan_text), UnicodeAnalysis())
        hidden_matches: list[RuleMatch] = []
        if uni.hidden_text:
            hidden_matches = run("Unicode Analysis",
                                 lambda: self.patterns.scan(normalize(uni.hidden_text or "").normalized, origin="unicode_tags"),
                                 [])
        if "layer_error:Unicode Analysis" not in invariants:
            summary = ", ".join(f"{f.kind} x{f.count}" for f in uni.findings) or "No suspicious Unicode."
            if uni.hidden_text:
                summary += f" | Hidden tag text decoded: \"{uni.hidden_text[:80]}\""
            stages.append(StageResult(
                stage="Unicode Analysis", status="FLAG" if uni.findings else "PASS", summary=summary,
                details={"findings": [f.kind for f in uni.findings], "hidden_text": uni.hidden_text,
                         "hidden_text_rules": [m.rule_id for m in hidden_matches]},
            ))

        # ---- 3. Pattern detection ------------------------------------------
        matches = run("Pattern Detection", lambda: self.patterns.scan(norm.normalized), [])
        if "layer_error:Pattern Detection" not in invariants:
            stages.append(StageResult(
                stage="Pattern Detection", status="FLAG" if matches else "PASS",
                summary=", ".join(f"{m.rule_id} {m.name}" for m in matches) or "No rules matched.",
                details={"rules": [m.rule_id for m in matches]},
            ))

        # ---- 4. Context analysis -------------------------------------------
        ctx = run("Context Analysis",
                  lambda: assess_context(norm.normalized, matches, source, self.settings.discussion_dampening),
                  ContextAssessment())
        if "layer_error:Context Analysis" not in invariants:
            stages.append(StageResult(
                stage="Context Analysis", status="INFO" if ctx.dampened_matches else "PASS", summary=ctx.summary,
                details={"discussion_framing": ctx.discussion_framing, "imperative_signals": ctx.imperative_signals,
                         "dampened_matches": ctx.dampened_matches},
            ))

        # ---- 5. Encoding analysis ------------------------------------------
        enc = run("Encoding Analysis", lambda: self.encoding_scanner.scan(norm.normalized), EncodingAnalysis())
        if "layer_error:Encoding Analysis" not in invariants:
            if enc.findings:
                parts = [f"{' > '.join(f.chain)}: \"{f.decoded[:60]}\"" + (" [ATTACK]" if f.malicious else "")
                         for f in enc.findings[:4]]
                summary = "Decoded and rescanned -> " + " | ".join(parts)
            else:
                summary = "No encoded content."
            stages.append(StageResult(
                stage="Encoding Analysis", status="FLAG" if any(f.malicious for f in enc.findings) else ("INFO" if enc.findings else "PASS"),
                summary=summary,
                details={"candidates_examined": enc.candidates_examined, "depth_limit_reached": enc.depth_limit_reached},
            ))

        # ---- 6. Heuristic analysis -----------------------------------------
        heur = run("Heuristic Analysis",
                   lambda: run_heuristics(scan_text, norm.normalized, encoded_candidates=len(enc.findings)), [])
        fired = [h for h in heur if h.score > 0]
        if "layer_error:Heuristic Analysis" not in invariants:
            stages.append(StageResult(
                stage="Heuristic Analysis", status="FLAG" if fired else "PASS",
                summary=", ".join(f"{h.name} +{h.score}" for h in fired) or "No structural anomalies.",
                details={"evaluated": len(heur), "fired": [h.name for h in fired]},
            ))

        # ---- 7. Threat scoring ---------------------------------------------
        scored = self.scorer.score(matches, enc, uni, hidden_matches, heur, source, ctx)
        stages.append(StageResult(
            stage="Threat Scoring", status="FLAG" if scored.score >= self.settings.threshold_low else "PASS",
            summary=f"Risk {scored.score}/100 -> {scored.severity.value}",
            details={"breakdown": [c.model_dump() for c in scored.breakdown]},
        ))

        # ---- 8. Policy ------------------------------------------------------
        policy = self.policy.decide(scored.severity, source, mode, invariants)
        stages.append(StageResult(stage="Policy Engine", status=policy.decision.value, summary=policy.reason,
                                  details={"mode": mode.value, "enforced_decision": policy.enforced_decision.value}))

        explanation = build_explanation(
            categories=scored.categories, severity=scored.severity, decision=policy.decision,
            enforced=policy.enforced_decision, mode=mode, source=source, context=ctx,
            invariants=invariants, score=scored.score,
        )

        all_rules = matches + hidden_matches + [m for f in enc.findings for m in f.rule_matches]
        return AnalysisResult(
            source=source,
            mode=mode,
            original_input=text,
            normalized_input=norm.normalized,
            risk_score=scored.score,
            severity=scored.severity,
            decision=policy.decision,
            enforced_decision_without_mode=policy.enforced_decision,
            categories=scored.categories,
            triggered_rules=all_rules,
            heuristics=heur,
            encoding=enc,
            unicode=uni,
            normalization=norm,
            context=ctx,
            score_breakdown=scored.breakdown,
            invariant_violations=invariants,
            explanation=explanation,
            stages=stages,
            processing_ms=round((perf_counter() - started) * 1000, 2),
        )
