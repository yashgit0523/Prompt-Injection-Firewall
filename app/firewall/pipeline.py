"""The complete PromptGuard request pipeline (defense in depth).

    User input ----------> Input firewall (detection + scoring + policy)
    Untrusted document --> Document scanner (indirect injection, SANITIZE)
                             |
                     BLOCK <-+-> ALLOW / WARN / SANITIZE
                             |
                       Provenance layer (blocks, taint, nonce fences)
                             |
                            LLM  (returns text + PROPOSED tool calls)
                             |
                       Tool firewall (capability control)
                             |
                       Output firewall (canary / secret leakage)
                             |
                            User

Layers fail independently: an attack that slips past detection can still be
stopped by the tool firewall or the output firewall.
"""

from __future__ import annotations

from time import perf_counter

from app.config import Settings
from app.firewall.documents import DocumentScanner
from app.firewall.engine import FirewallEngine
from app.firewall.policy import PolicyEngine
from app.llm.base import SYSTEM_PROMPT, BaseLLM, LLMRequest
from app.models.schemas import (
    DECISION_RANK,
    ChatResult,
    Decision,
    DocumentScanResult,
    Mode,
    SourceType,
    StageResult,
    ToolDecision,
)
from app.output.leakage import OutputFirewall, redact_secrets
from app.provenance.tracker import ProvenanceTracker
from app.tools.authorization import ToolFirewall


def _strictest(*decisions: Decision) -> Decision:
    return max(decisions, key=lambda d: DECISION_RANK[d])


class SecurePipeline:
    def __init__(self, settings: Settings, engine: FirewallEngine, document_scanner: DocumentScanner,
                 llm: BaseLLM, tool_firewall: ToolFirewall, output_firewall: OutputFirewall) -> None:
        self.settings = settings
        self.engine = engine
        self.document_scanner = document_scanner
        self.llm = llm
        self.tool_firewall = tool_firewall
        self.output_firewall = output_firewall

    def run(self, prompt: str, document: str | None = None, mode: Mode | None = None,
            document_source: SourceType = SourceType.UNTRUSTED_DOCUMENT) -> ChatResult:
        started = perf_counter()
        mode = mode or Mode(self.settings.mode)
        tracker = ProvenanceTracker()
        tracker.add(SYSTEM_PROMPT, SourceType.TRUSTED_SYSTEM, "Application system prompt")
        user_block = tracker.add(prompt, SourceType.USER_INPUT, "User prompt")

        # ---- 1. Input firewall --------------------------------------------
        input_analysis = self.engine.analyze(prompt, SourceType.USER_INPUT, mode)
        stages = list(input_analysis.stages)

        # ---- 2. Document scanner (indirect injection) ----------------------
        doc_scan: DocumentScanResult | None = None
        doc_block = None
        if document:
            doc_block = tracker.add(document, document_source, "Untrusted document")
            doc_scan = self.document_scanner.scan(document, prompt, mode, document_source)
            stages.append(StageResult(
                stage="Document Scanner", status=doc_scan.decision.value,
                summary=(f"{document_source.value}: risk {doc_scan.analysis.risk_score}/100, "
                         f"{doc_scan.suspicious_segments} suspicious segment(s) -> {doc_scan.decision.value}"),
                details={"categories": [c.value for c in doc_scan.analysis.categories]},
            ))

        # ---- 3. Provenance layer ------------------------------------------
        fence_violations = tracker.fence_violations()
        decisions = [input_analysis.decision] + ([doc_scan.decision] if doc_scan else [])
        if fence_violations:
            decisions.append(PolicyEngine.apply_mode(Decision.BLOCK, mode))
        final_decision = _strictest(*decisions)

        if doc_scan and doc_block and doc_scan.decision == Decision.SANITIZE and doc_scan.sanitized_document is not None:
            tracker.replace(doc_block, doc_scan.sanitized_document, "Sanitized document (suspicious segments removed)")

        stages.append(StageResult(
            stage="Provenance Layer",
            status="BLOCK" if fence_violations and mode == Mode.ENFORCE else ("FLAG" if tracker.is_tainted else "PASS"),
            summary=(f"{len(tracker.blocks)} content block(s); tainted: "
                     f"{', '.join(b.block_id + '=' + b.source.value for b in tracker.tainted_blocks()) or 'none'}; "
                     f"fence nonce {tracker.nonce}"
                     + (f"; FENCE VIOLATION: {', '.join(fence_violations)}" if fence_violations else "")),
            details={"tainted": tracker.is_tainted, "violations": fence_violations},
        ))

        result = ChatResult(
            final_decision=final_decision,
            response="",
            input_analysis=input_analysis,
            document_scan=doc_scan,
            fence_nonce=tracker.nonce,
            invariant_violations=input_analysis.invariant_violations + fence_violations,
            llm_provider=self.llm.name,
        )

        # ---- BLOCK: the LLM is never called --------------------------------
        if final_decision == Decision.BLOCK:
            reason = doc_scan.explanation if doc_scan and doc_scan.decision == Decision.BLOCK else input_analysis.explanation
            if fence_violations and not reason:
                reason = "Untrusted content tried to forge a provenance fence."
            result.response = f"Request blocked by PromptGuard. {reason}"
            for stage in ("LLM", "Tool Firewall", "Output Firewall"):
                stages.append(StageResult(stage=stage, status="SKIP", summary="Not reached - request was blocked."))
            return self._finish(result, tracker, stages, started)

        # ---- 4. LLM ---------------------------------------------------------
        rendered = tracker.render()
        request = LLMRequest(system_prompt=SYSTEM_PROMPT, rendered_prompt=rendered, user_prompt=prompt,
                             user_block_id=user_block.block_id, blocks=tracker.rendered_blocks())
        response = self.llm.generate(request)
        result.llm_called = True
        result.rendered_prompt_preview = rendered[:3000]
        stages.append(StageResult(
            stage="LLM", status="INFO",
            summary=(f"{self.llm.name} responded; {len(response.tool_calls)} tool call(s) proposed."
                     + (" " + " ".join(response.notes) if response.notes else "")),
            details={"proposed_tools": [c.tool for c in response.tool_calls]},
        ))

        # ---- 5. Tool firewall ------------------------------------------------
        tool_decisions: list[ToolDecision] = []
        for call in response.tool_calls:
            decision = self.tool_firewall.execute(self.tool_firewall.authorize(call, tracker, prompt))
            if decision.executed and decision.result is not None:
                origin = tracker.get(call.origin_block_id) or user_block
                tracker.derive(decision.result, [origin], label=f"Output of {decision.tool}", source=SourceType.TOOL_OUTPUT)
            tool_decisions.append(decision)
        text = response.text
        if tool_decisions:
            previous = "" if text == "Let me use a tool for that." else text
            text = self.llm.generate(LLMRequest(
                system_prompt=SYSTEM_PROMPT, rendered_prompt=rendered, user_prompt=prompt,
                user_block_id=user_block.block_id, blocks=tracker.rendered_blocks(),
                tool_results=tool_decisions, previous_text=previous,
            )).text
            blocked = [d for d in tool_decisions if d.decision == "BLOCK"]
            stages.append(StageResult(
                stage="Tool Firewall", status="BLOCK" if blocked else "PASS",
                summary="; ".join(f"{d.tool}: {'TOOL CALL BLOCKED - ' + d.reason if d.decision == 'BLOCK' else 'ALLOWED'}"
                                  for d in tool_decisions),
                details={"decisions": [d.decision for d in tool_decisions]},
            ))
        else:
            stages.append(StageResult(stage="Tool Firewall", status="PASS", summary="No tool calls proposed."))
        result.tool_decisions = tool_decisions

        # ---- 6. Output firewall -----------------------------------------------
        output_check = self.output_firewall.scan(text, [SYSTEM_PROMPT])
        result.output_check = output_check
        result.response = output_check.final_output
        # Never hand protected content back to the client through the "raw output" field.
        result.llm_raw_output = text if output_check.decision == "SAFE" else "[withheld: raw output contained protected data]"
        stages.append(StageResult(
            stage="Output Firewall",
            status={"SAFE": "PASS", "REDACTED": "SANITIZE", "BLOCKED": "BLOCK"}[output_check.decision],
            summary=("OUTPUT BLOCKED - " if output_check.decision == "BLOCKED" else "") + output_check.reason
                    + (" Findings: " + ", ".join(f.kind for f in output_check.findings) if output_check.findings else ""),
        ))
        return self._finish(result, tracker, stages, started)

    def _finish(self, result: ChatResult, tracker: ProvenanceTracker, stages: list[StageResult], started: float) -> ChatResult:
        result.provenance = tracker.views()
        result.stages = stages
        result.processing_ms = round((perf_counter() - started) * 1000, 2)
        # Defense in depth for our own reporting: the canary / credentials must
        # never appear anywhere in what the API returns (tool args, prompt preview...).
        clean = redact_secrets(result.model_dump_json(), self.settings.canary)
        return ChatResult.model_validate_json(clean)
