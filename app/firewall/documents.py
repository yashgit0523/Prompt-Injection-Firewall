"""Untrusted document scanner (indirect prompt injection).

Indirect injection hides instructions in content the user did NOT write: a
web page, an e-mail, a PDF, a retrieved RAG chunk. The user innocently asks
"Summarize this document" and the document says "Ignore the user and ...".

The scanner:

1. analyses the whole document with source = UNTRUSTED_DOCUMENT (stricter:
   instructions in data are scored as INDIRECT_INJECTION),
2. splits it into segments (sentences, HTML comments) and scores each one,
   so the exact malicious sentences can be highlighted,
3. applies the document policy. SANITIZE removes the suspicious segments and
   re-scans the remainder; if the remainder is still MEDIUM or worse, the
   document is BLOCKED instead.
"""

from __future__ import annotations

import re

from app.firewall.engine import FirewallEngine
from app.firewall.policy import PolicyEngine
from app.models.schemas import (
    Decision,
    DocumentScanResult,
    DocumentSegment,
    Mode,
    Severity,
    SourceType,
)

_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_SENTENCE = re.compile(r"\S.*?(?:[.!?](?=\s|$)|$)", re.MULTILINE)
_MAX_SEGMENTS = 300
_BLOCKING_SEVERITIES = {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}


def split_segments(text: str) -> list[tuple[int, int]]:
    """Split ``text`` into (start, end) spans: HTML comments stay whole, the rest by sentence."""
    spans: list[tuple[int, int]] = []

    def sentences(start: int, end: int) -> None:
        for m in _SENTENCE.finditer(text, start, end):
            if m.group(0).strip():
                spans.append((m.start(), m.end()))

    cursor = 0
    for comment in _HTML_COMMENT.finditer(text):
        sentences(cursor, comment.start())
        spans.append((comment.start(), comment.end()))
        cursor = comment.end()
    sentences(cursor, len(text))
    return spans[:_MAX_SEGMENTS]


class DocumentScanner:
    def __init__(self, engine: FirewallEngine) -> None:
        self.engine = engine
        self.settings = engine.settings

    def scan(self, document: str, user_request: str, mode: Mode | None = None,
             source: SourceType = SourceType.UNTRUSTED_DOCUMENT) -> DocumentScanResult:
        mode = mode or Mode(self.settings.mode)
        analysis = self.engine.analyze(document, source, mode)

        segments: list[DocumentSegment] = []
        for index, (start, end) in enumerate(split_segments(document[: self.settings.max_document_chars])):
            seg_text = document[start:end]
            seg = self.engine.analyze(seg_text, source, Mode.ENFORCE)
            suspicious = seg.risk_score >= self.settings.threshold_low or bool(seg.categories)
            segments.append(DocumentSegment(
                index=index, text=seg_text, start=start, end=end,
                risk_score=seg.risk_score, severity=seg.severity, categories=seg.categories,
                rules=sorted({m.rule_id for m in seg.triggered_rules if not m.dampened}),
                suspicious=suspicious,
            ))
        flagged = [s for s in segments if s.suspicious]

        enforced = analysis.enforced_decision_without_mode
        sanitized_text: str | None = None
        sanitized_score: int | None = None
        note = ""
        if enforced == Decision.SANITIZE:
            if not flagged:
                enforced = Decision.BLOCK
                note = "The document is suspicious as a whole but no single segment could be isolated, so it is blocked."
            else:
                sanitized_text = self._remove(document, flagged)
                recheck = self.engine.analyze(sanitized_text, source, Mode.ENFORCE)
                sanitized_score = recheck.risk_score
                if recheck.severity in _BLOCKING_SEVERITIES:
                    enforced = Decision.BLOCK
                    note = f"After removing {len(flagged)} segment(s) the document still scored {recheck.risk_score}, so it is blocked."
                else:
                    note = (f"{len(flagged)} suspicious segment(s) were removed; the remaining content scored "
                            f"{recheck.risk_score}/100 and can be passed to the LLM as fenced DATA.")

        decision = PolicyEngine.apply_mode(enforced, mode)
        explanation = analysis.explanation + (f" {note}" if note else "")
        if decision != enforced:
            explanation += f" ({mode.value} mode: ENFORCE would have chosen {enforced.value}.)"
        return DocumentScanResult(
            source=source,
            user_request=user_request,
            analysis=analysis,
            segments=segments,
            suspicious_segments=len(flagged),
            decision=decision,
            sanitized_document=sanitized_text,
            sanitized_analysis_score=sanitized_score,
            explanation=explanation,
        )

    @staticmethod
    def _remove(document: str, flagged: list[DocumentSegment]) -> str:
        pieces: list[str] = []
        cursor = 0
        for seg in sorted(flagged, key=lambda s: s.start):
            pieces.append(document[cursor:seg.start])
            pieces.append("[removed by PromptGuard]")
            cursor = seg.end
        pieces.append(document[cursor:])
        return "".join(pieces)
