"""Security-event table definition and builders.

One row = one request seen by the firewall. Summary columns (score, severity,
decision...) are stored as real columns so they can be filtered and
aggregated; the complete analysis is stored as JSON in ``details`` for the
Request Inspector.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from app.models.schemas import (
    AnalysisResult,
    ChatResult,
    DocumentScanResult,
    SEVERITY_ORDER,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id                 TEXT PRIMARY KEY,
    created_at         TEXT NOT NULL,
    event_type         TEXT NOT NULL,      -- analyze | chat | document | demo
    scenario           TEXT,
    source             TEXT NOT NULL,
    mode               TEXT NOT NULL,
    original_input     TEXT NOT NULL,
    normalized_input   TEXT NOT NULL,
    risk_score         INTEGER NOT NULL,
    severity           TEXT NOT NULL,
    decision           TEXT NOT NULL,
    categories         TEXT NOT NULL,      -- JSON list
    primary_category   TEXT,
    triggered_rules    TEXT NOT NULL,      -- JSON list
    score_breakdown    TEXT NOT NULL,      -- JSON list
    explanation        TEXT NOT NULL,
    tool_decision      TEXT NOT NULL,      -- NONE | ALLOWED | BLOCKED
    tool_blocked_count INTEGER NOT NULL DEFAULT 0,
    output_decision    TEXT NOT NULL,      -- NOT_RUN | SAFE | REDACTED | BLOCKED
    details            TEXT NOT NULL,      -- full JSON for the request inspector
    processing_ms      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_decision ON events(decision);
"""

JSON_COLUMNS = ("categories", "triggered_rules", "score_breakdown", "details")


def new_event_id() -> str:
    return f"EVT-{uuid.uuid4().hex[:10].upper()}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _rules(analysis: AnalysisResult) -> list[dict[str, Any]]:
    return [
        {"rule_id": m.rule_id, "name": m.name, "category": m.category.value, "weight": m.weight,
         "effective_weight": m.effective_weight, "dampened": m.dampened, "origin": m.origin}
        for m in analysis.triggered_rules
    ]


def record_from_analysis(analysis: AnalysisResult, event_type: str = "analyze",
                         scenario: str | None = None) -> dict[str, Any]:
    categories = [c.value for c in analysis.categories]
    return {
        "id": new_event_id(),
        "created_at": _now(),
        "event_type": event_type,
        "scenario": scenario,
        "source": analysis.source.value,
        "mode": analysis.mode.value,
        "original_input": analysis.original_input,
        "normalized_input": analysis.normalized_input,
        "risk_score": analysis.risk_score,
        "severity": analysis.severity.value,
        "decision": analysis.decision.value,
        "categories": categories,
        "primary_category": categories[0] if categories else None,
        "triggered_rules": _rules(analysis),
        "score_breakdown": [c.model_dump() for c in analysis.score_breakdown],
        "explanation": analysis.explanation,
        "tool_decision": "NONE",
        "tool_blocked_count": 0,
        "output_decision": "NOT_RUN",
        "details": {"kind": "analysis", "analysis": analysis.model_dump(mode="json")},
        "processing_ms": analysis.processing_ms,
    }


def record_from_document(scan: DocumentScanResult, scenario: str | None = None) -> dict[str, Any]:
    record = record_from_analysis(scan.analysis, event_type="document", scenario=scenario)
    record["decision"] = scan.decision.value
    record["explanation"] = scan.explanation
    record["details"] = {"kind": "document", "document_scan": scan.model_dump(mode="json")}
    return record


def record_from_chat(chat: ChatResult, event_type: str = "chat", scenario: str | None = None) -> dict[str, Any]:
    inp = chat.input_analysis
    doc = chat.document_scan
    analyses = [inp] + ([doc.analysis] if doc else [])
    worst = max(analyses, key=lambda a: (a.risk_score, SEVERITY_ORDER[a.severity]))

    categories: list[str] = []
    for analysis in analyses:
        categories += [c.value for c in analysis.categories if c.value not in categories]
    rules = _rules(inp) + (_rules(doc.analysis) if doc else [])
    breakdown = [c.model_dump() for c in worst.score_breakdown]

    blocked_tools = [d for d in chat.tool_decisions if d.decision == "BLOCK"]
    if not chat.tool_decisions:
        tool_decision = "NONE"
    else:
        tool_decision = "BLOCKED" if blocked_tools else "ALLOWED"

    original = inp.original_input
    normalized = inp.normalized_input
    source = inp.source.value
    if doc:
        original += f"\n\n[{doc.source.value}]\n{doc.analysis.original_input}"
        normalized += f"\n\n[{doc.source.value}]\n{doc.analysis.normalized_input}"
        source = f"{inp.source.value} + {doc.source.value}"

    explanation = doc.explanation if doc and worst is doc.analysis else inp.explanation
    return {
        "id": chat.event_id or new_event_id(),
        "created_at": _now(),
        "event_type": event_type,
        "scenario": scenario,
        "source": source,
        "mode": inp.mode.value,
        "original_input": original,
        "normalized_input": normalized,
        "risk_score": worst.risk_score,
        "severity": worst.severity.value,
        "decision": chat.final_decision.value,
        "categories": categories,
        "primary_category": categories[0] if categories else None,
        "triggered_rules": rules,
        "score_breakdown": breakdown,
        "explanation": explanation,
        "tool_decision": tool_decision,
        "tool_blocked_count": len(blocked_tools),
        "output_decision": chat.output_check.decision if chat.output_check else "NOT_RUN",
        "details": {"kind": "chat", "chat": chat.model_dump(mode="json")},
        "processing_ms": chat.processing_ms,
    }


def serialize(record: dict[str, Any]) -> dict[str, Any]:
    row = dict(record)
    for column in JSON_COLUMNS:
        row[column] = json.dumps(row[column], ensure_ascii=False)
    return row


def deserialize(row: dict[str, Any]) -> dict[str, Any]:
    record = dict(row)
    for column in JSON_COLUMNS:
        record[column] = json.loads(record[column]) if record.get(column) else None
    return record
