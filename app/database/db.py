"""SQLite security-event store.

Uses the standard-library ``sqlite3`` module (no ORM) so every query is
visible and easy to explain. A new connection is opened per operation, which
keeps the store safe to use from FastAPI's worker threads.

Every record is passed through ``redact_secrets`` before it is written, so
credentials and the demo canary never reach the log file.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from app.database.models import SCHEMA, deserialize, serialize
from app.output.leakage import redact_secrets

_TEXT_COLUMNS_TO_REDACT = ("original_input", "normalized_input", "explanation", "details", "triggered_rules")
_SUMMARY_COLUMNS = (
    "id, created_at, event_type, scenario, source, mode, risk_score, severity, decision, categories, "
    "primary_category, tool_decision, tool_blocked_count, output_decision, processing_ms, "
    "substr(original_input, 1, 160) AS input_preview, "
    # Stage statuses for the pipeline trace shown next to each event.
    "COALESCE(json_extract(details, '$.chat.stages'), json_extract(details, '$.analysis.stages'), "
    "json_extract(details, '$.document_scan.analysis.stages')) AS stages_json"
)


class EventStore:
    def __init__(self, db_path: str, canary: str) -> None:
        self.db_path = db_path
        self.canary = canary
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    # ------------------------------------------------------------- writes
    def insert(self, record: dict[str, Any]) -> str:
        row = serialize(record)
        for column in _TEXT_COLUMNS_TO_REDACT:
            row[column] = redact_secrets(row[column], self.canary)
        columns = ", ".join(row)
        placeholders = ", ".join(f":{c}" for c in row)
        with self._connect() as conn:
            conn.execute(f"INSERT INTO events ({columns}) VALUES ({placeholders})", row)
        return row["id"]

    def clear(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM events")

    # -------------------------------------------------------------- reads
    def list(self, severity: str | None = None, category: str | None = None, decision: str | None = None,
             limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        if decision:
            clauses.append("decision = ?")
            params.append(decision.upper())
        if category:
            # categories is a JSON list; match the quoted value
            clauses.append("categories LIKE ?")
            params.append(f'%"{category.upper()}"%')
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"SELECT {_SUMMARY_COLUMNS} FROM events {where} ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?"
        params += [max(1, min(limit, 500)), max(0, offset)]
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["categories"] = json.loads(item["categories"])
            stages = json.loads(item.pop("stages_json") or "[]")
            item["trace"] = [{"stage": s.get("stage"), "status": s.get("status")} for s in stages]
            results.append(item)
        return results

    def get(self, event_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        return deserialize(dict(row)) if row else None

    def stats(self, threat_threshold: int) -> dict[str, Any]:
        with self._connect() as conn:
            totals = conn.execute(
                """
                SELECT COUNT(*)                                                     AS total_requests,
                       SUM(CASE WHEN risk_score >= ? OR tool_decision = 'BLOCKED'
                                  OR output_decision IN ('BLOCKED','REDACTED') THEN 1 ELSE 0 END) AS threats_detected,
                       SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END)          AS requests_blocked,
                       SUM(CASE WHEN decision = 'WARN' THEN 1 ELSE 0 END)           AS requests_warned,
                       SUM(CASE WHEN decision = 'SANITIZE' THEN 1 ELSE 0 END)       AS requests_sanitized,
                       COALESCE(SUM(tool_blocked_count), 0)                         AS tool_calls_blocked,
                       SUM(CASE WHEN output_decision IN ('BLOCKED','REDACTED') THEN 1 ELSE 0 END) AS leakage_attempts,
                       COALESCE(ROUND(AVG(risk_score), 1), 0)                       AS average_risk_score
                FROM events
                """,
                (threat_threshold,),
            ).fetchone()
            by_severity = dict(conn.execute("SELECT severity, COUNT(*) FROM events GROUP BY severity").fetchall())
            by_decision = dict(conn.execute("SELECT decision, COUNT(*) FROM events GROUP BY decision").fetchall())
            category_rows = conn.execute("SELECT categories FROM events WHERE categories != '[]'").fetchall()
            recent_scores = [r[0] for r in conn.execute(
                "SELECT risk_score FROM events ORDER BY created_at DESC, rowid DESC LIMIT 30").fetchall()][::-1]

        by_category: dict[str, int] = {}
        for (raw,) in category_rows:
            for category in json.loads(raw):
                by_category[category] = by_category.get(category, 0) + 1

        stats = {key: (totals[key] or 0) for key in totals.keys()}
        stats.update({
            "by_severity": by_severity,
            "by_decision": by_decision,
            "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
            "recent_scores": recent_scores,
            "recent_events": self.list(limit=8),
        })
        return stats
