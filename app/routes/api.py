"""REST API (documented automatically at /docs)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from app import __version__
from app.database.models import record_from_analysis, record_from_chat, record_from_document
from app.demos import SCENARIOS, SCENARIOS_BY_ID
from app.detection.patterns import rules_as_dicts
from app.models.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    ChatRequest,
    ChatResult,
    DocumentScanRequest,
    Mode,
    SourceType,
    UNTRUSTED_SOURCES,
)
from app.services import Services

router = APIRouter(prefix="/api", tags=["PromptGuard API"])

# Requests far beyond the configured limit are rejected outright (the engine
# would only scan the first N characters anyway). This protects the server.
_HARD_LIMIT_FACTOR = 5


def _services(request: Request) -> Services:
    return request.app.state.services


def _guard_size(text: str, limit: int) -> None:
    if len(text) > limit * _HARD_LIMIT_FACTOR:
        raise HTTPException(status_code=413, detail=f"Input too large ({len(text)} chars).")


@router.get("/health", summary="Health check")
def health(request: Request) -> dict[str, Any]:
    s = _services(request)
    return {
        "status": "ok",
        "app": s.settings.app_name,
        "version": __version__,
        "mode": s.settings.mode,
        "llm_provider": s.llm.name,
        "rules_enabled": len(s.engine.patterns.enabled_rules),
    }


@router.get("/config", summary="Public firewall configuration (no secrets)")
def config(request: Request) -> dict[str, Any]:
    s = _services(request)
    return {**s.settings.public_view(), "tools": s.registry.describe(), "rule_count": len(rules_as_dicts())}


@router.get("/rules", summary="Detection rule table")
def rules() -> list[dict[str, Any]]:
    return rules_as_dicts()


@router.post("/analyze", response_model=AnalyzeResponse, summary="Analyze a prompt without sending it to the LLM")
def analyze(body: AnalyzeRequest, request: Request) -> AnalyzeResponse:
    s = _services(request)
    limit = s.settings.max_document_chars if body.source in UNTRUSTED_SOURCES else s.settings.max_input_chars
    _guard_size(body.prompt, limit)
    analysis = s.engine.analyze(body.prompt, body.source)
    event_id = s.store.insert(record_from_analysis(analysis))
    return AnalyzeResponse(
        event_id=event_id,
        risk_score=analysis.risk_score,
        severity=analysis.severity,
        decision=analysis.decision,
        categories=analysis.categories,
        triggered_rules=analysis.triggered_rules,
        score_breakdown=analysis.score_breakdown,
        explanation=analysis.explanation,
        analysis=analysis,
    )


@router.post("/chat", response_model=ChatResult, summary="Run a prompt through the full firewall + LLM pipeline")
def chat(body: ChatRequest, request: Request) -> ChatResult:
    s = _services(request)
    _guard_size(body.prompt, s.settings.max_input_chars)
    if body.document:
        _guard_size(body.document, s.settings.max_document_chars)
    result = s.pipeline.run(body.prompt, body.document)
    record = record_from_chat(result)
    result.event_id = s.store.insert(record)
    return result


@router.post("/document/scan", summary="Scan untrusted document content (indirect injection)")
def document_scan(body: DocumentScanRequest, request: Request) -> dict[str, Any]:
    s = _services(request)
    _guard_size(body.document, s.settings.max_document_chars)
    if body.run_llm:
        result = s.pipeline.run(body.user_request, body.document)
        result.event_id = s.store.insert(record_from_chat(result, event_type="document"))
        return {"event_id": result.event_id, "scan": result.document_scan, "chat": result}
    scan = s.document_scanner.scan(body.document, body.user_request)
    event_id = s.store.insert(record_from_document(scan))
    return {"event_id": event_id, "scan": scan, "chat": None}


@router.get("/demo", summary="List Attack Demo Lab scenarios")
def list_demos() -> list[dict[str, Any]]:
    return [scenario.public() for scenario in SCENARIOS]


@router.post("/demo/{scenario_id}", summary="Run a predefined demonstration scenario")
def run_demo(scenario_id: str, request: Request) -> dict[str, Any]:
    scenario = SCENARIOS_BY_ID.get(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail=f"Unknown scenario '{scenario_id}'.")
    s = _services(request)
    # A scenario may run the INPUT firewall in a softer mode to let an attack reach
    # the model; capability controls (tool/output firewall) are always enforced.
    mode = Mode(scenario.mode) if scenario.mode else None
    result = s.pipeline.run(scenario.prompt, scenario.document, mode=mode,
                            document_source=SourceType.UNTRUSTED_DOCUMENT)
    result.event_id = s.store.insert(record_from_chat(result, event_type="demo", scenario=scenario.id))
    return {"scenario": scenario.public(), "event_id": result.event_id, "result": result}


@router.get("/events", summary="List security events")
def list_events(
    request: Request,
    severity: str | None = Query(None, description="SAFE, LOW, MEDIUM, HIGH, CRITICAL"),
    category: str | None = Query(None, description="e.g. INSTRUCTION_OVERRIDE"),
    decision: str | None = Query(None, description="ALLOW, WARN, SANITIZE, BLOCK"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[dict[str, Any]]:
    return _services(request).store.list(severity, category, decision, limit, offset)


@router.delete("/events", summary="Delete all security events (demo reset)")
def clear_events(request: Request) -> dict[str, str]:
    _services(request).store.clear()
    return {"status": "cleared"}


@router.get("/events/{event_id}", summary="Full details of one security event")
def get_event(event_id: str, request: Request) -> dict[str, Any]:
    event = _services(request).store.get(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found.")
    return event


@router.get("/stats", summary="Dashboard statistics")
def stats(request: Request) -> dict[str, Any]:
    s = _services(request)
    return s.store.stats(s.settings.threshold_low)
