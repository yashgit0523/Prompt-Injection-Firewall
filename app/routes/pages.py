"""Server-rendered HTML pages (Jinja2). Pages load their data from the JSON API."""

from __future__ import annotations

import hashlib
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.detection.patterns import rules_as_dicts

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))
router = APIRouter(include_in_schema=False)
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


def _static_version() -> str:
    """Short hash of every static file. It changes whenever CSS or JS changes."""
    digest = hashlib.sha256()
    for path in sorted(STATIC_DIR.rglob("*")):
        if path.is_file():
            digest.update(path.relative_to(STATIC_DIR).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()[:10]


_ASSET_VERSION = _static_version()


def asset(path: str) -> str:
    """Versioned static URL, so browsers never reuse an outdated cached file after a deploy."""
    return f"/static/{path}?v={_ASSET_VERSION}"


TEMPLATES.env.globals["asset"] = asset


def _render(request: Request, template: str, active: str, **context: object) -> HTMLResponse:
    settings = request.app.state.services.settings
    return TEMPLATES.TemplateResponse(
        request, template, {"active": active, "mode": settings.mode, **context}
    )


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    return _render(request, "index.html", "dashboard")


@router.get("/scanner", response_class=HTMLResponse)
def scanner(request: Request) -> HTMLResponse:
    return _render(request, "scanner.html", "scanner")


@router.get("/documents", response_class=HTMLResponse)
def documents(request: Request) -> HTMLResponse:
    return _render(request, "documents.html", "documents")


@router.get("/demo", response_class=HTMLResponse)
def demo(request: Request) -> HTMLResponse:
    return _render(request, "demo.html", "demo")


@router.get("/events", response_class=HTMLResponse)
def events(request: Request) -> HTMLResponse:
    return _render(request, "logs.html", "events")


@router.get("/events/{event_id}", response_class=HTMLResponse)
def event_detail(request: Request, event_id: str) -> HTMLResponse:
    return _render(request, "event.html", "events", event_id=event_id)


@router.get("/about", response_class=HTMLResponse)
def about(request: Request) -> HTMLResponse:
    return _render(request, "about.html", "about", rules=rules_as_dicts())
