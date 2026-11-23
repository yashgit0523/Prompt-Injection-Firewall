"""PromptGuard application entry point.

Run with:   uvicorn app.main:app --reload
Dashboard:  http://127.0.0.1:8000/
API docs:   http://127.0.0.1:8000/docs
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.config import Settings, get_settings
from app.routes import api, pages
from app.services import build_services

STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory (tests pass their own Settings with a temporary database)."""
    settings = settings or get_settings()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        logging.getLogger("promptguard").info(
            "PromptGuard %s started in %s mode with LLM provider '%s'",
            __version__, settings.mode, app.state.services.llm.name,
        )
        yield

    app = FastAPI(
        title="PromptGuard API",
        version=__version__,
        description=(
            "AI Prompt Injection Detection & Firewall. Detection (normalization, patterns, heuristics, "
            "encoding and Unicode analysis, risk scoring) is combined with capability control "
            "(provenance, tool authorization, output leakage protection)."
        ),
        lifespan=lifespan,
    )
    app.state.services = build_services(settings)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(api.router)
    app.include_router(pages.router)
    return app


app = create_app()
