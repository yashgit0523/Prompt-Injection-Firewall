"""Shared pytest fixtures. Every test gets its own temporary SQLite database."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Importing app.main builds a module-level app; point it at a temp DB so the
# test run never writes into the project's real data/ directory.
os.environ.setdefault("PROMPTGUARD_DB_PATH", str(Path(tempfile.mkdtemp()) / "import.db"))

from fastapi.testclient import TestClient  # noqa: E402

from app.config import Settings  # noqa: E402
from app.firewall.engine import FirewallEngine  # noqa: E402
from app.services import Services, build_services  # noqa: E402


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(db_path=str(tmp_path / "promptguard-test.db"))


@pytest.fixture
def engine(settings: Settings) -> FirewallEngine:
    return FirewallEngine(settings)


@pytest.fixture
def services(settings: Settings) -> Services:
    return build_services(settings)


@pytest.fixture
def client(settings: Settings):
    from app.main import create_app

    with TestClient(create_app(settings)) as test_client:
        yield test_client
