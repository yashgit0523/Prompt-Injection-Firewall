"""Wires every PromptGuard component together (simple dependency container)."""

from __future__ import annotations

from dataclasses import dataclass

from app.config import Settings
from app.database.db import EventStore
from app.firewall.documents import DocumentScanner
from app.firewall.engine import FirewallEngine
from app.firewall.pipeline import SecurePipeline
from app.llm.base import BaseLLM
from app.llm.providers import build_llm
from app.output.leakage import OutputFirewall
from app.tools.authorization import ToolFirewall
from app.tools.registry import ToolRegistry


@dataclass
class Services:
    settings: Settings
    engine: FirewallEngine
    document_scanner: DocumentScanner
    registry: ToolRegistry
    tool_firewall: ToolFirewall
    output_firewall: OutputFirewall
    llm: BaseLLM
    pipeline: SecurePipeline
    store: EventStore


def build_services(settings: Settings) -> Services:
    engine = FirewallEngine(settings)
    document_scanner = DocumentScanner(engine)
    registry = ToolRegistry()
    tool_firewall = ToolFirewall(registry, settings)
    output_firewall = OutputFirewall(settings.canary, settings.output_leak_action)
    llm = build_llm(settings)
    pipeline = SecurePipeline(settings, engine, document_scanner, llm, tool_firewall, output_firewall)
    store = EventStore(settings.db_path, settings.canary)
    return Services(settings, engine, document_scanner, registry, tool_firewall, output_firewall, llm, pipeline, store)
