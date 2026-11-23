"""Pydantic models shared by every layer of PromptGuard.

These models are the "contract" between modules: the detection layer produces
them, the firewall combines them, the API returns them and the database stores
them. Keeping them in one file makes the data flow easy to follow.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------
class Severity(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_ORDER = {Severity.SAFE: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


class Decision(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"


# Used to pick the "most severe" decision when several layers vote.
DECISION_RANK = {Decision.ALLOW: 0, Decision.WARN: 1, Decision.SANITIZE: 2, Decision.BLOCK: 3}


class Mode(str, Enum):
    LEARNING = "LEARNING"
    MONITOR = "MONITOR"
    ENFORCE = "ENFORCE"


class Category(str, Enum):
    DIRECT_INJECTION = "DIRECT_INJECTION"
    INSTRUCTION_OVERRIDE = "INSTRUCTION_OVERRIDE"
    SYSTEM_PROMPT_EXTRACTION = "SYSTEM_PROMPT_EXTRACTION"
    ROLE_HIJACKING = "ROLE_HIJACKING"
    JAILBREAK = "JAILBREAK"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    DELIMITER_INJECTION = "DELIMITER_INJECTION"
    TOOL_MANIPULATION = "TOOL_MANIPULATION"
    ENCODED_INJECTION = "ENCODED_INJECTION"
    INDIRECT_INJECTION = "INDIRECT_INJECTION"
    UNICODE_SMUGGLING = "UNICODE_SMUGGLING"


CATEGORY_LABELS: dict[str, str] = {
    "DIRECT_INJECTION": "Direct Prompt Injection",
    "INSTRUCTION_OVERRIDE": "Instruction Override",
    "SYSTEM_PROMPT_EXTRACTION": "System Prompt Extraction",
    "ROLE_HIJACKING": "Role Hijacking",
    "JAILBREAK": "Jailbreak Attempt",
    "DATA_EXFILTRATION": "Data Exfiltration",
    "DELIMITER_INJECTION": "Delimiter Injection",
    "TOOL_MANIPULATION": "Tool Manipulation",
    "ENCODED_INJECTION": "Encoded Injection",
    "INDIRECT_INJECTION": "Indirect Prompt Injection",
    "UNICODE_SMUGGLING": "Unicode Smuggling",
}


class SourceType(str, Enum):
    """Where a piece of content came from (its provenance)."""

    TRUSTED_SYSTEM = "TRUSTED_SYSTEM"
    USER_INPUT = "USER_INPUT"
    UNTRUSTED_DOCUMENT = "UNTRUSTED_DOCUMENT"
    EXTERNAL_CONTENT = "EXTERNAL_CONTENT"
    TOOL_OUTPUT = "TOOL_OUTPUT"


UNTRUSTED_SOURCES = {SourceType.UNTRUSTED_DOCUMENT, SourceType.EXTERNAL_CONTENT, SourceType.TOOL_OUTPUT}


# --------------------------------------------------------------------------
# Detection results
# --------------------------------------------------------------------------
class RuleMatch(BaseModel):
    """One detection rule that matched the input."""

    rule_id: str
    name: str
    category: Category
    severity: Severity
    weight: int
    effective_weight: float          # weight after contextual dampening
    matched_text: str
    start: int
    end: int
    dampened: bool = False
    dampening_reason: str | None = None
    origin: str = "direct"           # direct | decoded:<encoding> | unicode_tags


class HeuristicResult(BaseModel):
    name: str
    score: int
    reason: str


class NormalizationResult(BaseModel):
    original: str
    normalized: str
    steps: list[str] = Field(default_factory=list)
    removed_characters: int = 0
    changed: bool = False


class UnicodeFinding(BaseModel):
    kind: str                        # ZERO_WIDTH, BIDI_CONTROL, TAG_CHARACTER, ...
    count: int
    codepoints: list[str]
    positions: list[int]
    score: int
    reason: str


class UnicodeAnalysis(BaseModel):
    findings: list[UnicodeFinding] = Field(default_factory=list)
    hidden_text: str | None = None   # ASCII text smuggled via Unicode tag characters
    total_score: int = 0


class EncodingFinding(BaseModel):
    encoding: str                    # base64, hex, url, unicode_escape, html_entity, rot13
    snippet: str                     # (truncated) encoded text that was found
    decoded: str                     # (truncated) safely decoded text
    depth: int                       # 1 = decoded once, 2 = decoded twice ...
    chain: list[str]                 # e.g. ["base64", "url"]
    rule_matches: list[RuleMatch] = Field(default_factory=list)
    malicious: bool = False


class EncodingAnalysis(BaseModel):
    findings: list[EncodingFinding] = Field(default_factory=list)
    candidates_examined: int = 0
    depth_limit_reached: bool = False


class ContextAssessment(BaseModel):
    """Result of 'discussing an attack' vs 'performing an attack' analysis."""

    discussion_framing: bool = False
    analysis_wrapper: bool = False
    framing_cues: list[str] = Field(default_factory=list)
    imperative_signals: list[str] = Field(default_factory=list)
    quoted_matches: int = 0
    dampened_matches: int = 0
    summary: str = ""


class ScoreComponent(BaseModel):
    component: str
    points: int
    reason: str


class StageResult(BaseModel):
    """One step of the request pipeline, shown in the demo lab and inspector."""

    stage: str
    status: str                      # PASS | FLAG | BLOCK | WARN | SANITIZE | SKIP | ERROR | INFO
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)


class AnalysisResult(BaseModel):
    """Full, explainable output of the input firewall for one piece of content."""

    source: SourceType
    mode: Mode
    original_input: str
    normalized_input: str
    risk_score: int
    severity: Severity
    decision: Decision
    enforced_decision_without_mode: Decision   # what ENFORCE mode would have done
    categories: list[Category]
    triggered_rules: list[RuleMatch]
    heuristics: list[HeuristicResult]
    encoding: EncodingAnalysis
    unicode: UnicodeAnalysis
    normalization: NormalizationResult
    context: ContextAssessment
    score_breakdown: list[ScoreComponent]
    invariant_violations: list[str] = Field(default_factory=list)
    explanation: str
    stages: list[StageResult] = Field(default_factory=list)
    processing_ms: float = 0.0


# --------------------------------------------------------------------------
# Provenance, tools, output
# --------------------------------------------------------------------------
class ContentBlockView(BaseModel):
    block_id: str
    source: SourceType
    trusted: bool
    label: str
    parent_ids: list[str] = Field(default_factory=list)
    preview: str


class ToolCall(BaseModel):
    """A tool call *proposed* by the LLM. It is never executed directly."""

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    origin_block_id: str | None = None    # which content block caused the proposal


class ToolCheck(BaseModel):
    check: str
    passed: bool
    detail: str


class ToolDecision(BaseModel):
    tool: str
    arguments: dict[str, Any]
    decision: str                    # ALLOW | BLOCK
    reason: str
    checks: list[ToolCheck] = Field(default_factory=list)
    executed: bool = False
    result: str | None = None
    origin_block_id: str | None = None
    origin_source: SourceType | None = None


class LeakFinding(BaseModel):
    kind: str                        # canary | canary_encoded | system_prompt | secret_pattern | exfil_url
    detail: str
    evidence: str


class OutputCheck(BaseModel):
    decision: str                    # SAFE | REDACTED | BLOCKED
    findings: list[LeakFinding] = Field(default_factory=list)
    final_output: str
    reason: str


# --------------------------------------------------------------------------
# Document scanning
# --------------------------------------------------------------------------
class DocumentSegment(BaseModel):
    index: int
    text: str
    start: int
    end: int
    risk_score: int
    severity: Severity
    categories: list[Category] = Field(default_factory=list)
    rules: list[str] = Field(default_factory=list)
    suspicious: bool = False


class DocumentScanResult(BaseModel):
    source: SourceType = SourceType.UNTRUSTED_DOCUMENT
    user_request: str
    analysis: AnalysisResult
    segments: list[DocumentSegment]
    suspicious_segments: int
    decision: Decision
    sanitized_document: str | None = None
    sanitized_analysis_score: int | None = None
    explanation: str


# --------------------------------------------------------------------------
# Pipeline (chat) results
# --------------------------------------------------------------------------
class ChatResult(BaseModel):
    event_id: str | None = None
    final_decision: Decision
    response: str
    input_analysis: AnalysisResult
    document_scan: DocumentScanResult | None = None
    provenance: list[ContentBlockView] = Field(default_factory=list)
    fence_nonce: str | None = None
    rendered_prompt_preview: str | None = None
    llm_called: bool = False
    llm_provider: str | None = None
    llm_raw_output: str | None = None
    tool_decisions: list[ToolDecision] = Field(default_factory=list)
    output_check: OutputCheck | None = None
    invariant_violations: list[str] = Field(default_factory=list)
    stages: list[StageResult] = Field(default_factory=list)
    processing_ms: float = 0.0


# --------------------------------------------------------------------------
# API request bodies
# --------------------------------------------------------------------------
class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="Text to analyze (not sent to the LLM).")
    source: SourceType = Field(SourceType.USER_INPUT, description="Provenance of the text.")


class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="User prompt.")
    document: str | None = Field(None, description="Optional untrusted document to give the LLM.")


class DocumentScanRequest(BaseModel):
    document: str = Field(..., min_length=1, description="Untrusted document content.")
    user_request: str = Field("Summarize this document.", description="What the user asked about the document.")
    run_llm: bool = Field(True, description="Also run the full pipeline (MockLLM, tools, output firewall).")


class AnalyzeResponse(BaseModel):
    event_id: str | None
    risk_score: int
    severity: Severity
    decision: Decision
    categories: list[Category]
    triggered_rules: list[RuleMatch]
    score_breakdown: list[ScoreComponent]
    explanation: str
    analysis: AnalysisResult
