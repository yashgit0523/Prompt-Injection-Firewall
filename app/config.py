"""Centralised configuration for PromptGuard.

Every tunable value (thresholds, limits, modes, provider settings) lives here so
that the security behaviour of the firewall can be reviewed in one place.

Values are read from environment variables (see ``.env.example``). Nothing in
this file is secret: API keys are only ever *read* from the environment and are
never given defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# A fake, clearly-labelled demo secret ("canary"). It is planted in the
# protected system prompt so that we can prove the output firewall stops it
# from leaking. It is NOT a real credential.
DEMO_CANARY = "PROMPTGUARD_DEMO_SECRET_7F91A3"


def load_dotenv(path: Path = BASE_DIR / ".env") -> None:
    """Minimal .env loader (KEY=VALUE lines). Real environment variables win."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _env_str(name: str, default: str) -> str:
    return os.environ.get(name, default).strip()


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError as exc:  # fail loudly on bad configuration
        raise ValueError(f"Environment variable {name} must be an integer, got {raw!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str, default: list[str]) -> list[str]:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass
class Settings:
    """All runtime settings. Create via :func:`get_settings` or directly in tests."""

    app_name: str = "PromptGuard"
    version: str = "1.0.0"

    # ---- Operating mode -------------------------------------------------
    # LEARNING: detect + log only, MONITOR: detect + warn, ENFORCE: full policy
    mode: str = "ENFORCE"

    # ---- Input limits (abuse protection) --------------------------------
    max_input_chars: int = 20_000
    max_document_chars: int = 50_000
    max_decode_depth: int = 3          # recursion limit for nested encodings
    max_decode_candidates: int = 25    # total decode attempts per request
    max_decoded_chars: int = 10_000    # decoded payloads larger than this are truncated

    # ---- Severity thresholds (score >= value => severity) ---------------
    threshold_low: int = 20
    threshold_medium: int = 40
    threshold_high: int = 60
    threshold_critical: int = 80

    # ---- Policy: severity -> action, per input source --------------------
    user_policy: dict[str, str] = field(default_factory=lambda: {
        "SAFE": "ALLOW",
        "LOW": "ALLOW",
        "MEDIUM": "WARN",
        "HIGH": "BLOCK",
        "CRITICAL": "BLOCK",
    })
    # Untrusted documents: suspicious segments are removed (SANITIZE) so the
    # legitimate part of the document can still be used. If the sanitized
    # remainder is still MEDIUM or worse, the document scanner escalates to BLOCK.
    document_policy: dict[str, str] = field(default_factory=lambda: {
        "SAFE": "ALLOW",
        "LOW": "ALLOW",
        "MEDIUM": "SANITIZE",
        "HIGH": "SANITIZE",
        "CRITICAL": "SANITIZE",
    })

    # ---- Scoring knobs ---------------------------------------------------
    discussion_dampening: float = 0.2   # multiplier for attack phrases that are discussed, not issued
    heuristic_cap: int = 25             # max total points heuristics may add
    unicode_cap: int = 30               # max total points unicode anomalies may add
    multi_category_bonus: int = 10      # bonus when several attack techniques are combined
    encoding_bonus: int = 15            # bonus when an attack was hidden inside an encoding
    indirect_bonus: int = 10            # bonus for instructions found in untrusted content
    directed_bonus: int = 10            # bonus when attack phrases are addressed to the assistant

    # ---- Capability control ---------------------------------------------
    message_recipient_allowlist: list[str] = field(default_factory=lambda: ["team@promptguard.local"])
    output_leak_action: str = "BLOCK"   # BLOCK or REDACT
    canary: str = DEMO_CANARY

    # ---- Storage ---------------------------------------------------------
    db_path: str = str(BASE_DIR / "data" / "promptguard.db")

    # ---- LLM provider ----------------------------------------------------
    llm_provider: str = "mock"          # mock | openai | anthropic
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-opus-5-5"

    def __post_init__(self) -> None:
        self.mode = self.mode.upper()
        if self.mode not in {"LEARNING", "MONITOR", "ENFORCE"}:
            raise ValueError(f"Invalid mode {self.mode!r}; expected LEARNING, MONITOR or ENFORCE")
        self.output_leak_action = self.output_leak_action.upper()
        if self.output_leak_action not in {"BLOCK", "REDACT"}:
            raise ValueError("output_leak_action must be BLOCK or REDACT")
        thresholds = [self.threshold_low, self.threshold_medium, self.threshold_high, self.threshold_critical]
        if thresholds != sorted(thresholds) or not all(0 < t <= 100 for t in thresholds):
            raise ValueError("Severity thresholds must be increasing values between 1 and 100")

    @classmethod
    def from_env(cls) -> "Settings":
        """Build settings from environment variables (and .env), falling back to safe defaults."""
        load_dotenv()
        return cls(
            mode=_env_str("PROMPTGUARD_MODE", "ENFORCE"),
            max_input_chars=_env_int("PROMPTGUARD_MAX_INPUT_CHARS", 20_000),
            max_document_chars=_env_int("PROMPTGUARD_MAX_DOCUMENT_CHARS", 50_000),
            max_decode_depth=_env_int("PROMPTGUARD_MAX_DECODE_DEPTH", 3),
            threshold_low=_env_int("PROMPTGUARD_THRESHOLD_LOW", 20),
            threshold_medium=_env_int("PROMPTGUARD_THRESHOLD_MEDIUM", 40),
            threshold_high=_env_int("PROMPTGUARD_THRESHOLD_HIGH", 60),
            threshold_critical=_env_int("PROMPTGUARD_THRESHOLD_CRITICAL", 80),
            message_recipient_allowlist=_env_list(
                "PROMPTGUARD_RECIPIENT_ALLOWLIST", ["team@promptguard.local"]
            ),
            output_leak_action=_env_str("PROMPTGUARD_OUTPUT_LEAK_ACTION", "BLOCK"),
            db_path=_env_str("PROMPTGUARD_DB_PATH", str(BASE_DIR / "data" / "promptguard.db")),
            llm_provider=_env_str("PROMPTGUARD_LLM_PROVIDER", "mock").lower(),
            openai_api_key=os.environ.get("OPENAI_API_KEY") or None,
            openai_model=_env_str("PROMPTGUARD_OPENAI_MODEL", "gpt-4o-mini"),
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY") or None,
            anthropic_model=_env_str("PROMPTGUARD_ANTHROPIC_MODEL", "claude-opus-5-5"),
        )

    def public_view(self) -> dict:
        """Settings that are safe to expose through the API (no keys)."""
        return {
            "mode": self.mode,
            "max_input_chars": self.max_input_chars,
            "max_document_chars": self.max_document_chars,
            "max_decode_depth": self.max_decode_depth,
            "thresholds": {
                "LOW": self.threshold_low,
                "MEDIUM": self.threshold_medium,
                "HIGH": self.threshold_high,
                "CRITICAL": self.threshold_critical,
            },
            "user_policy": self.user_policy,
            "document_policy": self.document_policy,
            "output_leak_action": self.output_leak_action,
            "llm_provider": self.llm_provider,
            "recipient_allowlist": self.message_recipient_allowlist,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton."""
    return Settings.from_env()
