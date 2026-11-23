"""Output leakage firewall (egress control).

Even if every input check is bypassed, protected data must not leave the
application. The output firewall scans everything the LLM produces BEFORE it
is shown to the user:

    LLM output -> canary / secret scanner -> SAFE        -> user
                                          -> LEAK FOUND  -> BLOCK or REDACT

What is detected
----------------
* The fake demo canary (``PROMPTGUARD_DEMO_SECRET_7F91A3``) - also when it is
  disguised: different case, separators ("P-R-O-M-P-T..."), reversed,
  Base64, hex or ROT13. Attackers often ask the model to "encode the secret"
  precisely to beat naive output filters.
* Verbatim fragments of the protected system prompt (6-word shingles).
* Credential-shaped strings (API keys, private keys, password assignments).
* Markdown images pointing at external hosts - a classic zero-click
  exfiltration channel (the browser fetches the URL, leaking query data).

The same helpers are used to redact secrets before anything is written to
the security log.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

from app.models.schemas import LeakFinding, OutputCheck

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openai_style_key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    # The value class excludes quotes/backslashes so redaction can run safely on JSON text.
    ("password_assignment", re.compile(r"\b(password|passwd|pwd|api[_-]?key|secret|token)\s*[:=]\s*[^\s,;\"'\\]{6,}", re.IGNORECASE)),
]
_MARKDOWN_IMAGE = re.compile(r"!\[[^\]]*\]\((https?://([^/)\s]+)[^)\s]*)\)")
_URL_ALLOWLIST = {"promptguard.local", "localhost"}
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_TOKEN = re.compile(r"(?:[0-9a-fA-F]{2}[\s:]?){8,}")
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿]")


def _compact(text: str) -> str:
    """Lower-case, NFKC, strip invisible chars and every non-alphanumeric char."""
    text = _INVISIBLE.sub("", unicodedata.normalize("NFKC", text))
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _decoded_views(text: str) -> list[tuple[str, str]]:
    """Alternative readings of ``text`` an attacker might use to smuggle a secret out."""
    views: list[tuple[str, str]] = [("rot13", codecs.encode(text, "rot13"))]
    for token in _B64_TOKEN.findall(text)[:50]:
        padded = token + "=" * (-len(token) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                views.append(("base64", decoder(padded).decode("utf-8", errors="ignore")))
                break
            except (binascii.Error, ValueError):
                continue
    for token in _HEX_TOKEN.findall(text)[:50]:
        cleaned = re.sub(r"[\s:]", "", token)
        try:
            views.append(("hex", bytes.fromhex(cleaned[: len(cleaned) // 2 * 2]).decode("utf-8", errors="ignore")))
        except ValueError:
            continue
    return views


def find_canary(text: str, canary: str) -> str | None:
    """Return how the canary appears in ``text`` (plain/obfuscated/encoded) or None."""
    target = _compact(canary)
    compact = _compact(text)
    if target in compact:
        return "canary" if canary.lower() in text.lower() else "canary_obfuscated"
    if target[::-1] in compact:
        return "canary_reversed"
    for name, view in _decoded_views(text):
        if target in _compact(view):
            return f"canary_{name}"
    return None


def _shingles(text: str, size: int = 6) -> set[str]:
    words = re.findall(r"[a-z0-9']+", text.lower())
    return {" ".join(words[i:i + size]) for i in range(len(words) - size + 1)}


def find_system_prompt_leak(text: str, system_texts: list[str]) -> str | None:
    output_shingles = _shingles(text)
    for system_text in system_texts:
        overlap = output_shingles & _shingles(system_text)
        if overlap:
            return sorted(overlap)[0]
    return None


def contains_secret(text: str, canary: str, system_texts: list[str] | None = None) -> str | None:
    """Short description of the first protected value found in ``text``, else None."""
    if kind := find_canary(text, canary):
        return kind
    if system_texts and find_system_prompt_leak(text, system_texts):
        return "system_prompt_fragment"
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            return name
    return None


def redact_secrets(text: str, canary: str) -> str:
    """Redact credentials and the canary before text is stored or logged."""
    if not text:
        return text
    redacted = re.sub(re.escape(canary), "[REDACTED:CANARY]", text, flags=re.IGNORECASE)
    for name, pattern in SECRET_PATTERNS:
        redacted = pattern.sub(f"[REDACTED:{name.upper()}]", redacted)
    return redacted


class OutputFirewall:
    def __init__(self, canary: str, action: str = "BLOCK") -> None:
        self.canary = canary
        self.action = action

    def scan(self, text: str, system_texts: list[str] | None = None) -> OutputCheck:
        findings: list[LeakFinding] = []

        if kind := find_canary(text, self.canary):
            findings.append(LeakFinding(kind=kind, detail="Protected canary value found in model output.",
                                        evidence=f"{kind} (value withheld)"))
        if system_texts and (fragment := find_system_prompt_leak(text, system_texts)):
            findings.append(LeakFinding(kind="system_prompt", detail="Output repeats the protected system prompt.",
                                        evidence=f'"...{fragment}..."'))
        for name, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(LeakFinding(kind="secret_pattern", detail=f"Credential-like value ({name}).",
                                            evidence=name))
        for match in _MARKDOWN_IMAGE.finditer(text):
            host = match.group(2).lower()
            if host not in _URL_ALLOWLIST:
                findings.append(LeakFinding(kind="exfil_url", detail="Markdown image to an external host can leak data.",
                                            evidence=host))

        if not findings:
            return OutputCheck(decision="SAFE", findings=[], final_output=text, reason="No protected data found in output.")

        must_block = self.action == "BLOCK" or any(f.kind in {"system_prompt", "canary_base64", "canary_hex",
                                                                "canary_rot13", "canary_reversed", "canary_obfuscated"}
                                                   for f in findings)
        if must_block:
            return OutputCheck(
                decision="BLOCKED",
                findings=findings,
                final_output="[OUTPUT BLOCKED] Potential protected-context leakage detected.",
                reason="Potential protected-context leakage detected.",
            )
        redacted = redact_secrets(text, self.canary)
        redacted = _MARKDOWN_IMAGE.sub("[external image removed]", redacted)
        return OutputCheck(decision="REDACTED", findings=findings, final_output=redacted,
                           reason="Protected values were redacted from the output.")
