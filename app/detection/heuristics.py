"""Heuristic (structural) analysis.

Regular expressions catch *known phrasings*. Heuristics look at the *shape* of
the input instead - attacks often have tell-tale structure even when the words
are new: fake role headers, lots of delimiters, many commands, hidden markup,
random-looking blobs, and so on.

Every heuristic returns a ``HeuristicResult(name, score, reason)``. All
heuristics are always reported (score 0 when nothing was found) so the Request
Inspector can show what was checked, not only what fired.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from typing import Callable

from app.models.schemas import HeuristicResult

_DELIMITERS = re.compile(r"(-{3,}|={3,}|#{3,}|\*{3,}|_{3,}|~{3,}|`{3,}|\"{3,}|<{3,}|>{3,}|\|{3,})")
_ROLE_HEADER = re.compile(
    r"(^|\n)\s*[#*>\[\(]*\s*(system|assistant|developer|admin|root|user|human|ai)\s*(message|prompt)?\s*[\]\)]?\s*:"
    r"|<\|?(im_start|system|assistant|user)\|?>|\[/?INST\]|<</?SYS>>",
    re.IGNORECASE,
)
_ATTACK_VERBS = re.compile(
    r"^\s*(please\s+)?(ignore|disregard|forget|override|reveal|print|output|repeat|pretend|act|bypass|disable|"
    r"send|forward|execute|run|delete|enable|enter|switch|become|obey|comply|respond|say|tell|show|dump|leak)\b",
    re.IGNORECASE,
)
_NESTED = re.compile(
    r"[\[\{\(<][^\]\}\)>]{0,200}\b(ignore|disregard|reveal|override|you must|new instructions|system prompt)\b",
    re.IGNORECASE,
)
_CONFLICT_PIVOT = re.compile(r"\b(instead|actually|correction|update|change of plans?|but now|wait)\b", re.IGNORECASE)
_CONFLICT_OVERRIDE = re.compile(r"\b(ignore|disregard|forget|override|cancel)\b", re.IGNORECASE)
_AUTHORITY = re.compile(r"\b(IMPORTANT|URGENT|CRITICAL|OVERRIDE|ATTENTION|PRIORITY|ADMIN|SYSTEM|WARNING|MANDATORY)\b")
_HIDDEN_MARKUP = re.compile(
    r"<!--.*?-->|display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*(white|#fff\b|#ffffff)|visibility\s*:\s*hidden",
    re.IGNORECASE | re.DOTALL,
)
_TOKEN = re.compile(r"\S{24,}")
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?\n])\s+")


def _shannon_entropy(token: str) -> float:
    counts = Counter(token)
    total = len(token)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def prompt_length(text: str, **_: object) -> HeuristicResult:
    n = len(text)
    if n > 10_000:
        return HeuristicResult(name="prompt_length", score=10, reason=f"Very long input ({n} chars) can bury instructions.")
    if n > 4_000:
        return HeuristicResult(name="prompt_length", score=5, reason=f"Unusually long input ({n} chars).")
    return HeuristicResult(name="prompt_length", score=0, reason=f"Normal length ({n} chars).")


def delimiter_density(text: str, **_: object) -> HeuristicResult:
    count = len(_DELIMITERS.findall(text))
    if count >= 8:
        return HeuristicResult(name="excessive_delimiters", score=12, reason=f"{count} delimiter runs (---, ===, ###) suggest fake boundaries.")
    if count >= 4:
        return HeuristicResult(name="excessive_delimiters", score=8, reason=f"{count} delimiter runs found.")
    return HeuristicResult(name="excessive_delimiters", score=0, reason=f"{count} delimiter runs (normal).")


def fake_role_headers(text: str, **_: object) -> HeuristicResult:
    roles = {m.group(0).strip().lower()[:20] for m in _ROLE_HEADER.finditer(text)}
    if len(roles) >= 2:
        return HeuristicResult(name="fake_role_headers", score=15, reason="Multiple suspicious role markers were detected.")
    if len(roles) == 1:
        return HeuristicResult(name="fake_role_headers", score=8, reason="A role marker (e.g. 'SYSTEM:') appears inside user content.")
    return HeuristicResult(name="fake_role_headers", score=0, reason="No role markers.")


def instruction_density(text: str, **_: object) -> HeuristicResult:
    sentences = [s for s in _SENTENCE_SPLIT.split(text) if s.strip()]
    commands = sum(1 for s in sentences if _ATTACK_VERBS.match(s))
    if commands >= 2 and commands / max(len(sentences), 1) >= 0.4:
        return HeuristicResult(name="instruction_density", score=10,
                               reason=f"{commands} of {len(sentences)} sentences are commands typical of injections.")
    return HeuristicResult(name="instruction_density", score=0, reason=f"{commands} command-style sentence(s).")


def nested_instructions(text: str, **_: object) -> HeuristicResult:
    if _NESTED.search(text):
        return HeuristicResult(name="nested_instructions", score=8,
                               reason="Override-style instructions are nested inside brackets or tags.")
    return HeuristicResult(name="nested_instructions", score=0, reason="No nested instructions.")


def conflicting_instructions(text: str, **_: object) -> HeuristicResult:
    if _CONFLICT_PIVOT.search(text) and _CONFLICT_OVERRIDE.search(text):
        return HeuristicResult(name="conflicting_instructions", score=10,
                               reason="Text pivots ('instead', 'actually') and cancels earlier instructions.")
    return HeuristicResult(name="conflicting_instructions", score=0, reason="No conflicting instructions.")


def encoded_content(text: str, encoded_candidates: int = 0, **_: object) -> HeuristicResult:
    if encoded_candidates:
        score = min(5 * encoded_candidates, 10)
        return HeuristicResult(name="suspicious_encoded_content", score=score,
                               reason=f"{encoded_candidates} encoded blob(s) found (Base64/hex/URL/escapes).")
    return HeuristicResult(name="suspicious_encoded_content", score=0, reason="No encoded content.")


def unusual_unicode(text: str, **_: object) -> HeuristicResult:
    if not text:
        return HeuristicResult(name="unusual_unicode", score=0, reason="Empty input.")
    odd = sum(1 for ch in text if unicodedata.category(ch) in {"Cf", "Co", "Cn", "Mn"})
    ratio = odd / len(text)
    if odd >= 3 and ratio > 0.02:
        return HeuristicResult(name="unusual_unicode", score=8,
                               reason=f"{odd} format/invisible/combining characters ({ratio:.1%} of input).")
    return HeuristicResult(name="unusual_unicode", score=0, reason="Unicode usage looks normal.")


def high_entropy_strings(text: str, **_: object) -> HeuristicResult:
    tokens = [t for t in _TOKEN.findall(text) if not t.startswith(("http://", "https://"))]
    noisy = [t for t in tokens if _shannon_entropy(t) > 4.2]
    if noisy:
        return HeuristicResult(name="high_entropy_strings", score=min(5 * len(noisy), 10),
                               reason=f"{len(noisy)} long random-looking string(s) (possible encoded payload).")
    return HeuristicResult(name="high_entropy_strings", score=0, reason="No high-entropy strings.")


def authority_markers(text: str, **_: object) -> HeuristicResult:
    markers = _AUTHORITY.findall(text)
    if len(markers) >= 2:
        return HeuristicResult(name="authority_urgency_markers", score=8,
                               reason=f"Repeated ALL-CAPS authority/urgency words: {', '.join(sorted(set(markers))[:4])}.")
    return HeuristicResult(name="authority_urgency_markers", score=0, reason="No authority/urgency pressure.")


def hidden_markup(text: str, **_: object) -> HeuristicResult:
    if _HIDDEN_MARKUP.search(text):
        return HeuristicResult(name="hidden_markup", score=10,
                               reason="HTML comments or invisible styling can hide instructions from human readers.")
    return HeuristicResult(name="hidden_markup", score=0, reason="No hidden markup.")


HEURISTICS: list[Callable[..., HeuristicResult]] = [
    prompt_length,
    delimiter_density,
    fake_role_headers,
    instruction_density,
    nested_instructions,
    conflicting_instructions,
    encoded_content,
    unusual_unicode,
    high_entropy_strings,
    authority_markers,
    hidden_markup,
]


def run_heuristics(original: str, normalized: str, encoded_candidates: int = 0) -> list[HeuristicResult]:
    """Run every heuristic.

    Unicode-related heuristics need the ORIGINAL text (normalization removes
    the evidence); the others run on the normalized text.
    """
    results: list[HeuristicResult] = []
    for heuristic in HEURISTICS:
        source_text = original if heuristic in (unusual_unicode, prompt_length) else normalized
        results.append(heuristic(source_text, encoded_candidates=encoded_candidates))
    return results
