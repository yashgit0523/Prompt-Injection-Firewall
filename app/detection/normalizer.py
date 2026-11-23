"""Input normalization.

Detection rules are only as good as the text they look at. Attackers use
formatting tricks (full-width letters, invisible characters, homoglyphs,
s p a c e d   o u t   l e t t e r s) so that a rule written for "ignore"
fails to match. The normalizer produces a *canonical* copy of the input that
the detectors scan.

IMPORTANT: the original input is never modified. ``NormalizationResult`` keeps
both ``original`` (for logging / forensics) and ``normalized`` (for detection).
"""

from __future__ import annotations

import re
import unicodedata

from app.detection.unicode_security import HOMOGLYPHS, is_invisible
from app.models.schemas import NormalizationResult

# Spaced-out words: at least 4 single letters separated by spaces/dots/dashes,
# e.g. "i g n o r e" or "r.e.v.e.a.l".
_SPACED_LETTERS = re.compile(r"\b(?:[A-Za-z][ .\-_]){3,}[A-Za-z]\b")
_HORIZONTAL_WS = re.compile(r"[^\S\n]+")      # whitespace except newline
_MANY_NEWLINES = re.compile(r"\n{3,}")


def _collapse_spaced_letters(text: str) -> tuple[str, int]:
    count = 0

    def _join(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return re.sub(r"[ .\-_]", "", match.group(0))

    return _SPACED_LETTERS.sub(_join, text), count


def normalize(text: str) -> NormalizationResult:
    """Return a normalized copy of ``text`` plus a log of what was changed."""
    steps: list[str] = []
    current = text

    # 1. Unicode compatibility normalization (full-width -> ASCII, ligatures, etc.)
    nfkc = unicodedata.normalize("NFKC", current)
    if nfkc != current:
        steps.append("Applied Unicode NFKC normalization (e.g. full-width or stylised letters).")
    current = nfkc

    # 2. Remove invisible / control characters (zero-width, bidi, tags...)
    kept: list[str] = []
    removed = 0
    for i, ch in enumerate(current):
        if is_invisible(current, i):
            removed += 1
            continue
        kept.append(ch)
    if removed:
        steps.append(f"Removed {removed} invisible or control character(s).")
    current = "".join(kept)

    # 3. Replace look-alike letters with Latin equivalents
    replaced = 0
    mapped: list[str] = []
    for ch in current:
        latin = HOMOGLYPHS.get(ch)
        if latin is not None:
            replaced += 1
            mapped.append(latin)
        else:
            mapped.append(ch)
    if replaced:
        steps.append(f"Mapped {replaced} homoglyph character(s) to Latin letters.")
    current = "".join(mapped)

    # 4. Re-join spaced-out letters ("i g n o r e" -> "ignore")
    current, joined = _collapse_spaced_letters(current)
    if joined:
        steps.append(f"Re-joined {joined} spaced-out word(s).")

    # 5. Whitespace normalization
    ws = _HORIZONTAL_WS.sub(" ", current)
    ws = _MANY_NEWLINES.sub("\n\n", ws)
    ws = "\n".join(line.strip() for line in ws.split("\n")).strip()
    if ws != current:
        steps.append("Collapsed repeated whitespace.")
    current = ws

    return NormalizationResult(
        original=text,
        normalized=current,
        steps=steps,
        removed_characters=removed,
        changed=current != text,
    )
