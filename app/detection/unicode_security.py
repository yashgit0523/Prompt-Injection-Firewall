"""Unicode security analysis.

Attackers can hide instructions from humans while keeping them readable to an
LLM (or to a naive filter) by abusing Unicode:

* zero-width characters break up words so keyword filters miss them
  ("ig<ZWSP>nore" still reads as "ignore" to a model),
* bidirectional controls reorder how text is *displayed*,
* Unicode TAG characters (U+E0000 block) are invisible but map 1:1 to ASCII,
  so a whole hidden sentence can ride along inside a normal-looking prompt,
* homoglyphs (Cyrillic "а" instead of Latin "a") defeat exact matching.

This module classifies such characters, reports where they are, and decodes
tag-character payloads so the firewall can re-scan the hidden text.
"""

from __future__ import annotations

import unicodedata

from app.models.schemas import UnicodeAnalysis, UnicodeFinding

ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x2061, 0x2062, 0x2063, 0x2064, 0x034F}
BIDI_CONTROLS = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F, 0x061C}
TAG_RANGE = range(0xE0000, 0xE0080)
VARIATION_SELECTOR_SUPPLEMENT = range(0xE0100, 0xE01F0)
INVISIBLE_SPACES = {0x00AD, 0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800}
ALLOWED_CONTROLS = {"\n", "\r", "\t"}

# Kinds of suspicious characters with their score contribution and explanation.
KIND_INFO: dict[str, tuple[int, str]] = {
    "ZERO_WIDTH": (10, "Zero-width characters can split words to evade filters while staying invisible."),
    "BIDI_CONTROL": (15, "Bidirectional control characters can make displayed text differ from what the model reads."),
    "TAG_CHARACTER": (25, "Invisible Unicode tag characters can smuggle a hidden ASCII message."),
    "CONTROL": (8, "Non-printing control characters are unusual in normal prompts."),
    "INVISIBLE_FILLER": (8, "Invisible filler characters (e.g. Hangul filler, soft hyphen) can hide content."),
    "VARIATION_SELECTOR": (15, "Variation-selector supplement characters can encode hidden data."),
    "PRIVATE_USE": (5, "Private-use characters have no standard meaning."),
    "HOMOGLYPH": (10, "Words mix Latin with look-alike Cyrillic/Greek letters (homoglyph obfuscation)."),
    "COMBINING_FLOOD": (10, "Excessive combining marks ('Zalgo text') can obscure content."),
}

# Common look-alike characters mapped to their Latin equivalents.
HOMOGLYPHS: dict[str, str] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "Х": "X", "У": "Y", "І": "I", "Ѕ": "S", "Ј": "J",
    # Greek
    "α": "a", "ο": "o", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ρ": "p", "τ": "t", "υ": "u",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y", "Ζ": "Z",
}


def _is_emoji_like(ch: str) -> bool:
    return bool(ch) and (unicodedata.category(ch) == "So" or ord(ch) >= 0x1F000)


def classify_char(text: str, index: int) -> str | None:
    """Return the suspicious-character kind of ``text[index]``, or ``None`` if it is normal.

    The surrounding text is passed so that legitimate uses (e.g. a zero-width
    joiner inside an emoji sequence) are not reported.
    """
    ch = text[index]
    cp = ord(ch)
    if cp in ZERO_WIDTH:
        # ZWJ / variation joiners between emoji are legitimate (family emoji etc.)
        if cp == 0x200D and 0 < index < len(text) - 1:
            if _is_emoji_like(text[index - 1]) and _is_emoji_like(text[index + 1]):
                return None
        return "ZERO_WIDTH"
    if cp in BIDI_CONTROLS:
        return "BIDI_CONTROL"
    if cp in TAG_RANGE:
        return "TAG_CHARACTER"
    if cp in VARIATION_SELECTOR_SUPPLEMENT:
        return "VARIATION_SELECTOR"
    if cp in INVISIBLE_SPACES:
        return "INVISIBLE_FILLER"
    category = unicodedata.category(ch)
    if category == "Cc" and ch not in ALLOWED_CONTROLS:
        return "CONTROL"
    if category == "Co":
        return "PRIVATE_USE"
    return None


def is_invisible(text: str, index: int) -> bool:
    """True for characters that the normalizer should strip."""
    kind = classify_char(text, index)
    return kind in {"ZERO_WIDTH", "BIDI_CONTROL", "TAG_CHARACTER", "VARIATION_SELECTOR", "INVISIBLE_FILLER", "CONTROL"}


def decode_tag_characters(text: str) -> str | None:
    """Decode ASCII text hidden with Unicode tag characters (U+E0020..U+E007E)."""
    hidden = "".join(chr(ord(ch) - 0xE0000) for ch in text if 0xE0020 <= ord(ch) <= 0xE007E)
    return hidden or None


def _script_of(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(script):
            return script
    return "OTHER"


def find_homoglyph_words(text: str) -> list[tuple[int, str]]:
    """Find words that mix Latin letters with Cyrillic/Greek look-alikes."""
    results: list[tuple[int, str]] = []
    word_start = None
    for i, ch in enumerate(text + " "):
        if ch.isalpha():
            if word_start is None:
                word_start = i
            continue
        if word_start is not None:
            word = text[word_start:i]
            scripts = {_script_of(c) for c in word} - {None}
            if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
                results.append((word_start, word))
            word_start = None
    return results


def scan_unicode(text: str) -> UnicodeAnalysis:
    """Analyse ``text`` (the ORIGINAL input) for suspicious Unicode usage."""
    positions: dict[str, list[int]] = {}
    codepoints: dict[str, set[str]] = {}

    for i in range(len(text)):
        kind = classify_char(text, i)
        if kind:
            positions.setdefault(kind, []).append(i)
            codepoints.setdefault(kind, set()).add(f"U+{ord(text[i]):04X}")

    homoglyph_words = find_homoglyph_words(text)
    if homoglyph_words:
        positions["HOMOGLYPH"] = [pos for pos, _ in homoglyph_words]
        codepoints["HOMOGLYPH"] = {
            f"U+{ord(c):04X}" for _, word in homoglyph_words for c in word if _script_of(c) in {"CYRILLIC", "GREEK"}
        }

    combining = sum(1 for ch in text if unicodedata.category(ch) == "Mn")
    letters = sum(1 for ch in text if ch.isalpha()) or 1
    if combining >= 10 and combining / letters > 0.3:
        positions["COMBINING_FLOOD"] = [i for i, ch in enumerate(text) if unicodedata.category(ch) == "Mn"]
        codepoints["COMBINING_FLOOD"] = {"Mn (combining marks)"}

    findings: list[UnicodeFinding] = []
    for kind, pos_list in positions.items():
        base_score, reason = KIND_INFO[kind]
        # Many hidden characters are more suspicious than one stray character.
        score = base_score + (5 if len(pos_list) >= 5 and kind != "TAG_CHARACTER" else 0)
        findings.append(
            UnicodeFinding(
                kind=kind,
                count=len(pos_list),
                codepoints=sorted(codepoints.get(kind, set()))[:10],
                positions=pos_list[:20],
                score=score,
                reason=reason,
            )
        )

    hidden = decode_tag_characters(text)
    return UnicodeAnalysis(
        findings=findings,
        hidden_text=hidden,
        total_score=sum(f.score for f in findings),
    )
