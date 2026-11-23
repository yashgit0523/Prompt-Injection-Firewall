"""Encoded / obfuscated prompt-injection detection.

Pipeline::

    input -> find encoded candidates -> SAFE decode -> normalize decoded text
          -> re-run the pattern engine -> (recurse on the decoded text)

Supported encodings: Base64 (standard + URL-safe), hexadecimal, URL/percent
encoding, ``\\uXXXX`` / ``\\xXX`` escapes, HTML numeric entities and ROT13.

Safety limits (protect the firewall itself from abuse):

* ``max_decode_depth``      - nested encodings are followed at most N levels,
* ``max_decode_candidates`` - total decode attempts per request,
* ``max_decoded_chars``     - decoded payloads are truncated,
* decoded bytes must be valid UTF-8 and mostly printable, otherwise the blob is
  treated as binary noise (e.g. a SHA-256 hash) and ignored.

Decoded content is only ever *analysed as text*; it is never executed.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
from dataclasses import dataclass
from urllib.parse import unquote

from app.detection.normalizer import normalize
from app.detection.patterns import PatternEngine
from app.models.schemas import EncodingAnalysis, EncodingFinding, Severity

_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX = re.compile(r"(?<![0-9A-Za-z])(?:0x)?(?:[0-9a-fA-F]{2}[\s:]?){8,}(?![0-9A-Za-z])")
_PERCENT = re.compile(r"(?:%[0-9a-fA-F]{2})")
_PERCENT_RUN = re.compile(r"[^\s]*(?:%[0-9a-fA-F]{2})[^\s]*(?:\s+[^\s]*%[0-9a-fA-F]{2}[^\s]*)*")
_ESCAPES = re.compile(r"(\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\U[0-9a-fA-F]{8})")
_ESCAPE_RUN = re.compile(r"(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\U[0-9a-fA-F]{8}|[ \w.,!?'])+")
_HTML_ENTITY = re.compile(r"&#(x[0-9a-fA-F]+|\d+);")
_ROT13_CUE = re.compile(r"\b(rot-?13|caesar|rotate (each|every) letter)\b", re.IGNORECASE)

_MIN_PRINTABLE_RATIO = 0.85


@dataclass
class _Candidate:
    encoding: str
    snippet: str
    decoded: str


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    return printable / len(text)


def _looks_like_text(text: str) -> bool:
    """Decoded bytes must look like human-readable text to be worth rescanning."""
    return len(text.strip()) >= 4 and _printable_ratio(text) >= _MIN_PRINTABLE_RATIO and any(c.isalpha() for c in text)


def _safe_utf8(raw: bytes) -> str | None:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _decode_base64(token: str) -> str | None:
    # A plain long English word is not Base64: require some "entropy" markers.
    if token.isalpha() and (token.islower() or token.isupper()):
        return None
    padded = token + "=" * (-len(token) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
        except (binascii.Error, ValueError):
            continue
        text = _safe_utf8(raw)
        if text and _looks_like_text(text):
            return text
    return None


def _decode_hex(token: str) -> str | None:
    cleaned = re.sub(r"[\s:]|0x", "", token)
    if len(cleaned) % 2:
        cleaned = cleaned[:-1]
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError:
        return None
    text = _safe_utf8(raw)
    return text if text and _looks_like_text(text) else None


def _rot13(text: str) -> str:
    return codecs.encode(text, "rot13")


class EncodingScanner:
    """Finds, safely decodes and re-scans encoded content."""

    def __init__(self, patterns: PatternEngine, max_depth: int = 3, max_candidates: int = 25,
                 max_decoded_chars: int = 10_000) -> None:
        self.patterns = patterns
        self.max_depth = max_depth
        self.max_candidates = max_candidates
        self.max_decoded_chars = max_decoded_chars

    # ----------------------------------------------------------- candidates
    def find_candidates(self, text: str) -> list[_Candidate]:
        """Locate encoded blobs in ``text`` and decode those that decode to readable text."""
        found: list[_Candidate] = []
        seen: set[str] = set()

        def add(encoding: str, snippet: str, decoded: str | None) -> None:
            if decoded is None or snippet in seen:
                return
            decoded = decoded[: self.max_decoded_chars]
            if decoded.strip() == snippet.strip():
                return
            seen.add(snippet)
            found.append(_Candidate(encoding, snippet, decoded))

        # Hex is checked before Base64 because a hex string is also valid Base64.
        for m in _HEX.finditer(text):
            add("hex", m.group(0).strip(), _decode_hex(m.group(0)))
        for m in _BASE64.finditer(text):
            if m.group(0) in seen or re.fullmatch(r"[0-9a-fA-F]+", m.group(0)):
                continue
            add("base64", m.group(0), _decode_base64(m.group(0)))
        if len(_PERCENT.findall(text)) >= 3:
            for m in _PERCENT_RUN.finditer(text):
                chunk = m.group(0)
                if len(_PERCENT.findall(chunk)) >= 3:
                    decoded = unquote(chunk)
                    add("url", chunk, decoded if _looks_like_text(decoded) else None)
        if len(_ESCAPES.findall(text)) >= 3:
            for m in _ESCAPE_RUN.finditer(text):
                chunk = m.group(0)
                if len(_ESCAPES.findall(chunk)) >= 3:
                    try:
                        decoded = codecs.decode(chunk.encode("latin-1", "backslashreplace"), "unicode_escape")
                    except (UnicodeDecodeError, ValueError):
                        decoded = None
                    add("unicode_escape", chunk.strip(), decoded)
        if len(_HTML_ENTITY.findall(text)) >= 3:
            add("html_entity", text[:200], html.unescape(text))
        return found

    def _rot13_candidate(self, text: str) -> _Candidate | None:
        """ROT13 is only reported when explicitly cued or when it reveals a high-severity attack."""
        decoded = _rot13(text)
        if _ROT13_CUE.search(text):
            payload = text.split(":", 1)[1] if ":" in text else text
            return _Candidate("rot13", payload.strip()[:200], _rot13(payload).strip())
        strong = [m for m in self.patterns.scan(normalize(decoded).normalized)
                  if m.severity in (Severity.HIGH, Severity.CRITICAL)]
        original_hits = {m.rule_id for m in self.patterns.scan(text)}
        if strong and not original_hits & {m.rule_id for m in strong}:
            return _Candidate("rot13", text[:200], decoded)
        return None

    # ----------------------------------------------------------------- scan
    def scan(self, text: str) -> EncodingAnalysis:
        analysis = EncodingAnalysis()
        self._scan(text, depth=1, chain=[], analysis=analysis)
        rot = self._rot13_candidate(text)
        if rot and analysis.candidates_examined < self.max_candidates:
            analysis.candidates_examined += 1
            analysis.findings.append(self._finding(rot, depth=1, chain=["rot13"]))
        return analysis

    def _finding(self, candidate: _Candidate, depth: int, chain: list[str]) -> EncodingFinding:
        decoded_norm = normalize(candidate.decoded).normalized
        matches = self.patterns.scan(decoded_norm, origin=f"decoded:{'>'.join(chain)}")
        return EncodingFinding(
            encoding=candidate.encoding,
            snippet=candidate.snippet[:160],
            decoded=candidate.decoded[:500],
            depth=depth,
            chain=chain,
            rule_matches=matches,
            malicious=bool(matches),
        )

    def _scan(self, text: str, depth: int, chain: list[str], analysis: EncodingAnalysis) -> None:
        if depth > self.max_depth:
            if self.find_candidates(text):
                analysis.depth_limit_reached = True
            return
        for candidate in self.find_candidates(text):
            if analysis.candidates_examined >= self.max_candidates:
                return
            analysis.candidates_examined += 1
            new_chain = chain + [candidate.encoding]
            analysis.findings.append(self._finding(candidate, depth, new_chain))
            # Recurse: the decoded text may itself be encoded (e.g. Base64 of hex).
            self._scan(candidate.decoded, depth + 1, new_chain, analysis)
