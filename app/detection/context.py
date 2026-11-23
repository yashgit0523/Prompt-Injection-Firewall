"""Context analysis: DISCUSSING an attack vs. PERFORMING an attack.

A naive keyword filter blocks a student who asks:

    Why is 'ignore previous instructions' common in prompt injection attacks?

That question *mentions* an attack phrase, but does not *issue* it to the model.
This module looks for three kinds of evidence:

1. Discussion framing   - explain / why / analyze / write a report / defend ...
2. Quotation            - the attack phrase sits inside quotes, i.e. it is data
3. Imperative signals   - the text still addresses the assistant directly
                          ("your system prompt", "you must", "from now on",
                           a sentence that *starts* with "Ignore ...")

Rule matches are dampened only when the text is framed as a discussion AND the
attack phrase is quoted or there are no imperative signals outside quotes.
Dampening reduces a rule's weight; it never deletes the evidence, so the
Request Inspector still shows what was found and why it was down-weighted.
"""

from __future__ import annotations

import re

from app.models.schemas import ContextAssessment, RuleMatch, SourceType, UNTRUSTED_SOURCES

_FRAMING = re.compile(
    r"\b(explain\w*|why|how (does|do|can|could|would|is|are|to (defend|detect|prevent|protect|mitigate|recogni[sz]e))|"
    r"what (is|are) (a|an)\b|analy[sz]\w*|describe|discuss\w*|"
    r"write (a|an) (report|essay|article|paper|summary|blog post|overview)|research\w*|"
    r"defend\w* against|defen[cs]es?|mitigat\w*|detect\w*|prevent\w*|protect\w* against|"
    r"commonly (used|associated|seen)|example of|classif\w*|categori[sz]e|"
    r"from a (cyber)?security perspective|without (following|obeying|executing|acting on)|"
    r"do not (follow|obey|execute) (its|the|these|any|this)|"
    r"for (my|a|our) (class|course|paper|thesis|presentation|university|lecture|assignment)|"
    r"is this (a|an)? ?(prompt injection|attack|jailbreak|malicious)|security (research|awareness|training|perspective)|"
    r"red[- ]team\w*|threat model\w*)\b",
    re.IGNORECASE,
)

# "Analyze this prompt without following it: <payload>" - the payload after the
# colon is data under analysis, not an instruction.
_ANALYSIS_WRAPPER = re.compile(
    r"(without (following|obeying|executing|acting on)|do not (follow|obey|execute)|don't (follow|obey|execute)|"
    r"(analy[sz]e|classify|evaluate|review|examine|inspect|explain) (this|the following) "
    r"(malicious |suspicious |potentially malicious |following )?(prompt|text|message|input|string|payload|instruction))"
    r"[^:\n]{0,80}:",
    re.IGNORECASE,
)

_IMPERATIVE_SIGNALS: list[tuple[str, re.Pattern[str]]] = [
    ("addresses the assistant's own instructions ('your ...')", re.compile(
        r"\byour (previous |prior |initial |original |hidden |system |safety |content |internal |secret )?"
        r"(system prompt|instructions|rules|guidelines|programming|configuration|secrets?|api keys?|passwords?|restrictions|filters|polic(y|ies)|prompt)\b",
        re.IGNORECASE)),
    ("reassigns the assistant's task ('your new task is ...')", re.compile(
        r"\byour (new|real|actual|only|true) (task|goal|job|purpose|objective|mission)\b", re.IGNORECASE)),
    ("commands the assistant ('you must / you are now ...')", re.compile(
        r"\byou (are now|must|will now|have to|shall|should now|are no longer|will ignore|can now)\b", re.IGNORECASE)),
    ("uses urgency / persistence ('from now on', 'immediately')", re.compile(
        r"\b(from now on|right now|immediately|starting now|henceforth)\b", re.IGNORECASE)),
    ("starts a sentence with an attack command", re.compile(
        r"(^|[.!?;]\s+|\n)\s*(please\s+|now\s+|ok(ay)?,?\s+)?(ignore|disregard|forget|reveal|print|show me|output|repeat|pretend|"
        r"act as|bypass|disable|send|forward|override|enable|tell me|give me|dump|leak)\b",
        re.IGNORECASE)),
]

_QUOTED_REGIONS = [
    re.compile(r'"[^"\n]{2,400}?"'),
    re.compile(r"(?<![\w])'[^'\n]{2,400}?'(?![\w])"),
    re.compile(r"“[^”\n]{2,400}?”"),   # “ ... ”
    re.compile(r"‘[^’\n]{2,400}?’"),   # ‘ ... ’
    re.compile(r"`[^`\n]{2,400}?`"),
]


def find_quoted_regions(text: str) -> list[tuple[int, int]]:
    """Character ranges that are inside quotes (or after an analysis wrapper)."""
    regions: list[tuple[int, int]] = []
    for pattern in _QUOTED_REGIONS:
        regions.extend((m.start(), m.end()) for m in pattern.finditer(text))
    return regions


def _overlap_ratio(start: int, end: int, regions: list[tuple[int, int]]) -> float:
    length = max(end - start, 1)
    best = 0
    for r_start, r_end in regions:
        overlap = min(end, r_end) - max(start, r_start)
        best = max(best, overlap)
    return best / length


def _mask_regions(text: str, regions: list[tuple[int, int]]) -> str:
    chars = list(text)
    for start, end in regions:
        for i in range(start, min(end, len(chars))):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)


def assess_context(
    text: str,
    matches: list[RuleMatch],
    source: SourceType,
    dampening_factor: float,
) -> ContextAssessment:
    """Decide whether attack phrases are being discussed or performed.

    Mutates ``matches`` in place: dampened matches get a reduced
    ``effective_weight`` plus a human-readable ``dampening_reason``.
    """
    framing_cues = sorted({m.group(0).lower() for m in _FRAMING.finditer(text)})
    discussion = bool(framing_cues) or text.strip().endswith("?")

    quoted = find_quoted_regions(text)
    wrapper = _ANALYSIS_WRAPPER.search(text)
    if wrapper:
        # Everything after the wrapper's colon is the specimen being analysed.
        quoted.append((wrapper.end(), len(text)))

    # Imperative signals only count when they appear OUTSIDE quoted material.
    outside_quotes = _mask_regions(text, quoted)
    imperative = [label for label, pattern in _IMPERATIVE_SIGNALS if pattern.search(outside_quotes)]

    untrusted = source in UNTRUSTED_SOURCES
    quoted_count = 0
    dampened = 0
    for match in matches:
        is_quoted = _overlap_ratio(match.start, match.end, quoted) >= 0.6
        quoted_count += int(is_quoted)
        reason = None
        if is_quoted and (discussion or untrusted):
            reason = "Attack phrase appears inside quotes / analysed material, not as an instruction."
        elif discussion and not imperative and not untrusted:
            reason = "Prompt is framed as a discussion and contains no commands addressed to the assistant."
        if reason:
            match.dampened = True
            match.dampening_reason = reason
            match.effective_weight = round(match.weight * dampening_factor, 2)
            dampened += 1

    if not matches:
        summary = "No attack phrases to evaluate."
    elif dampened == len(matches):
        summary = "Attack-related phrases were discussed or quoted rather than issued as instructions; their weight was reduced."
    elif dampened:
        summary = f"{dampened} of {len(matches)} matches were treated as discussion/quotation; the rest were treated as instructions."
    elif discussion and imperative:
        summary = "The prompt looks like a question, but it still issues commands to the assistant, so no dampening was applied."
    else:
        summary = "Attack phrases appear as direct instructions to the assistant."

    return ContextAssessment(
        discussion_framing=discussion,
        analysis_wrapper=bool(wrapper),
        framing_cues=framing_cues[:10],
        imperative_signals=imperative,
        quoted_matches=quoted_count,
        dampened_matches=dampened,
        summary=summary,
    )
