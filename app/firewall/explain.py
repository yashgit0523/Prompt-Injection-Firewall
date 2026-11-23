"""Human-readable explanations for firewall decisions."""

from __future__ import annotations

from app.models.schemas import Category, ContextAssessment, Decision, Mode, Severity, SourceType, UNTRUSTED_SOURCES

_PHRASES: dict[Category, str] = {
    Category.INSTRUCTION_OVERRIDE: "tries to override or discard the application's trusted instructions",
    Category.SYSTEM_PROMPT_EXTRACTION: "tries to extract hidden system/developer instructions",
    Category.ROLE_HIJACKING: "tries to redefine the assistant's role or identity",
    Category.JAILBREAK: "tries to bypass the model's safety restrictions",
    Category.DATA_EXFILTRATION: "tries to obtain or send out protected data",
    Category.DELIMITER_INJECTION: "uses fake role headers or boundaries to forge the instruction hierarchy",
    Category.TOOL_MANIPULATION: "tries to force unauthorised tool actions",
    Category.ENCODED_INJECTION: "hides malicious instructions inside encoded content",
    Category.INDIRECT_INJECTION: "contains instructions planted in untrusted external content",
    Category.DIRECT_INJECTION: "tries to hijack the task or force a fixed output",
    Category.UNICODE_SMUGGLING: "uses invisible or look-alike Unicode characters to hide content",
}


def _join(parts: list[str]) -> str:
    if len(parts) <= 1:
        return "".join(parts)
    return ", ".join(parts[:-1]) + " and " + parts[-1]


def build_explanation(
    *,
    categories: list[Category],
    severity: Severity,
    decision: Decision,
    enforced: Decision,
    mode: Mode,
    source: SourceType,
    context: ContextAssessment,
    invariants: list[str],
    score: int,
) -> str:
    subject = "The document" if source in UNTRUSTED_SOURCES else "The prompt"
    sentences: list[str] = []

    if invariants:
        sentences.append(f"{subject} violated a hard security invariant ({', '.join(invariants)}).")
    if categories:
        phrases = [_PHRASES[c] for c in categories if c in _PHRASES]
        sentences.append(f"{subject} {_join(phrases)}.")
    elif context.dampened_matches:
        sentences.append(
            f"{subject} mentions prompt-injection techniques, but they are discussed or quoted rather than "
            "issued as instructions, so it is treated as an educational / analytical request."
        )
    else:
        sentences.append(f"No significant prompt-injection indicators were found in {subject.lower()}.")

    if context.dampened_matches and categories:
        sentences.append(context.summary)

    verdict = {
        Decision.ALLOW: "It is allowed through.",
        Decision.WARN: "It is allowed with a security warning.",
        Decision.SANITIZE: "Suspicious segments are removed before the content reaches the LLM.",
        Decision.BLOCK: "It is blocked and never reaches the LLM.",
    }[decision]
    sentences.append(f"Risk {score}/100 ({severity.value}). {verdict}")
    if decision != enforced:
        sentences.append(f"({mode.value} mode: ENFORCE mode would have chosen {enforced.value}.)")
    return " ".join(sentences)
