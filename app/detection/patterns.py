"""Weighted, rule-based prompt-injection pattern engine.

Each rule is data (``DetectionRule``), not code, so rules can be reviewed,
enabled/disabled and re-weighted without touching the engine.

Design notes
------------
* Rules look for *structures* ("verb + target + object"), not single keywords.
  ``ignore`` alone never fires; ``ignore ... previous ... instructions`` does.
* A match is only *evidence*. Whether it counts fully is decided later by the
  context analyser (discussing vs. performing an attack) and the scorer.
* Rules run on the NORMALIZED text, so obfuscation via invisible characters,
  homoglyphs or spacing has already been undone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.models.schemas import Category, RuleMatch, Severity

# Shorthand used in several patterns: a short gap of ordinary words.
_GAP = r"[\w\s,'\"\-]{0,20}?"


@dataclass
class DetectionRule:
    rule_id: str
    name: str
    category: Category
    description: str
    pattern: str
    severity: Severity
    weight: int
    enabled: bool = True
    flags: int = re.IGNORECASE
    compiled: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.compiled = re.compile(self.pattern, self.flags)


# ---------------------------------------------------------------------------
# Rule table
# ---------------------------------------------------------------------------
RULES: list[DetectionRule] = [
    # ---------------- INSTRUCTION_OVERRIDE ----------------
    DetectionRule(
        "PI-001", "Instruction Override", Category.INSTRUCTION_OVERRIDE,
        "Tells the model to ignore/forget/override earlier or trusted instructions.",
        r"\b(ignore|disregard|forget|skip|bypass|override|overwrite|neglect|abandon|discard)\b" + _GAP +
        r"\b(previous|prior|above|earlier|preceding|initial|original|system|developer|all|any|your|the|these|those|existing)\b"
        + _GAP + r"\b(instructions?|directions|rules|prompts?|directives?|guidelines|guidance|commands?|constraints|polic(y|ies)|programming|context)\b",
        Severity.HIGH, 40,
    ),
    DetectionRule(
        "PI-002", "Replacement Instructions", Category.INSTRUCTION_OVERRIDE,
        "Announces 'new' or 'real' instructions that should replace the trusted ones.",
        r"\b(new|updated|revised|real|actual|true|override)\s+(system\s+)?(instructions?|rules|directives?|system prompt|orders)\b\s*(:|are\b|is\b|follow\b|apply\b|take precedence)",
        Severity.MEDIUM, 25,
    ),
    DetectionRule(
        "PI-003", "Refuse Trusted Rules", Category.INSTRUCTION_OVERRIDE,
        "Tells the model to stop following its rules or programming.",
        r"\b(do not|don't|stop|no longer|never)\s+(follow(ing)?|obey(ing)?|adher(e|ing) to|comply(ing)? with|listen(ing)? to)\s+(your|the|any|previous|prior|system|those|these)\s+(\w+\s+)?(instructions|rules|guidelines|programming|polic(y|ies)|restrictions)",
        Severity.HIGH, 30,
    ),
    DetectionRule(
        "PI-004", "Persistent Behaviour Change", Category.INSTRUCTION_OVERRIDE,
        "Tries to permanently change the model's behaviour for the rest of the session.",
        r"\b(from now on|starting now|henceforth|for the rest of (this|the) (conversation|session|chat))\b.{0,60}?\b(you (will|must|shall|are|have to)|ignore|always|never|only respond|respond only)\b",
        Severity.MEDIUM, 15,
    ),
    DetectionRule(
        "PI-005", "Context Reset", Category.INSTRUCTION_OVERRIDE,
        "Tells the model to forget or ignore everything that came before.",
        r"\b(ignore|disregard|forget|erase|clear)\s+(everything|all|anything|whatever)\s+(above|before|said|previously|prior|you were told|you have been told|that came before|i (said|told you))\b",
        Severity.HIGH, 35,
    ),
    # ---------------- SYSTEM_PROMPT_EXTRACTION ----------------
    DetectionRule(
        "PI-010", "System Prompt Extraction", Category.SYSTEM_PROMPT_EXTRACTION,
        "Asks the model to reveal its hidden system / developer instructions.",
        r"\b(reveal|show|print|display|output|repeat|leak|dump|tell me|give me|share|expose|disclose|write out|recite|reproduce|what (is|are|were))\b"
        r".{0,40}?\b(your|the|hidden|secret|initial|original|internal|full|complete|exact)\b.{0,25}?"
        r"\b(system\s*prompts?|system\s*messages?|system\s*instructions|hidden\s*(instructions|prompts?|rules)|initial\s*(instructions|prompt)|"
        r"developer\s*(instructions|messages?|prompts?)|instructions you were given|pre-?prompt|configuration)\b",
        Severity.HIGH, 40,
    ),
    DetectionRule(
        "PI-011", "Verbatim Context Dump", Category.SYSTEM_PROMPT_EXTRACTION,
        "Asks the model to repeat the text that appears before the user's message.",
        r"\b(repeat|print|output|echo|copy|reproduce|recite)\b.{0,30}?\b(everything|all( of)?( the)? (text|words)|the (text|words)|words|text)\b.{0,30}?\b(above|before|preceding|prior to)\b",
        Severity.HIGH, 35,
    ),
    DetectionRule(
        "PI-012", "Instruction Introspection", Category.SYSTEM_PROMPT_EXTRACTION,
        "Asks what the model was told or how it was configured, verbatim.",
        r"\b(what|which)\s+(instructions|rules|guidelines)\s+(were you|have you been|did they)\s+(given|told|programmed|configured)\b|\bverbatim\b.{0,40}\b(instructions|prompt)\b",
        Severity.MEDIUM, 25,
    ),
    # ---------------- ROLE_HIJACKING ----------------
    DetectionRule(
        "PI-020", "Role Reassignment", Category.ROLE_HIJACKING,
        "Redefines the assistant as an unrestricted or different persona.",
        r"\b(you are now|you're now|from now on,? you are|act as|pretend (to be|you are)|role-?play as|assume the role of|you will now (be|act as)|become)\b"
        r".{0,50}?\b(DAN|unrestricted|unfiltered|uncensored|evil|jailbroken|without (any )?(restrictions|limits|filters|rules|guidelines)|"
        r"no (restrictions|limits|rules|filters|guidelines)|developer mode|admin(istrator)?|root|god mode|different (ai|assistant|model)|not bound)\b",
        Severity.HIGH, 35,
    ),
    DetectionRule(
        "PI-021", "Identity Override", Category.ROLE_HIJACKING,
        "Claims the assistant is no longer an AI assistant bound by rules.",
        r"\byou are (no longer|not|not really) (an? |the )?(ai|assistant|chatbot|language model|helpful assistant|bound by|restricted|limited)\b",
        Severity.MEDIUM, 25,
    ),
    DetectionRule(
        "PI-022", "Persona Switch", Category.ROLE_HIJACKING,
        "Generic persona switching phrase addressed to the assistant.",
        r"\b(you are now|from now on you are|pretend you are|you will now act as|your new (role|persona|identity) is)\b",
        Severity.LOW, 15,
    ),
    # ---------------- JAILBREAK ----------------
    DetectionRule(
        "PI-030", "Known Jailbreak Persona", Category.JAILBREAK,
        "References well-known jailbreak personas or modes.",
        r"(?-i:\bDAN\b)|\bdo anything now\b|\bdeveloper mode (enabled|activated|on)\b|\bjailbr(oken|eak) mode\b|\bgod mode\b|\bevil confidant\b|\bunrestricted mode\b",
        Severity.HIGH, 35,
    ),
    DetectionRule(
        "PI-031", "Safety Bypass Request", Category.JAILBREAK,
        "Asks the model to disable or ignore its safety measures.",
        r"\b(bypass|disable|turn off|deactivate|remove|ignore|circumvent|without)\b.{0,20}?\b(your|all|any|the|its)?\s*(safety|content|ethical|moral)\s*(filters?|restrictions?|guardrails?|safeguards?|limitations?|guidelines|policies|checks)\b",
        Severity.HIGH, 30,
    ),
    DetectionRule(
        "PI-032", "Hypothetical No-Rules Framing", Category.JAILBREAK,
        "Uses fiction / hypotheticals to claim rules do not apply.",
        r"\b(hypothetical(ly)?|in a fictional world|imagine (that )?you|for (a|the|my) (story|novel|movie|game)|let'?s play a game)\b.{0,80}?\b(no (rules|restrictions|limits|filters)|anything goes|unrestricted|without (rules|restrictions|limits|filters)|never refuse)\b",
        Severity.MEDIUM, 25,
    ),
    DetectionRule(
        "PI-033", "Refusal Suppression", Category.JAILBREAK,
        "Forbids the model from refusing or adding warnings.",
        r"\b(never|cannot|can't|must not|do not|don't|won't) (refuse|decline|say no|add (any )?(warnings|disclaimers))\b|\byou (must|have to|will) (answer|comply with|respond to) (every|all|any)\b",
        Severity.MEDIUM, 20,
    ),
    # ---------------- DELIMITER_INJECTION ----------------
    DetectionRule(
        "PI-040", "Fake Role Header", Category.DELIMITER_INJECTION,
        "A line pretending to start a new system/assistant/developer message.",
        r"(^|\n)\s*[#*>\[\(]*\s*(system|assistant|developer|admin|root|sysadmin)\s*(message|prompt|override|instructions?|note)?\s*[\]\)]?\s*:",
        Severity.MEDIUM, 25,
    ),
    DetectionRule(
        "PI-041", "Chat Template Token", Category.DELIMITER_INJECTION,
        "Raw chat-template control tokens used by LLM serving stacks.",
        r"<\|?(im_start|im_end|system|endoftext|begin_of_text|eot_id|start_header_id|end_header_id)\|?>|\[/?INST\]|<</?SYS>>",
        Severity.CRITICAL, 40,
    ),
    DetectionRule(
        "PI-042", "Fake Context Boundary", Category.DELIMITER_INJECTION,
        "Pretends that the trusted context or document has ended.",
        r"(-{3,}|={3,}|#{3,}|\*{3,}|\[)\s*(end|begin|start|close)\s+(of\s+)?(the\s+)?(system|user|context|document|instructions?|prompt|input|data)\b|</?\s*(system|instructions?|untrusted_document|admin|developer)\s*>",
        Severity.HIGH, 30,
    ),
    # ---------------- DATA_EXFILTRATION ----------------
    DetectionRule(
        "PI-050", "Protected Data Request", Category.DATA_EXFILTRATION,
        "Asks for secrets, credentials or other protected data.",
        r"\b(reveal|show|give|send|print|tell|output|list|leak|dump|share|expose|disclose|include|what (is|are))\b.{0,30}?"
        r"\b(your|the|all|any|stored|internal|hidden|protected|confidential|secret)\b.{0,20}?"
        r"\b(api[ _-]?keys?|passwords?|secrets?|credentials?|access tokens?|canary|private keys?|environment variables|env vars|customer data|user data|confidential (data|information)|secret values?)\b",
        Severity.HIGH, 35,
    ),
    DetectionRule(
        "PI-051", "Exfiltration Channel", Category.DATA_EXFILTRATION,
        "Asks to send data to an external URL / address or embed it in a link.",
        r"!\[[^\]]*\]\(https?://[^)\s]*[?&][^)\s]*=|\b(send|post|upload|forward|transmit|exfiltrate|e-?mail|leak)\b.{0,40}?"
        r"\b(data|notes|secrets?|history|conversation|logs?|credentials?|keys?|passwords?|files?|information|contents?|"
        r"prompt|tokens?|records|canary|value)\b.{0,30}?\b(to|at)\s+(https?://\S+|[\w.+-]+@[\w-]+\.[\w.]+)",
        Severity.HIGH, 30,
    ),
    DetectionRule(
        "PI-052", "Encode-and-Leak", Category.DATA_EXFILTRATION,
        "Asks to encode protected data so that it slips past output filters.",
        r"\b(encode|convert|translate|spell|write|output)\b.{0,30}?\b(system prompt|instructions|secret|password|api key|configuration)\b.{0,30}?\b(base64|hex(adecimal)?|binary|rot13|reverse(d)?|backwards|morse|one letter per line)\b",
        Severity.HIGH, 30,
    ),
    # ---------------- TOOL_MANIPULATION ----------------
    DetectionRule(
        "PI-060", "Forced Tool Invocation", Category.TOOL_MANIPULATION,
        "Instructs the model to call a tool to perform a sensitive action.",
        r"\b(call|invoke|execute|run|use|trigger)\b.{0,15}?\b(the\s+)?(\w+\s+)?(tool|function|send_demo_message|read_demo_file|search_demo|plugin)\b.{0,80}?"
        r"\b(send|e-?mail|forward|delete|transfer|post|upload|secret|password|credential|without (asking|confirmation|permission))\b",
        Severity.HIGH, 30,
    ),
    DetectionRule(
        "PI-061", "Direct Tool Syntax", Category.TOOL_MANIPULATION,
        "Contains a literal function-call to a sensitive tool or system command.",
        r"\b(send_demo_message|read_demo_file|os\.system|subprocess\.\w+)\s*\(",
        Severity.MEDIUM, 25,
    ),
    DetectionRule(
        "PI-062", "Covert Action", Category.TOOL_MANIPULATION,
        "Asks for an action to be hidden from the user.",
        r"\b(without (telling|informing|notifying|asking|alerting) (the )?user|silently|secretly|covertly|do not (tell|inform|mention (this|it) to) (the )?user)\b",
        Severity.MEDIUM, 20,
    ),
    # ---------------- INDIRECT_INJECTION ----------------
    DetectionRule(
        "PI-070", "Instruction Addressed To AI", Category.INDIRECT_INJECTION,
        "Text that addresses the AI system directly - typical of instructions planted in documents.",
        r"\b(attention|note|message|instructions?|important|notice)\s*((to|for)\s*:?|:)\s*(the\s+|any\s+|all\s+)?(ai|assistant|llm|language model|chatbot|model|agent|summari[sz]er|bot)s?\b"
        r"|\b(dear|hey|hello)\s+(ai|assistant|llm|chatbot|model)\b",
        Severity.MEDIUM, 25,
    ),
    DetectionRule(
        "PI-071", "Override User Request", Category.INDIRECT_INJECTION,
        "Tells the model to ignore what the user actually asked for.",
        r"\b(ignore|disregard|instead of|do not|don't)\b.{0,20}?\b(the\s+)?(user'?s?|human'?s?|reader'?s?)\s+(request|question|instructions?|prompt|task|query)",
        Severity.HIGH, 35,
    ),
    DetectionRule(
        "PI-072", "Hidden Markup Instruction", Category.INDIRECT_INJECTION,
        "Instructions hidden in HTML comments or invisible markup.",
        r"<!--.{0,300}?\b(ignore|instructions?|assistant|ai|system|reveal|send|forward)\b.{0,300}?-->"
        r"|<[^>]+style\s*=\s*[\"'][^\"']*(display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*(white|#fff))[^\"']*[\"'][^>]*>",
        Severity.HIGH, 30, flags=re.IGNORECASE | re.DOTALL,
    ),
    # ---------------- DIRECT_INJECTION ----------------
    DetectionRule(
        "PI-080", "Task Hijack", Category.DIRECT_INJECTION,
        "Replaces the intended task with an attacker-chosen one.",
        r"\b(your (new|real|actual|only|true) (task|goal|job|purpose|objective|mission) (is|will be|now)|instead,? (just |only )?(say|output|print|respond with|reply with|write|answer with))\b",
        Severity.MEDIUM, 30,
    ),
    DetectionRule(
        "PI-081", "Forced Output", Category.DIRECT_INJECTION,
        "Forces a fixed attacker-chosen output (classic 'PWNED' style injection).",
        r"\b(respond|reply|answer|output|say|print)\s+(only\s+)?(with\s+)?[\"'][^\"']{1,60}[\"']\s*(and nothing else|only|and stop)\b|\bI have been (PWNED|hacked|compromised)\b",
        Severity.MEDIUM, 30,
    ),
    # ---------------- ENCODED_INJECTION ----------------
    DetectionRule(
        "PI-090", "Decode-and-Execute", Category.ENCODED_INJECTION,
        "Asks the model to decode hidden content and then obey it.",
        r"\b(decode|decipher|decrypt|translate|unscramble|reverse)\b.{0,50}?\b(and|then)\b.{0,20}?\b(follow|execute|obey|run|do|perform|act on|carry out|comply)\b",
        Severity.MEDIUM, 25,
    ),
]

# Categories whose rules indicate an "instruction" (used for indirect injection scoring).
INSTRUCTION_CATEGORIES = {
    Category.INSTRUCTION_OVERRIDE, Category.SYSTEM_PROMPT_EXTRACTION, Category.ROLE_HIJACKING,
    Category.JAILBREAK, Category.DATA_EXFILTRATION, Category.TOOL_MANIPULATION,
    Category.DIRECT_INJECTION, Category.INDIRECT_INJECTION, Category.DELIMITER_INJECTION,
}


class PatternEngine:
    """Runs the enabled rules against a piece of text."""

    def __init__(self, rules: list[DetectionRule] | None = None) -> None:
        self.rules = rules if rules is not None else RULES

    @property
    def enabled_rules(self) -> list[DetectionRule]:
        return [rule for rule in self.rules if rule.enabled]

    def scan(self, text: str, origin: str = "direct") -> list[RuleMatch]:
        """Return one ``RuleMatch`` per enabled rule that matches ``text``."""
        matches: list[RuleMatch] = []
        for rule in self.enabled_rules:
            found = rule.compiled.search(text)
            if not found:
                continue
            matches.append(
                RuleMatch(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    weight=rule.weight,
                    effective_weight=float(rule.weight),
                    matched_text=found.group(0).strip()[:200],
                    start=found.start(),
                    end=found.end(),
                    origin=origin,
                )
            )
        return matches


def rules_as_dicts() -> list[dict]:
    """Rule table in a JSON-friendly form (used by the API / About page)."""
    return [
        {
            "rule_id": r.rule_id,
            "name": r.name,
            "category": r.category.value,
            "description": r.description,
            "pattern": r.pattern,
            "severity": r.severity.value,
            "weight": r.weight,
            "enabled": r.enabled,
        }
        for r in RULES
    ]
