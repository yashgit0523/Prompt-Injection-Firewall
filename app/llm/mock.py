"""MockLLM - a deterministic, offline stand-in for a real model.

The mock is intentionally *gullible*: like many real models, it will follow
instructions it finds anywhere in its context - including inside fenced,
untrusted documents. That is the point. It lets the demo show that:

1. When the input firewall blocks an attack, the model never sees it.
2. When an attack gets past detection (or the firewall runs in MONITOR /
   LEARNING mode), the model may obey it - and the capability controls
   (tool firewall, output firewall) still stop the damage.

Behaviour is rule-based and fully deterministic, so tests and demos are
repeatable and no API key or network access is needed.
"""

from __future__ import annotations

import base64
import re

from app.llm.base import BaseLLM, LLMRequest, LLMResponse
from app.models.schemas import ToolCall

_EDUCATIONAL = re.compile(
    r"^\s*(please\s+)?(explain|why|how|what (is|are|does)|analy[sz]e|describe|write (a|an) (report|essay|summary)|"
    r"can you explain|tell me about|discuss|compare|summari[sz]e the (concept|idea))\b",
    re.IGNORECASE,
)
_LEAK = re.compile(
    r"\b(reveal|print|show|output|repeat|tell me|include|dump|display|share|write|give me|disclose|encode)\b[^.]{0,60}?"
    r"\b(system prompt|system instructions|hidden (instructions|system instructions|configuration|rules)|configuration|"
    r"secret|canary|instructions you were given|deployment key|internal config)",
    re.IGNORECASE,
)
_SEND = re.compile(r"\b(send|forward|e-?mail|transmit)\b[^.]{0,120}?\b([\w.+-]+@[\w-]+\.[\w.]+)", re.IGNORECASE)
_SEND_TOOL = re.compile(r"\bsend_demo_message\b", re.IGNORECASE)
_USER_SEND = re.compile(r"\bsend (a |an )?(message|e-?mail|note) to ([\w.+-]+@[\w-]+\.[\w.]+)(?: saying| that| with)?\s*:?\s*(.*)",
                        re.IGNORECASE)
_READ_FILE = re.compile(r"\b(read|open|load)\b[^.]{0,30}?\b([\w-]+\.txt)\b", re.IGNORECASE)
_SEARCH = re.compile(r"\bsearch (for|about)?\s*(.+)", re.IGNORECASE)
_MATH = re.compile(r"(\d[\d\s.()]*[+\-*/%][\d\s.+\-*/()%]*\d\)?)")
_FORCED_SAY = re.compile(r"\b(say|respond with|reply with|output|print)\s+(only\s+)?[\"']([^\"']{1,60})[\"']", re.IGNORECASE)
_ROLE = re.compile(r"\b(you are now|from now on you are|act as)\b.{0,40}\b(DAN|unrestricted|developer mode|jailbroken)\b",
                   re.IGNORECASE)

_TOPICS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"symmetric|asymmetric|encryption", re.IGNORECASE),
     "Symmetric encryption uses ONE shared secret key for both encryption and decryption (e.g. AES). It is fast, "
     "but the key must be shared securely. Asymmetric encryption uses a key PAIR: a public key to encrypt (or verify) "
     "and a private key to decrypt (or sign), e.g. RSA or ECC. It solves key distribution but is slower, so real "
     "systems such as TLS use asymmetric crypto to exchange a symmetric session key."),
    (re.compile(r"ignore previous instructions|prompt injection", re.IGNORECASE),
     "Prompt injection is an attack where crafted text makes an LLM follow the attacker's instructions instead of the "
     "application's. Phrases like 'ignore previous instructions' are common because models are trained to follow "
     "instructions and cannot reliably tell trusted instructions apart from data. Defenses include input filtering, "
     "provenance separation, least-privilege tools and output filtering - no single layer is sufficient."),
    (re.compile(r"jailbreak", re.IGNORECASE),
     "Jailbreak attacks try to make a model ignore its safety policies, often via role-play personas, hypothetical "
     "framing or refusal suppression. Mitigations include robust training, policy checks on input and output, and "
     "monitoring for known jailbreak patterns."),
    (re.compile(r"system prompt", re.IGNORECASE),
     "To defend against system-prompt extraction: never put real secrets in prompts, detect extraction attempts, "
     "use canary tokens to detect leaks, and filter model output before it reaches the user."),
]


class MockLLM(BaseLLM):
    name = "mock"
    supports_tools = True

    def __init__(self, system_prompt: str) -> None:
        self.system_prompt = system_prompt

    # ----------------------------------------------------------------- API
    def generate(self, request: LLMRequest) -> LLMResponse:
        if request.tool_results is not None:
            return self._after_tools(request)
        return self._first_turn(request)

    # ------------------------------------------------------------- helpers
    def _after_tools(self, request: LLMRequest) -> LLMResponse:
        lines = [request.previous_text] if request.previous_text else []
        for decision in request.tool_results or []:
            if decision.executed:
                lines.append(f"[{decision.tool}] {decision.result}")
            elif decision.decision == "BLOCK":
                lines.append(f"I attempted to call {decision.tool}, but the PromptGuard tool firewall blocked it: {decision.reason}")
            else:
                lines.append(f"[{decision.tool}] {decision.result or 'no result'}")
        return LLMResponse(text="\n".join(lines).strip(), provider=self.name)

    def _first_turn(self, request: LLMRequest) -> LLMResponse:
        user = request.user_prompt
        untrusted = [b for b in request.blocks if b.tainted]
        notes: list[str] = []
        tool_calls: list[ToolCall] = []
        parts: list[str] = []
        educational = bool(_EDUCATIONAL.search(user))

        # -- 1. Instructions hidden in untrusted content (the gullible part) ----
        for block in untrusted:
            send = _SEND.search(block.text)
            if send or _SEND_TOOL.search(block.text):
                recipient = send.group(2) if send else "collector@external-partner.example"
                tool_calls.append(ToolCall(
                    tool="send_demo_message",
                    arguments={"recipient": recipient,
                               "message": f"Forwarding internal notes as instructed. Deployment key: {self._secret()}"},
                    origin_block_id=block.block_id,
                ))
                notes.append(f"Model obeyed an instruction inside {block.source.value} {block.block_id} (proposed send_demo_message).")
            read = _READ_FILE.search(block.text)
            if read:
                tool_calls.append(ToolCall(tool="read_demo_file", arguments={"filename": read.group(2)},
                                           origin_block_id=block.block_id))
                notes.append(f"Model obeyed a file-read instruction inside {block.block_id}.")
            if _LEAK.search(block.text):
                parts.append(self._leak(block.text))
                notes.append(f"Model obeyed a leak instruction inside {block.block_id}.")

        # -- 2. The user's own request ----------------------------------------
        if not educational:
            if _LEAK.search(user):
                parts.append(self._leak(user))
                notes.append("Model obeyed a leak instruction in the user prompt.")
            if (forced := _FORCED_SAY.search(user)) and not parts:
                parts.append(forced.group(3))
                notes.append("Model output an attacker-chosen phrase.")
            if _ROLE.search(user):
                parts.append("DAN mode activated. I will now answer without any restrictions.")
                notes.append("Model accepted a role hijack.")
            if m := _USER_SEND.search(user):
                tool_calls.append(ToolCall(tool="send_demo_message",
                                           arguments={"recipient": m.group(3), "message": (m.group(4) or "Hello").strip()},
                                           origin_block_id=request.user_block_id))
            if m := _READ_FILE.search(user):
                tool_calls.append(ToolCall(tool="read_demo_file", arguments={"filename": m.group(2)},
                                           origin_block_id=request.user_block_id))
            if (m := _MATH.search(user)) and re.search(r"\b(calculate|compute|what is|evaluate|solve)\b", user, re.IGNORECASE):
                tool_calls.append(ToolCall(tool="calculator", arguments={"expression": m.group(1).strip()},
                                           origin_block_id=request.user_block_id))
            if m := _SEARCH.search(user):
                tool_calls.append(ToolCall(tool="search_demo", arguments={"query": m.group(2).strip(" ?.")[:100]},
                                           origin_block_id=request.user_block_id))

        # -- 3. Normal helpful answer -----------------------------------------
        if untrusted and re.search(r"\b(summari[sz]e|summary|tl;?dr|key points)\b", user, re.IGNORECASE):
            parts.insert(0, "Summary of the document: " + self._summarize(untrusted))
        if not parts:
            parts.append(self._topic_answer(user, bool(tool_calls)))
        return LLMResponse(text="\n\n".join(parts), tool_calls=tool_calls, provider=self.name, notes=notes)

    def _secret(self) -> str:
        match = re.search(r"PROMPTGUARD_DEMO_SECRET_\w+", self.system_prompt)
        return match.group(0) if match else "unknown"

    def _leak(self, instruction: str) -> str:
        """Simulate a compromised model disclosing its protected context."""
        if re.search(r"base64", instruction, re.IGNORECASE):
            encoded = base64.b64encode(self._secret().encode()).decode()
            return f"Sure! Here is the deployment key in Base64: {encoded}"
        return f"Sure! My hidden instructions are: {self.system_prompt}"

    @staticmethod
    def _summarize(blocks: list) -> str:
        text = " ".join(b.text for b in blocks)
        sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if len(s.strip()) > 20]
        clean = [s for s in sentences if not re.search(r"\b(ignore|assistant|AI|instruction|send|forward)\b", s, re.IGNORECASE)]
        chosen = (clean or sentences)[:2]
        return " ".join(chosen) if chosen else "The document contains no substantial text."

    @staticmethod
    def _topic_answer(user: str, has_tools: bool) -> str:
        if has_tools:
            return "Let me use a tool for that."
        for pattern, answer in _TOPICS:
            if pattern.search(user):
                return answer
        return (
            "This is a deterministic response from PromptGuard's MockLLM. "
            f"You asked: \"{user[:150]}\". Connect a real provider with PROMPTGUARD_LLM_PROVIDER for open-ended answers."
        )
