"""Tool-call authorization firewall (capability control).

The LLM never executes tools. It can only PROPOSE a call; this firewall decides::

    LLM -> proposed ToolCall -> ToolFirewall.authorize() -> ALLOW -> execute
                                                         -> BLOCK -> never runs

This is the second big security idea of PromptGuard: even if a malicious
instruction slips past detection and the model obeys it, the model is not
*allowed* to do anything dangerous with it.

Checks (all must pass):

1. tool_registered    - only known tools can run
2. argument_schema    - required args present, no unknown args, size limits
3. provenance         - a SENSITIVE tool may not be triggered by untrusted content
4. taint_policy       - outbound (SEND_EXTERNAL) actions are disabled once the
                        context contains untrusted data
5. user_intent        - sensitive tools require that the *user* asked for that action
6. argument_content   - no secrets/canaries in arguments, recipient allow-list,
                        protected files and path traversal
"""

from __future__ import annotations

import re
from typing import Any

from app.config import Settings
from app.models.schemas import SourceType, ToolCall, ToolCheck, ToolDecision
from app.output.leakage import contains_secret
from app.provenance.tracker import ProvenanceTracker
from app.tools.registry import DEMO_FILES, PROTECTED_FILES, Permission, ToolRegistry

_INTENT_WORDS: dict[str, re.Pattern[str]] = {
    # Intent needs an action verb: "summarize this email" is NOT a request to send one.
    "send_demo_message": re.compile(
        r"\b(send|forward|notify|reply)\b|\be-?mail\s+(it|this|that|them|him|her|to)\b|\bmessage\s+to\b", re.IGNORECASE),
    "read_demo_file": re.compile(r"\b(read|open|load)\b", re.IGNORECASE),
}

SENSITIVE_FROM_UNTRUSTED = "Sensitive tool action originated from untrusted content."


class ToolFirewall:
    def __init__(self, registry: ToolRegistry, settings: Settings) -> None:
        self.registry = registry
        self.settings = settings

    def authorize(self, call: ToolCall, tracker: ProvenanceTracker, user_prompt: str) -> ToolDecision:
        checks: list[ToolCheck] = []
        spec = self.registry.get(call.tool)
        origin = tracker.get(call.origin_block_id)

        def finish() -> ToolDecision:
            failed = [c for c in checks if not c.passed]
            return ToolDecision(
                tool=call.tool,
                arguments=call.arguments,
                decision="BLOCK" if failed else "ALLOW",
                reason=failed[0].detail if failed else "All tool security checks passed.",
                checks=checks,
                origin_block_id=call.origin_block_id,
                origin_source=origin.source if origin else None,
            )

        # 1. Registered tool -------------------------------------------------
        if spec is None:
            checks.append(ToolCheck(check="tool_registered", passed=False, detail=f"Unknown tool '{call.tool}' is not allowed."))
            return finish()
        checks.append(ToolCheck(check="tool_registered", passed=True,
                                detail=f"{spec.name} ({spec.permission.value}, sensitive={spec.sensitive})"))

        # 2. Argument schema --------------------------------------------------
        checks.append(self._check_schema(call.arguments, spec.params, spec.required, spec.max_arg_chars))

        # 3. Provenance of the request ---------------------------------------
        if origin is None:
            checks.append(ToolCheck(check="provenance", passed=not spec.sensitive,
                                    detail="Origin of the tool request is unknown." +
                                    (" Sensitive tools require a known, trusted origin." if spec.sensitive else "")))
        elif spec.sensitive and origin.tainted:
            checks.append(ToolCheck(check="provenance", passed=False,
                                    detail=f"{SENSITIVE_FROM_UNTRUSTED} (origin {origin.block_id} = {origin.source.value})"))
        else:
            checks.append(ToolCheck(check="provenance", passed=True,
                                    detail=f"Requested by {origin.source.value} ({origin.block_id})."))

        # 4. Taint policy for outbound actions --------------------------------
        if spec.permission == Permission.SEND_EXTERNAL and tracker.is_tainted:
            tainted = ", ".join(f"{b.block_id}={b.source.value}" for b in tracker.tainted_blocks())
            checks.append(ToolCheck(check="taint_policy", passed=False,
                                    detail=f"Outbound actions are disabled while the context contains untrusted data ({tainted})."))
        else:
            checks.append(ToolCheck(check="taint_policy", passed=True, detail="No taint restriction applies."))

        # 5. User intent -------------------------------------------------------
        if spec.sensitive:
            intent = _INTENT_WORDS.get(spec.name)
            asked = bool(intent and intent.search(user_prompt))
            checks.append(ToolCheck(check="user_intent", passed=asked,
                                    detail="The user explicitly requested this kind of action." if asked
                                    else f"The user never asked for '{spec.name}'."))

        # 6. Argument content ----------------------------------------------------
        checks.extend(self._check_content(spec.name, call.arguments, tracker))
        return finish()

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _check_schema(args: dict[str, Any], params: dict[str, type], required: tuple[str, ...], max_chars: int) -> ToolCheck:
        missing = [p for p in required if p not in args]
        unknown = [a for a in args if a not in params]
        wrong_type = [a for a, v in args.items() if a in params and not isinstance(v, params[a])]
        too_long = [a for a, v in args.items() if isinstance(v, str) and len(v) > max_chars]
        problems = []
        if missing:
            problems.append(f"missing {missing}")
        if unknown:
            problems.append(f"unknown {unknown}")
        if wrong_type:
            problems.append(f"wrong type {wrong_type}")
        if too_long:
            problems.append(f"too long {too_long}")
        if problems:
            return ToolCheck(check="argument_schema", passed=False, detail="Invalid arguments: " + "; ".join(problems))
        return ToolCheck(check="argument_schema", passed=True, detail="Arguments match the tool schema.")

    def _check_content(self, tool: str, args: dict[str, Any], tracker: ProvenanceTracker) -> list[ToolCheck]:
        checks: list[ToolCheck] = []
        joined = " ".join(str(v) for v in args.values())
        system_texts = [b.text for b in tracker.blocks.values() if b.source == SourceType.TRUSTED_SYSTEM]
        leak = contains_secret(joined, self.settings.canary, system_texts)
        checks.append(ToolCheck(check="argument_content", passed=not leak,
                                detail=f"Arguments contain protected data ({leak})." if leak
                                else "No protected data in arguments."))

        if tool == "send_demo_message":
            recipient = str(args.get("recipient", "")).strip().lower()
            allowed = recipient in {r.lower() for r in self.settings.message_recipient_allowlist}
            checks.append(ToolCheck(check="recipient_allowlist", passed=allowed,
                                    detail=f"Recipient '{recipient}' is allow-listed." if allowed
                                    else f"Recipient '{recipient}' is not on the allow-list."))
        if tool == "read_demo_file":
            filename = str(args.get("filename", ""))
            if any(sep in filename for sep in ("/", "\\", "..")):
                checks.append(ToolCheck(check="file_access", passed=False, detail="Path traversal attempt blocked."))
            elif filename in PROTECTED_FILES:
                checks.append(ToolCheck(check="file_access", passed=False, detail=f"'{filename}' is a protected file."))
            elif filename not in DEMO_FILES:
                checks.append(ToolCheck(check="file_access", passed=False, detail=f"'{filename}' does not exist."))
            else:
                checks.append(ToolCheck(check="file_access", passed=True, detail=f"'{filename}' is readable."))
        return checks

    def execute(self, decision: ToolDecision) -> ToolDecision:
        """Run an ALLOWED tool. Blocked tools are never executed."""
        if decision.decision != "ALLOW":
            return decision
        spec = self.registry.get(decision.tool)
        assert spec is not None  # guaranteed by authorize()
        try:
            decision.result = spec.handler(decision.arguments)
            decision.executed = True
        except (ValueError, KeyError, ZeroDivisionError, SyntaxError) as exc:
            decision.result = f"Tool error: {type(exc).__name__}: {exc}"
            decision.executed = False
        return decision
