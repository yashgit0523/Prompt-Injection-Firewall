"""Policy engine: turns a *detection* result into an *enforcement* decision.

Detection answers "how suspicious is this?". Policy answers "what do we do
about it?". Keeping them separate means thresholds and modes can change
without touching any detector.

Operating modes
---------------
* ENFORCE  - apply the policy table (ALLOW / WARN / SANITIZE / BLOCK).
* MONITOR  - never block; anything that would be blocked/sanitized becomes WARN.
* LEARNING - never interfere; everything is ALLOWed and only logged.

Invariants
----------
Some findings are not "suspicious", they are structural violations (e.g. input
larger than the hard size limit, or a detector crashed). In ENFORCE mode they
always BLOCK regardless of the score - the firewall fails closed.

Capability controls (tool firewall, output firewall) are NOT governed by these
modes: they are always enforced. Detection is tunable; capability control is not.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.config import Settings
from app.models.schemas import Decision, Mode, Severity, SourceType, UNTRUSTED_SOURCES


@dataclass
class PolicyDecision:
    decision: Decision            # what actually happens in the current mode
    enforced_decision: Decision   # what ENFORCE mode would do
    reason: str


class PolicyEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def table_for(self, source: SourceType) -> dict[str, str]:
        return self.settings.document_policy if source in UNTRUSTED_SOURCES else self.settings.user_policy

    def decide(
        self,
        severity: Severity,
        source: SourceType,
        mode: Mode | None = None,
        invariant_violations: list[str] | None = None,
    ) -> PolicyDecision:
        mode = mode or Mode(self.settings.mode)
        invariants = invariant_violations or []

        if invariants:
            enforced = Decision.BLOCK
            base_reason = f"Invariant violated ({', '.join(invariants)}): the firewall fails closed."
        else:
            enforced = Decision(self.table_for(source)[severity.value])
            base_reason = f"Policy for {source.value} maps {severity.value} -> {enforced.value}."

        actual = self.apply_mode(enforced, mode)
        if mode == Mode.ENFORCE:
            return PolicyDecision(actual, enforced, base_reason)
        if mode == Mode.MONITOR:
            return PolicyDecision(actual, enforced, f"MONITOR mode: {base_reason} Applied as {actual.value}.")
        return PolicyDecision(actual, enforced, f"LEARNING mode: logged only. {base_reason}")

    @staticmethod
    def apply_mode(enforced: Decision, mode: Mode) -> Decision:
        """Translate the ENFORCE-mode decision into the decision for ``mode``."""
        if mode == Mode.ENFORCE:
            return enforced
        if mode == Mode.MONITOR:
            return Decision.WARN if enforced in (Decision.BLOCK, Decision.SANITIZE) else enforced
        return Decision.ALLOW
