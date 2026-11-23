"""Explainable threat scoring (0-100).

The score is built from independent components, and every component that adds
points is listed in the ``score_breakdown`` with the reason it was added:

    Instruction Override            +40
    System Prompt Extraction        +40
    Multiple techniques combined    +10
    Heuristic: instruction_density  +10
                                    ----
    Threat score (capped at 100)     100

Scoring rules
-------------
* Pattern matches are grouped by attack category. A category contributes its
  strongest rule plus 50% of any additional rules in the same category
  (diminishing returns: ten weak matches should not equal ten strong ones).
* If the context analyser found that the attack phrases are *addressed to the
  assistant* ("your system prompt", "you must ..."), a ``directed_bonus`` is
  added - this is what separates performing an attack from mentioning one.
* Contextual dampening has already been applied to each match's
  ``effective_weight`` by the context analyser.
* Encoded payloads that decode to an attack add the decoded attack's weight
  plus an ``encoding_bonus`` - hiding an attack is itself evidence of intent.
* Unicode anomalies and heuristics are capped so they can raise suspicion but
  never dominate the score on their own.
* Severity floor: a non-dampened match of a HIGH-severity rule lifts the score
  to at least MEDIUM (WARN); a CRITICAL-severity rule lifts it to at least HIGH.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from app.config import Settings
from app.models.schemas import (
    CATEGORY_LABELS,
    Category,
    ContextAssessment,
    EncodingAnalysis,
    HeuristicResult,
    RuleMatch,
    ScoreComponent,
    Severity,
    SourceType,
    UnicodeAnalysis,
    UNTRUSTED_SOURCES,
)
from app.detection.patterns import INSTRUCTION_CATEGORIES


@dataclass
class ScoreResult:
    score: int
    severity: Severity
    categories: list[Category]
    breakdown: list[ScoreComponent] = field(default_factory=list)


def severity_for(score: int, settings: Settings) -> Severity:
    if score >= settings.threshold_critical:
        return Severity.CRITICAL
    if score >= settings.threshold_high:
        return Severity.HIGH
    if score >= settings.threshold_medium:
        return Severity.MEDIUM
    if score >= settings.threshold_low:
        return Severity.LOW
    return Severity.SAFE


def _category_points(matches: list[RuleMatch]) -> float:
    """Strongest rule counts fully; extra rules in the same category count half."""
    weights = sorted((m.effective_weight for m in matches), reverse=True)
    return weights[0] + 0.5 * sum(weights[1:]) if weights else 0.0


class ThreatScorer:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def score(
        self,
        rule_matches: list[RuleMatch],
        encoding: EncodingAnalysis,
        unicode: UnicodeAnalysis,
        hidden_text_matches: list[RuleMatch],
        heuristics: list[HeuristicResult],
        source: SourceType,
        context: ContextAssessment | None = None,
    ) -> ScoreResult:
        s = self.settings
        breakdown: list[ScoreComponent] = []
        categories: set[Category] = set()
        total = 0.0

        # 1) Direct pattern matches, grouped by category
        by_category: dict[Category, list[RuleMatch]] = defaultdict(list)
        for match in rule_matches:
            by_category[match.category].append(match)
        for category, matches in sorted(by_category.items(), key=lambda kv: -_category_points(kv[1])):
            points = _category_points(matches)
            if points <= 0:
                continue
            rule_ids = ", ".join(m.rule_id for m in matches)
            dampened = all(m.dampened for m in matches)
            reason = f"Matched {rule_ids}"
            if dampened:
                reason += " (weight reduced: discussed/quoted, not issued)"
            else:
                categories.add(category)
            breakdown.append(ScoreComponent(component=CATEGORY_LABELS[category.value], points=round(points), reason=reason))
            total += points

        # 1b) Attack phrases addressed directly to the assistant
        live_matches = [m for m in rule_matches if not m.dampened]
        if context and context.imperative_signals and live_matches:
            breakdown.append(ScoreComponent(
                component="Directed At Assistant", points=s.directed_bonus,
                reason="Commands target the assistant: " + "; ".join(context.imperative_signals[:2]),
            ))
            total += s.directed_bonus

        # 2) Encoded payloads that decode to an attack
        malicious_encodings = [f for f in encoding.findings if f.malicious]
        if malicious_encodings:
            best = max(malicious_encodings, key=lambda f: max(m.weight for m in f.rule_matches))
            decoded_points = _category_points(best.rule_matches)
            points = decoded_points + s.encoding_bonus
            categories.add(Category.ENCODED_INJECTION)
            categories.update(m.category for m in best.rule_matches)
            breakdown.append(ScoreComponent(
                component="Encoded Injection",
                points=round(points),
                reason=f"{' > '.join(best.chain)} payload decoded to an attack ({', '.join(m.rule_id for m in best.rule_matches)})",
            ))
            total += points
        if encoding.depth_limit_reached:
            breakdown.append(ScoreComponent(component="Decode Depth Limit", points=10,
                                            reason=f"Encoding nested deeper than MAX_DECODE_DEPTH={s.max_decode_depth}"))
            categories.add(Category.ENCODED_INJECTION)
            total += 10

        # 3) Unicode anomalies (capped) + hidden tag-character payloads
        if unicode.total_score:
            points = min(unicode.total_score, s.unicode_cap)
            kinds = ", ".join(f.kind for f in unicode.findings)
            breakdown.append(ScoreComponent(component="Unicode Anomaly", points=points, reason=f"Suspicious characters: {kinds}"))
            categories.add(Category.UNICODE_SMUGGLING)
            total += points
        if hidden_text_matches:
            points = _category_points(hidden_text_matches)
            categories.add(Category.UNICODE_SMUGGLING)
            categories.update(m.category for m in hidden_text_matches)
            breakdown.append(ScoreComponent(
                component="Hidden Unicode Payload", points=round(points),
                reason=f"Invisible tag characters spelled out an attack ({', '.join(m.rule_id for m in hidden_text_matches)})",
            ))
            total += points

        # 4) Indirect injection: instructions inside untrusted content
        attack_categories = {c for c in categories if c in INSTRUCTION_CATEGORIES}
        if source in UNTRUSTED_SOURCES and attack_categories:
            categories.add(Category.INDIRECT_INJECTION)
            breakdown.append(ScoreComponent(
                component="Indirect Injection", points=s.indirect_bonus,
                reason=f"Instructions found inside {source.value} (untrusted data should never give orders)",
            ))
            total += s.indirect_bonus

        # 5) Several distinct techniques combined
        if len(categories) >= 2:
            breakdown.append(ScoreComponent(component="Multiple Techniques", points=s.multi_category_bonus,
                                            reason=f"{len(categories)} attack categories combined"))
            total += s.multi_category_bonus

        # 6) Structural heuristics (capped)
        heuristic_points = sum(h.score for h in heuristics if h.score > 0)
        if heuristic_points:
            capped = min(heuristic_points, s.heuristic_cap)
            fired = ", ".join(h.name for h in heuristics if h.score > 0)
            reason = f"Heuristics fired: {fired}"
            if capped < heuristic_points:
                reason += f" (capped at {s.heuristic_cap})"
            breakdown.append(ScoreComponent(component="Structural Heuristics", points=capped, reason=reason))
            total += capped

        # 7) Severity floor: a clear (non-dampened) high-severity rule match is
        #    never waved through, however few other signals exist.
        #    HIGH rule -> at least MEDIUM, CRITICAL rule -> at least HIGH.
        floors = {Severity.HIGH: (s.threshold_medium, "MEDIUM"), Severity.CRITICAL: (s.threshold_high, "HIGH")}
        severe = [m for m in live_matches + hidden_text_matches if m.severity in floors]
        if severe:
            worst = max(severe, key=lambda m: floors[m.severity][0])
            floor, floor_name = floors[worst.severity]
            if total < floor:
                breakdown.append(ScoreComponent(
                    component="Severity Floor", points=round(floor - total),
                    reason=f"{worst.rule_id} is a {worst.severity.value}-severity rule; minimum risk is {floor_name}",
                ))
                total = floor

        score = max(0, min(100, round(total)))
        if score == 100 and total > 100:
            breakdown.append(ScoreComponent(component="Cap", points=100 - round(total), reason="Score is capped at 100"))
        return ScoreResult(
            score=score,
            severity=severity_for(score, s),
            categories=sorted(categories, key=lambda c: c.value),
            breakdown=breakdown,
        )
