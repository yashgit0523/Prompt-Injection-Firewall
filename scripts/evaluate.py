"""PromptGuard security evaluation.

Runs the REAL detection engine over ``datasets/test_prompts.json`` and computes
confusion-matrix metrics. Nothing is hardcoded: change a rule and the numbers
change.

    python scripts/evaluate.py              # summary
    python scripts/evaluate.py --verbose    # every sample
    python scripts/evaluate.py --json out.json

Definitions
-----------
Positive  = the firewall did NOT simply allow the input (WARN, SANITIZE or BLOCK).
TP = malicious & flagged     FN = malicious & allowed
TN = benign & allowed        FP = benign & flagged

Samples with ``"source": "document"`` go through the document scanner
(UNTRUSTED_DOCUMENT provenance); all others are analysed as USER_INPUT.
The engine always runs in ENFORCE mode for evaluation.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config import Settings  # noqa: E402
from app.firewall.documents import DocumentScanner  # noqa: E402
from app.firewall.engine import FirewallEngine  # noqa: E402
from app.models.schemas import Decision, Mode, SourceType  # noqa: E402

DATASET = ROOT / "datasets" / "test_prompts.json"
LINE = "=" * 49


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def evaluate(dataset_path: Path) -> dict:
    samples = json.loads(dataset_path.read_text(encoding="utf-8"))
    settings = Settings(mode="ENFORCE", db_path=":memory:")
    engine = FirewallEngine(settings)
    scanner = DocumentScanner(engine)

    rows = []
    for sample in samples:
        if sample.get("source") == "document":
            scan = scanner.scan(sample["prompt"], "Summarize this document.", Mode.ENFORCE)
            decision, score, severity = scan.decision, scan.analysis.risk_score, scan.analysis.severity
            categories = scan.analysis.categories
        else:
            result = engine.analyze(sample["prompt"], SourceType.USER_INPUT, Mode.ENFORCE)
            decision, score, severity, categories = result.decision, result.risk_score, result.severity, result.categories
        flagged = decision != Decision.ALLOW
        rows.append({
            "id": sample["id"],
            "category": sample["category"],
            "malicious": sample["malicious"],
            "expected_decision": sample["expected_decision"],
            "decision": decision.value,
            "risk_score": score,
            "severity": severity.value,
            "detected_categories": [c.value for c in categories],
            "flagged": flagged,
            "correct": flagged == sample["malicious"],
            "exact_decision_match": decision.value == sample["expected_decision"],
            "prompt": sample["prompt"],
        })

    tp = sum(r["malicious"] and r["flagged"] for r in rows)
    tn = sum(not r["malicious"] and not r["flagged"] for r in rows)
    fp = sum(not r["malicious"] and r["flagged"] for r in rows)
    fn = sum(r["malicious"] and not r["flagged"] for r in rows)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)

    per_category: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "correct": 0})
    for r in rows:
        per_category[r["category"]]["total"] += 1
        per_category[r["category"]]["correct"] += int(r["correct"])

    return {
        "samples": len(rows),
        "malicious": sum(r["malicious"] for r in rows),
        "benign": sum(not r["malicious"] for r in rows),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": _ratio(tp + tn, len(rows)),
        "precision": precision,
        "recall": recall,
        "f1": _ratio(2 * precision * recall, precision + recall),
        "false_positive_rate": _ratio(fp, fp + tn),
        "false_negative_rate": _ratio(fn, fn + tp),
        "exact_decision_match": _ratio(sum(r["exact_decision_match"] for r in rows), len(rows)),
        "per_category": dict(per_category),
        "rows": rows,
    }


def print_report(report: dict, verbose: bool) -> None:
    print(LINE)
    print("PROMPTGUARD SECURITY EVALUATION")
    print(LINE)
    print(f"\nSamples: {report['samples']}  (malicious: {report['malicious']}, benign: {report['benign']})\n")
    print(f"TP: {report['tp']}")
    print(f"TN: {report['tn']}")
    print(f"FP: {report['fp']}")
    print(f"FN: {report['fn']}\n")
    print(f"Accuracy:             {report['accuracy']:.2%}")
    print(f"Precision:            {report['precision']:.2%}")
    print(f"Recall:               {report['recall']:.2%}")
    print(f"F1 Score:             {report['f1']:.2%}")
    print(f"False Positive Rate:  {report['false_positive_rate']:.2%}")
    print(f"False Negative Rate:  {report['false_negative_rate']:.2%}")
    print(f"Exact decision match: {report['exact_decision_match']:.2%}  (vs. expected_decision field)\n")

    print("Per-category correctness:")
    for category, stats in sorted(report["per_category"].items()):
        print(f"  {category:26s} {stats['correct']:3d}/{stats['total']:<3d}")

    errors = [r for r in report["rows"] if not r["correct"]]
    print(f"\nMisclassified samples ({len(errors)}):")
    for r in errors:
        kind = "FN (missed attack)" if r["malicious"] else "FP (benign flagged)"
        preview = r["prompt"].encode("unicode_escape").decode("ascii")[:90]
        print(f"  {r['id']:4s} {kind:20s} score={r['risk_score']:3d} decision={r['decision']:8s} {preview}")

    if verbose:
        print("\nAll samples:")
        for r in report["rows"]:
            mark = "OK " if r["correct"] else "ERR"
            print(f"  [{mark}] {r['id']:4s} {r['category']:26s} expected={r['expected_decision']:8s} "
                  f"got={r['decision']:8s} score={r['risk_score']:3d} {r['severity']}")
    print("\n" + LINE)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate PromptGuard on the labelled dataset.")
    parser.add_argument("--dataset", type=Path, default=DATASET)
    parser.add_argument("--verbose", action="store_true", help="print every sample")
    parser.add_argument("--json", type=Path, help="also write the full report as JSON")
    args = parser.parse_args()

    report = evaluate(args.dataset)
    print_report(report, args.verbose)
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Full report written to {args.json}")


if __name__ == "__main__":
    main()
