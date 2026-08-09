#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.detection_quality_report.v1"


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected JSON object")
    return data


def pct(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def f1_score(precision: float, recall: float) -> float:
    if precision <= 0 or recall <= 0:
        return 0.0
    return round(2 * precision * recall / (precision + recall), 2)


def coverage_rows(section: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key, value in sorted(section.items()):
        if not isinstance(value, dict):
            continue
        total = int(value.get("total") or value.get("malicious") or 0)
        detected = int(value.get("detected") or 0)
        missed = int(value.get("missed") or max(total - detected, 0))
        rows.append({
            "key": key,
            "total": total,
            "detected": detected,
            "missed": missed,
            "recall_percent": round(detected * 100.0 / total, 2) if total else 0.0,
        })
    return rows


def build_report(coverage: dict[str, Any], alert_quality: dict[str, Any]) -> dict[str, Any]:
    recall = pct(coverage.get("coverage_percent"))
    precision = pct(alert_quality.get("actionable_precision_percent"))
    reviewed = pct(alert_quality.get("review_coverage_percent"))
    tactic_rows = coverage_rows(coverage.get("by_tactic", {}))
    technique_rows = coverage_rows(coverage.get("by_technique", {}))
    missed_tactics = [row for row in tactic_rows if row["missed"] > 0]
    missed_techniques = [row for row in technique_rows if row["missed"] > 0]
    feedback = alert_quality.get("feedback") if isinstance(alert_quality.get("feedback"), dict) else {}
    feedback_entries = int(feedback.get("feedback_entries") or 0)
    feedback_matched = int(feedback.get("feedback_matched_alerts") or 0)
    feedback_unmatched = int(feedback.get("feedback_unmatched_alerts") or 0)
    recommendations = []
    if reviewed < 80:
        recommendations.append("Increase analyst review coverage before using alert precision as release evidence.")
    if feedback_entries == 0:
        recommendations.append("Attach analyst feedback ledger to make precision evidence auditable.")
    elif feedback_unmatched > 0:
        recommendations.append("Review unmatched alert feedback entries so the quality report covers the latest analyst decisions.")
    if recall < 80:
        recommendations.append("Add or tune rules for missed ATT&CK techniques before expanding detector training.")
    if precision < 70:
        recommendations.append("Prioritize noisy alert patterns with low analyst-confirmed precision.")
    if missed_techniques:
        recommendations.append("Review missed techniques: " + ", ".join(row["key"] for row in missed_techniques[:8]))
    if not recommendations:
        recommendations.append("Detection quality is within the configured open-source readiness targets.")
    status = "pass" if recall >= 80 and precision >= 70 and reviewed >= 80 else "review_required"
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "recall_percent": recall,
        "precision_percent": precision,
        "f1_percent": f1_score(precision, recall),
        "review_coverage_percent": reviewed,
        "coverage_source": coverage.get("schema", ""),
        "alert_quality_source": alert_quality.get("schema", ""),
        "feedback": {
            "entries": feedback_entries,
            "matched_alerts": feedback_matched,
            "unmatched_alerts": feedback_unmatched,
            "by_classification": feedback.get("feedback_by_classification", {}),
        },
        "by_tactic": tactic_rows,
        "by_technique": technique_rows,
        "missed_tactics": missed_tactics,
        "missed_techniques": missed_techniques,
        "recommendations": recommendations,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Detection Quality Report",
        "",
        f"- Status: `{report['status']}`",
        f"- Precision: `{report['precision_percent']}%`",
        f"- Recall: `{report['recall_percent']}%`",
        f"- F1: `{report['f1_percent']}%`",
        f"- Review coverage: `{report['review_coverage_percent']}%`",
        f"- Feedback entries: `{report['feedback']['entries']}`",
        f"- Feedback matched alerts: `{report['feedback']['matched_alerts']}`",
        "",
        "## Missed Techniques",
        "",
        "| Technique | Total | Detected | Missed | Recall |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for row in report["missed_techniques"]:
        lines.append(f"| {row['key']} | {row['total']} | {row['detected']} | {row['missed']} | {row['recall_percent']}% |")
    if not report["missed_techniques"]:
        lines.append("| none | 0 | 0 | 0 | 100% |")
    lines.extend(["", "## Recommendations", ""])
    lines.extend(f"- {item}" for item in report["recommendations"])
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge ATT&CK coverage and alert quality into precision/recall release evidence.")
    parser.add_argument("--coverage", required=True)
    parser.add_argument("--alert-quality", required=True)
    parser.add_argument("--out-json", default="build/evaluation/detection-quality.json")
    parser.add_argument("--out-md", default="build/evaluation/detection-quality.md")
    args = parser.parse_args()
    report = build_report(load_json(Path(args.coverage)), load_json(Path(args.alert_quality)))
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} precision={report['precision_percent']} recall={report['recall_percent']} f1={report['f1_percent']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
