#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.alert_quality_report.v1"
REVIEWED = {"true_positive", "false_positive", "benign", "duplicate"}


def iter_input_files(values: list[str]) -> list[Path]:
    files: list[Path] = []
    for value in values:
        path = Path(value)
        if path.is_dir():
            files.extend(sorted(path.glob("alerts*.ndjson")))
        elif path.is_file():
            files.append(path)
        else:
            raise SystemExit(f"input not found: {value}")
    if not files:
        raise SystemExit("no alert inputs found")
    return files


def load_alerts(paths: list[Path]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise SystemExit(f"{path}:{line_no}: invalid JSON: {exc}") from exc
                record.setdefault("source_file", str(path))
                alerts.append(record)
    return alerts


def details(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("details")
    return value if isinstance(value, dict) else {}


def field(record: dict[str, Any], *names: str, default: str = "") -> str:
    record_details = details(record)
    for name in names:
        value = record.get(name)
        if value not in (None, ""):
            return str(value)
        value = record_details.get(name)
        if value not in (None, ""):
            return str(value)
    return default


def classification(record: dict[str, Any]) -> str:
    value = field(record, "classification", default="")
    if value:
        return value.lower().strip()
    return "needs_review"


def alert_key(record: dict[str, Any]) -> str:
    return field(record, "id", "alert_id", "dedup_key", default=json.dumps(record, sort_keys=True))


def pct(numerator: int, denominator: int) -> float:
    return round((numerator / denominator * 100.0), 2) if denominator else 0.0


def build_report(alerts: list[dict[str, Any]], inputs: list[Path]) -> dict[str, Any]:
    unique: dict[str, dict[str, Any]] = {}
    for record in alerts:
        unique[alert_key(record)] = record
    records = list(unique.values())

    by_classification: Counter[str] = Counter()
    by_pattern: dict[str, Counter[str]] = defaultdict(Counter)
    by_severity: dict[str, Counter[str]] = defaultdict(Counter)
    for record in records:
        cls = classification(record)
        pattern = field(record, "pattern", "rule_id", default="unknown")
        severity = field(record, "severity", default="unknown").lower()
        by_classification[cls] += 1
        by_pattern[pattern][cls] += 1
        by_pattern[pattern]["total"] += 1
        by_severity[severity][cls] += 1
        by_severity[severity]["total"] += 1

    true_positive = by_classification["true_positive"]
    false_positive = by_classification["false_positive"] + by_classification["benign"]
    duplicate = by_classification["duplicate"]
    reviewed = sum(by_classification[key] for key in REVIEWED)
    total = len(records)

    recommendations = []
    for pattern, counts in sorted(by_pattern.items()):
        pattern_fp = counts["false_positive"] + counts["benign"]
        pattern_tp = counts["true_positive"]
        if counts["total"] >= 2 and pattern_fp > pattern_tp:
            recommendations.append({
                "pattern": pattern,
                "reason": "false positive annotations exceed true positives",
                "false_positive": pattern_fp,
                "true_positive": pattern_tp,
                "total": counts["total"],
            })

    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": [str(path) for path in inputs],
        "total_alerts": total,
        "reviewed_alerts": reviewed,
        "unreviewed_alerts": max(total - reviewed, 0),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "duplicate": duplicate,
        "review_coverage_percent": pct(reviewed, total),
        "actionable_precision_percent": pct(true_positive, true_positive + false_positive),
        "duplicate_percent": pct(duplicate, reviewed),
        "by_classification": dict(sorted(by_classification.items())),
        "by_pattern": {key: dict(value) for key, value in sorted(by_pattern.items())},
        "by_severity": {key: dict(value) for key, value in sorted(by_severity.items())},
        "recommendations": recommendations,
    }


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# Alert Quality Report",
        "",
        f"- Generated at: `{report['generated_at']}`",
        f"- Total alerts: `{report['total_alerts']}`",
        f"- Reviewed alerts: `{report['reviewed_alerts']}`",
        f"- Review coverage: `{report['review_coverage_percent']}%`",
        f"- Actionable precision: `{report['actionable_precision_percent']}%`",
        "",
        "## By Classification",
        "",
        "| Classification | Count |",
        "| --- | ---: |",
    ]
    for cls, count in report["by_classification"].items():
        lines.append(f"| `{cls}` | {count} |")
    lines.extend(["", "## By Pattern", "", "| Pattern | Total | TP | FP/Benign | Duplicate | Needs Review |", "| --- | ---: | ---: | ---: | ---: | ---: |"])
    for pattern, row in report["by_pattern"].items():
        fp = row.get("false_positive", 0) + row.get("benign", 0)
        lines.append(
            f"| `{pattern}` | {row.get('total', 0)} | {row.get('true_positive', 0)} | "
            f"{fp} | {row.get('duplicate', 0)} | {row.get('needs_review', 0)} |"
        )
    lines.extend(["", "## Recommendations", ""])
    if report["recommendations"]:
        for item in report["recommendations"]:
            lines.append(f"- Review `{item['pattern']}`: {item['reason']} ({item['false_positive']} FP/benign vs {item['true_positive']} TP).")
    else:
        lines.append("- No high false-positive pattern candidates found.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate alert quality metrics from annotated ProvidAPT alert workflow records.")
    parser.add_argument("inputs", nargs="+", help="alerts.ndjson file, alerts archive, or directory")
    parser.add_argument("--out-json", default="build/evaluation/alert-quality.json")
    parser.add_argument("--out-md", default="build/evaluation/alert-quality.md")
    args = parser.parse_args()

    files = iter_input_files(args.inputs)
    report = build_report(load_alerts(files), files)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(out_md, report)
    print(
        "alerts={total} reviewed={reviewed} precision={precision}% out_json={out_json} out_md={out_md}".format(
            total=report["total_alerts"],
            reviewed=report["reviewed_alerts"],
            precision=report["actionable_precision_percent"],
            out_json=out_json,
            out_md=out_md,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
