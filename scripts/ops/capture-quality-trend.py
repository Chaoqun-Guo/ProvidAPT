#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.capture_quality_trend.v1"


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"failed to load {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"expected JSON object in {path}")
    return data


def input_hosts(report: dict[str, Any]) -> list[str]:
    hosts: set[str] = set()
    for value in report.get("inputs") or []:
        path = Path(str(value))
        for part in path.parts:
            if part.startswith("vm-") or part.startswith("host-"):
                hosts.add(part)
    return sorted(hosts)


def rate(report: dict[str, Any], key: str) -> float:
    rates = ((report.get("summary") or {}).get("field_rates") or {})
    try:
        return float(rates.get(key) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def scenario_count(report: dict[str, Any], key: str) -> int:
    counts = ((report.get("summary") or {}).get("scenario_counts") or {})
    try:
        return int(counts.get(key) or 0)
    except (TypeError, ValueError):
        return 0


def build_report(paths: list[Path]) -> dict[str, Any]:
    runs: list[dict[str, Any]] = []
    all_hosts: set[str] = set()
    field_names: set[str] = set()
    scenario_names: set[str] = set()
    for path in paths:
        report = load_json(path)
        summary = report.get("summary") or {}
        rates = summary.get("field_rates") or {}
        scenarios = summary.get("scenario_counts") or {}
        field_names.update(str(name) for name in rates)
        scenario_names.update(str(name) for name in scenarios)
        hosts = input_hosts(report)
        all_hosts.update(hosts)
        runs.append({
            "path": str(path),
            "generated_at": report.get("generated_at", ""),
            "status": report.get("status", ""),
            "event_count": int(summary.get("event_count") or 0),
            "file_event_count": int(summary.get("file_event_count") or 0),
            "network_event_count": int(summary.get("network_event_count") or 0),
            "hosts": hosts,
            "field_rates": rates,
            "scenario_counts": scenarios,
            "warnings": report.get("warnings") or [],
            "failures": report.get("failures") or [],
        })
    field_trends = {}
    for name in sorted(field_names):
        values = []
        for run in runs:
            try:
                values.append(float((run.get("field_rates") or {}).get(name) or 0.0))
            except (TypeError, ValueError):
                values.append(0.0)
        field_trends[name] = {
            "first": values[0] if values else 0.0,
            "last": values[-1] if values else 0.0,
            "delta": round((values[-1] - values[0]) if values else 0.0, 2),
            "min": min(values) if values else 0.0,
            "max": max(values) if values else 0.0,
        }
    scenario_totals = {
        name: sum(int((run.get("scenario_counts") or {}).get(name) or 0) for run in runs)
        for name in sorted(scenario_names)
    }
    total_events = sum(run["event_count"] for run in runs)
    status = "pass"
    blockers: list[str] = []
    if not runs:
        status = "blocked"
        blockers.append("no capture gate reports supplied")
    if any(run["status"] == "blocked" for run in runs):
        status = "blocked"
        blockers.append("one or more capture gate runs are blocked")
    missing_scenarios = [name for name in ("shell_activity", "file_activity", "network_activity", "process_chain") if scenario_totals.get(name, 0) == 0]
    if missing_scenarios:
        status = "warn" if status == "pass" else status
        blockers.append("missing scenario evidence: " + ", ".join(missing_scenarios))
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "run_count": len(runs),
        "total_events": total_events,
        "hosts": sorted(all_hosts),
        "runs": runs,
        "field_trends": field_trends,
        "scenario_totals": scenario_totals,
        "blockers": blockers,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Capture Quality Trend Report",
        "",
        f"- Status: `{report['status']}`",
        f"- Runs: `{report['run_count']}`",
        f"- Events: `{report['total_events']}`",
        f"- Hosts: `{', '.join(report['hosts']) if report['hosts'] else 'not inferred'}`",
        "",
        "## Field Trends",
        "",
        "| Field | First | Last | Delta | Min | Max |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, item in sorted(report["field_trends"].items()):
        lines.append(f"| {name} | {item['first']}% | {item['last']}% | {item['delta']} | {item['min']}% | {item['max']}% |")
    lines.extend(["", "## Scenario Totals", "", "| Scenario | Events |", "| --- | ---: |"])
    for name, value in sorted(report["scenario_totals"].items()):
        lines.append(f"| {name} | {value} |")
    if report["blockers"]:
        lines.extend(["", "## Follow Up", ""])
        lines.extend(f"- {item}" for item in report["blockers"])
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Aggregate capture enrichment field gate reports into a quality trend.")
    parser.add_argument("--gate-report", action="append", required=True, help="capture-enrichment-field-gate JSON report")
    parser.add_argument("--out-json", default="build/capture-quality/capture-quality-trend.json")
    parser.add_argument("--out-md", default="build/capture-quality/capture-quality-trend.md")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = build_report([Path(value) for value in args.gate_report])
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"capture quality trend: status={report['status']} runs={report['run_count']} events={report['total_events']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
