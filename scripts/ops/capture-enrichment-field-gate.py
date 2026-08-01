#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.capture_enrichment_field_gate.v1"
FILE_EVENT_HINTS = ("file", "open", "read", "write", "unlink", "rename", "chmod", "chown")
NETWORK_EVENT_HINTS = ("net", "socket", "connect", "accept", "send", "recv")


def iter_event_files(values: list[str]) -> list[Path]:
    files: list[Path] = []
    for value in values:
        path = Path(value)
        if path.is_dir():
            files.extend(sorted(path.rglob("*.ndjson")))
            files.extend(sorted(path.rglob("*.jsonl")))
        elif path.exists():
            files.append(path)
        else:
            raise SystemExit(f"event input not found: {value}")
    return sorted(dict.fromkeys(files))


def load_events(paths: list[Path]) -> tuple[list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    failures: list[str] = []
    for path in paths:
        for line_number, line in enumerate(path.read_text(encoding="utf-8-sig", errors="replace").splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                item = json.loads(stripped)
            except json.JSONDecodeError as exc:
                failures.append(f"{path}:{line_number}: invalid JSON: {exc}")
                continue
            if isinstance(item, dict):
                events.append(item)
            else:
                failures.append(f"{path}:{line_number}: expected JSON object")
    return events, failures


def nested(record: dict[str, Any], path: str) -> Any:
    value: Any = record
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def first_value(record: dict[str, Any], paths: tuple[str, ...]) -> Any:
    for path in paths:
        value = nested(record, path)
        if value not in (None, "", [], {}):
            return value
    return None


def has_field(record: dict[str, Any], paths: tuple[str, ...]) -> bool:
    return first_value(record, paths) is not None


def event_type(record: dict[str, Any]) -> str:
    return str(first_value(record, ("type", "event_type", "event.type", "payload.event_type")) or "")


def is_file_event(record: dict[str, Any]) -> bool:
    typ = event_type(record).lower()
    return any(hint in typ for hint in FILE_EVENT_HINTS) or has_field(record, ("payload.pathname", "pathname", "file.path"))


def is_network_event(record: dict[str, Any]) -> bool:
    typ = event_type(record).lower()
    return any(hint in typ for hint in NETWORK_EVENT_HINTS) or has_field(record, ("network.src_ip", "payload.src_ip", "src_ip", "payload.dst_ip", "dst_ip"))


def pct(numerator: int, denominator: int) -> float:
    return round(numerator * 100.0 / denominator, 2) if denominator else 0.0


def field_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(events)
    file_events = [event for event in events if is_file_event(event)]
    network_events = [event for event in events if is_network_event(event)]
    checks = {
        "event_type": sum(has_field(event, ("type", "event_type", "event.type")) for event in events),
        "pid": sum(has_field(event, ("process.pid", "pid")) for event in events),
        "ppid": sum(has_field(event, ("process.ppid", "ppid", "payload.parent_pid")) for event in events),
        "uid": sum(has_field(event, ("process.uid", "uid")) for event in events),
        "gid": sum(has_field(event, ("process.gid", "gid")) for event in events),
        "cmdline": sum(has_field(event, ("process.cmdline", "payload.cmdline", "cmdline", "enrich.cmdline")) for event in events),
        "exe_path": sum(has_field(event, ("process.exe_path", "payload.exe_path", "exe_path", "enrich.exe_path")) for event in events),
        "pathname": sum(has_field(event, ("payload.pathname", "pathname", "file.path")) for event in file_events),
        "network_tuple": sum(
            has_field(event, ("network.src_ip", "payload.src_ip", "src_ip", "network.source.ip"))
            and has_field(event, ("network.dst_ip", "payload.dst_ip", "dst_ip", "network.destination.ip"))
            and has_field(event, ("network.dst_port", "payload.dst_port", "dst_port", "network.destination.port"))
            for event in network_events
        ),
    }
    event_types = Counter(event_type(event) or "unknown" for event in events)
    return {
        "event_count": total,
        "file_event_count": len(file_events),
        "network_event_count": len(network_events),
        "field_counts": checks,
        "field_rates": {
            "event_type_percent": pct(checks["event_type"], total),
            "pid_percent": pct(checks["pid"], total),
            "ppid_percent": pct(checks["ppid"], total),
            "uid_percent": pct(checks["uid"], total),
            "gid_percent": pct(checks["gid"], total),
            "cmdline_percent": pct(checks["cmdline"], total),
            "exe_path_percent": pct(checks["exe_path"], total),
            "pathname_percent": pct(checks["pathname"], len(file_events)),
            "network_tuple_percent": pct(checks["network_tuple"], len(network_events)),
        },
        "event_type_summary": dict(sorted(event_types.items())),
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    files = iter_event_files(args.events)
    events, failures = load_events(files)
    warnings: list[str] = []
    summary = field_summary(events)
    rates = summary["field_rates"]
    if summary["event_count"] < args.min_events:
        failures.append(f"event count {summary['event_count']} below {args.min_events}")
    required_thresholds = {
        "event_type_percent": args.min_event_type_rate,
        "pid_percent": args.min_pid_rate,
        "ppid_percent": args.min_ppid_rate,
        "uid_percent": args.min_uid_rate,
        "gid_percent": args.min_gid_rate,
        "cmdline_percent": args.min_cmdline_rate,
        "exe_path_percent": args.min_exe_path_rate,
        "pathname_percent": args.min_pathname_rate,
        "network_tuple_percent": args.min_network_tuple_rate,
    }
    for name, threshold in required_thresholds.items():
        observed = float(rates.get(name) or 0.0)
        if observed < threshold:
            failures.append(f"{name} {observed}% below {threshold}%")
    if summary["file_event_count"] == 0:
        warnings.append("no file events found; pathname coverage could not exercise file capture")
    if summary["network_event_count"] == 0:
        warnings.append("no network events found; network tuple coverage could not exercise network capture")
    status = "blocked" if failures else "warn" if warnings else "pass"
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "inputs": [str(path) for path in files],
        "summary": summary,
        "thresholds": required_thresholds | {"min_events": args.min_events},
        "failures": failures,
        "warnings": warnings,
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    rates = summary["field_rates"]
    lines = [
        "# Capture Enrichment Field Gate",
        "",
        f"- Status: `{report['status']}`",
        f"- Events: `{summary['event_count']}`",
        f"- File events: `{summary['file_event_count']}`",
        f"- Network events: `{summary['network_event_count']}`",
        "",
        "| Field | Coverage |",
        "| --- | ---: |",
    ]
    for name, value in sorted(rates.items()):
        lines.append(f"| {name} | {value}% |")
    if report["failures"]:
        lines.extend(["", "## Failures", ""])
        lines.extend(f"- {item}" for item in report["failures"])
    if report["warnings"]:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {item}" for item in report["warnings"])
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Gate captured event enrichment fields for evaluation and ML readiness.")
    parser.add_argument("--events", action="append", required=True, help="NDJSON/JSONL event file or directory")
    parser.add_argument("--min-events", type=int, default=1)
    parser.add_argument("--min-event-type-rate", type=float, default=100.0)
    parser.add_argument("--min-pid-rate", type=float, default=95.0)
    parser.add_argument("--min-ppid-rate", type=float, default=80.0)
    parser.add_argument("--min-uid-rate", type=float, default=95.0)
    parser.add_argument("--min-gid-rate", type=float, default=95.0)
    parser.add_argument("--min-cmdline-rate", type=float, default=10.0)
    parser.add_argument("--min-exe-path-rate", type=float, default=10.0)
    parser.add_argument("--min-pathname-rate", type=float, default=80.0)
    parser.add_argument("--min-network-tuple-rate", type=float, default=80.0)
    parser.add_argument("--out-json", default="build/capture-quality/capture-enrichment-field-gate.json")
    parser.add_argument("--out-md", default="build/capture-quality/capture-enrichment-field-gate.md")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"capture enrichment field gate: status={report['status']} events={report['summary']['event_count']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
