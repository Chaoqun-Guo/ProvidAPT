#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.scheduled_report_plan.v1"
FORMATS = {"json", "markdown", "html", "bundle"}
CADENCE_RE = re.compile(r"^(\d+)(h|d|w)$")


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def validate_plan(args: argparse.Namespace) -> dict[str, Any]:
    formats = split_csv(args.formats)
    recipients = split_csv(args.recipients)
    failures: list[str] = []
    warnings: list[str] = []
    unsupported = [item for item in formats if item not in FORMATS]
    if unsupported:
        failures.append("unsupported formats: " + ", ".join(unsupported))
    if not formats:
        failures.append("at least one report format is required")
    if not CADENCE_RE.match(args.cadence):
        failures.append("cadence must use Nh, Nd, or Nw syntax")
    if not recipients:
        warnings.append("no recipients configured; reports will be generated but not delivered")
    if args.retention_days < 1:
        failures.append("retention_days must be at least 1")
    if args.max_report_mb < 1:
        failures.append("max_report_mb must be at least 1")
    status = "pass" if not failures else "blocked"
    if status == "pass" and warnings:
        status = "warn"
    command = (
        f"providaptctl compliance generate-report --format {','.join(formats)} "
        f"--out-dir {args.out_dir} --retention-days {args.retention_days}"
    )
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "report_name": args.name,
        "cadence": args.cadence,
        "formats": formats,
        "recipients": recipients,
        "out_dir": args.out_dir,
        "retention_days": args.retention_days,
        "max_report_mb": args.max_report_mb,
        "command": command,
        "systemd": {
            "service": f"providapt-report-{args.name}.service",
            "timer": f"providapt-report-{args.name}.timer",
            "on_calendar": cadence_to_systemd(args.cadence),
        },
        "kubernetes": {
            "cron": cadence_to_cron(args.cadence),
            "job_name": f"providapt-report-{args.name}",
        },
        "failures": failures,
        "warnings": warnings,
    }


def cadence_to_systemd(cadence: str) -> str:
    match = CADENCE_RE.match(cadence)
    if not match:
        return ""
    count, unit = int(match.group(1)), match.group(2)
    if unit == "h":
        return f"*-*-* 00/{count}:00:00"
    if unit == "d":
        return "daily" if count == 1 else f"*-*-* 02:00:00 UTC/{count} days"
    return "weekly" if count == 1 else f"Mon 02:00:00 UTC/{count} weeks"


def cadence_to_cron(cadence: str) -> str:
    match = CADENCE_RE.match(cadence)
    if not match:
        return ""
    count, unit = int(match.group(1)), match.group(2)
    if unit == "h":
        return f"0 */{count} * * *"
    if unit == "d":
        return f"0 2 */{count} * *"
    return "0 2 * * 1" if count == 1 else f"0 2 * * 1/{count}"


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Scheduled Report Plan",
        "",
        f"- Status: `{report['status']}`",
        f"- Report: `{report['report_name']}`",
        f"- Cadence: `{report['cadence']}`",
        f"- Formats: `{', '.join(report['formats'])}`",
        f"- Recipients: `{', '.join(report['recipients']) or 'none'}`",
        f"- Retention: `{report['retention_days']} days`",
        f"- Max size: `{report['max_report_mb']} MB`",
        "",
        "## Execution",
        "",
        f"- Command: `{report['command']}`",
        f"- systemd service: `{report['systemd']['service']}`",
        f"- systemd timer: `{report['systemd']['timer']}`",
        f"- systemd OnCalendar: `{report['systemd']['on_calendar']}`",
        f"- Kubernetes CronJob schedule: `{report['kubernetes']['cron']}`",
        "",
    ]
    if report["failures"]:
        lines.extend(["## Failures", ""])
        lines.extend(f"- {item}" for item in report["failures"])
        lines.append("")
    if report["warnings"]:
        lines.extend(["## Warnings", ""])
        lines.extend(f"- {item}" for item in report["warnings"])
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a scheduled executive/compliance report delivery plan.")
    parser.add_argument("--name", default="compliance")
    parser.add_argument("--cadence", default="1w")
    parser.add_argument("--formats", default="markdown,json")
    parser.add_argument("--recipients", default="")
    parser.add_argument("--out-dir", default="/var/lib/providapt/reports")
    parser.add_argument("--retention-days", type=int, default=90)
    parser.add_argument("--max-report-mb", type=int, default=128)
    parser.add_argument("--out-json", default="build/reports/scheduled-report-plan.json")
    parser.add_argument("--out-md", default="build/reports/scheduled-report-plan.md")
    args = parser.parse_args()
    report = validate_plan(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} report={report['report_name']} cadence={report['cadence']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
