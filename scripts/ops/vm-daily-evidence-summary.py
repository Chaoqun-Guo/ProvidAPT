#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.vm_continuous_evidence_daily.v1"


def load_json(path_value: str) -> dict[str, Any]:
    if not path_value:
        return {}
    path = Path(path_value)
    if not path.exists() or path.stat().st_size == 0:
        return {}
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    return data if isinstance(data, dict) else {}


def section(name: str, path_value: str, label: str) -> dict[str, Any]:
    data = load_json(path_value)
    status = str(data.get("status") or "missing")
    return {
        "name": name,
        "label": label,
        "path": path_value,
        "status": status,
        "summary": data.get("summary") if isinstance(data.get("summary"), dict) else {},
        "hosts": data.get("hosts") if isinstance(data.get("hosts"), list) else [],
        "evidence_present": bool(data),
    }


def overall(sections: dict[str, dict[str, Any]]) -> str:
    statuses = [item["status"] for item in sections.values()]
    if any(status in {"blocked", "fail", "missing"} for status in statuses):
        return "blocked"
    if any(status in {"warn", "unknown", "skipped"} for status in statuses):
        return "warn"
    return "pass"


def next_actions(sections: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    actions: list[dict[str, str]] = []
    for name, item in sections.items():
        status = str(item["status"])
        if status == "pass":
            continue
        actions.append({
            "section": name,
            "status": status,
            "next_step": f"Regenerate {item['label']} evidence and rerun vm-daily-evidence-summary.",
        })
    return actions


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    sections = {
        "capture": section("capture", args.capture_gate, "capture field coverage"),
        "service_health": section("service_health", args.service_health, "service health"),
        "trace_svg_stress": section("trace_svg_stress", args.trace_svg_stress, "trace svg stress"),
        "dashboard_visual_baseline": section("dashboard_visual_baseline", args.visual_baseline, "dashboard visual baseline"),
        "disk_log_budget": section("disk_log_budget", args.disk_log_budget, "disk and log budget"),
    }
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": overall(sections),
        "sections": sections,
        "next_actions": next_actions(sections),
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT VM Continuous Evidence Daily Summary",
        "",
        f"- Status: `{report['status']}`",
        f"- Generated at: `{report['generated_at']}`",
        "",
        "| Section | Status | Evidence |",
        "| --- | --- | --- |",
    ]
    for name, item in report["sections"].items():
        lines.append(f"| {name} | `{item['status']}` | {item.get('path', '') or 'missing'} |")
    if report["next_actions"]:
        lines.extend(["", "## Next Actions", ""])
        lines.extend(f"- `{item['section']}`: {item['next_step']}" for item in report["next_actions"])
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate daily VM continuous evidence into a release-ready summary.")
    parser.add_argument("--capture-gate", default="")
    parser.add_argument("--service-health", default="")
    parser.add_argument("--trace-svg-stress", default="")
    parser.add_argument("--visual-baseline", default="")
    parser.add_argument("--disk-log-budget", default="")
    parser.add_argument("--out-json", default="build/vm-evidence/daily-summary.json")
    parser.add_argument("--out-md", default="build/vm-evidence/daily-summary.md")
    args = parser.parse_args()
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"vm daily evidence: status={report['status']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
