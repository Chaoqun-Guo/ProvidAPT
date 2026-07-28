#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.attack_coverage_plan.v1"

TECHNIQUE_GUIDANCE = {
    "T1059": ("Command and Scripting Interpreter", "Add safe shell/process execution simulation and command allow/deny rules."),
    "T1059.004": ("Unix Shell", "Exercise bash/sh child process chains with harmless echo, env, and temp-file operations."),
    "T1105": ("Ingress Tool Transfer", "Simulate localhost/documentation-host curl or wget download into a temp directory."),
    "T1041": ("Exfiltration Over C2 Channel", "Simulate local-only archive creation plus documentation-safe HTTP POST metadata."),
    "T1005": ("Data from Local System", "Simulate reads from temp files that mirror sensitive filename patterns without touching real secrets."),
    "T1083": ("File and Directory Discovery", "Simulate ls/find against temporary directories and verify discovery rules."),
    "T1036": ("Masquerading", "Create temporary benign binaries/scripts with deceptive names under the simulation workspace."),
}


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected JSON object")
    return data


def rows_from_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = report.get("missed_techniques")
    if not isinstance(rows, list):
        rows = []
        for key, value in (report.get("by_technique") or {}).items():
            if isinstance(value, dict) and int(value.get("missed", 0) or 0) > 0:
                value = dict(value)
                value["key"] = key
                rows.append(value)
    clean: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = str(row.get("key") or row.get("technique_id") or "").strip()
        if not key:
            continue
        clean.append({
            "technique_id": key,
            "total": int(row.get("total", 0) or 0),
            "detected": int(row.get("detected", 0) or 0),
            "missed": int(row.get("missed", 0) or 0),
            "recall_percent": float(row.get("recall_percent", 0) or 0),
        })
    return clean


def build_plan(report: dict[str, Any]) -> dict[str, Any]:
    tasks = []
    for row in rows_from_report(report):
        name, guidance = TECHNIQUE_GUIDANCE.get(row["technique_id"], ("Unmapped ATT&CK technique", "Add a safe simulation step, rule expectation, and ground-truth label."))
        priority = "high" if row["missed"] >= 3 or row["recall_percent"] == 0 else "medium"
        tasks.append({
            "technique_id": row["technique_id"],
            "technique_name": name,
            "priority": priority,
            "missed": row["missed"],
            "recall_percent": row["recall_percent"],
            "simulation_guidance": guidance,
            "required_outputs": [
                "ground_truth.jsonl step with run_id, step_id, tactic_id, technique_id",
                "expected_event and expected_relation",
                "rule or alert pattern assertion",
                "cleanup command that removes all temporary artifacts",
            ],
        })
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "source_schema": report.get("schema", ""),
        "status": "complete" if not tasks else "planned",
        "task_count": len(tasks),
        "tasks": sorted(tasks, key=lambda item: (item["priority"], -item["missed"], item["technique_id"])),
    }


def render_markdown(plan: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT ATT&CK Coverage Plan",
        "",
        f"- Status: `{plan['status']}`",
        f"- Tasks: `{plan['task_count']}`",
        "",
        "| Priority | Technique | Missed | Recall | Simulation Guidance |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for task in plan["tasks"]:
        lines.append(f"| {task['priority']} | {task['technique_id']} {task['technique_name']} | {task['missed']} | {task['recall_percent']}% | {task['simulation_guidance']} |")
    if not plan["tasks"]:
        lines.append("| none | coverage complete | 0 | 100% | No additional simulation gaps found. |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Plan safe ATT&CK simulation and rule work for missed techniques.")
    parser.add_argument("--detection-quality", required=True)
    parser.add_argument("--out-json", default="build/evaluation/attack-coverage-plan.json")
    parser.add_argument("--out-md", default="build/evaluation/attack-coverage-plan.md")
    args = parser.parse_args()
    plan = build_plan(load_json(Path(args.detection_quality)))
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(plan), encoding="utf-8")
    print(f"status={plan['status']} tasks={plan['task_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
