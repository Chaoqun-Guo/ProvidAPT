#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.open_source_evidence_summary.v1"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        return {}
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    return data if isinstance(data, dict) else {}


def status_value(report: dict[str, Any], allow_missing: bool) -> str:
    if not report:
        return "warn" if allow_missing else "blocked"
    status = str(report.get("status") or report.get("source_status") or "").lower()
    if status in {"pass", "ready"}:
        return "pass"
    if status in {"warn", "warning", "planned", "skipped"}:
        return "warn"
    return "blocked"


def evidence_row(name: str, path: Path, report: dict[str, Any], allow_missing: bool) -> dict[str, Any]:
    row: dict[str, Any] = {
        "name": name,
        "path": str(path),
        "present": bool(report),
        "status": status_value(report, allow_missing),
        "schema": report.get("schema", ""),
        "blockers": [],
        "warnings": [],
        "summary": {},
    }
    if not report:
        row["warnings" if allow_missing else "blockers"].append(f"{name} evidence is missing")
        return row
    if name == "open_source_milestone":
        row["summary"] = milestone_summary(report)
    elif name == "open_source_readiness_backlog":
        row["summary"] = backlog_summary(report)
    elif name == "visual_regression_gate":
        row["summary"] = visual_gate_summary(report)
    elif name == "trace_svg_stress":
        row["summary"] = trace_summary(report)
    elif name == "onboarding_manifest":
        row["summary"] = onboarding_summary(report)
    row["blockers"].extend(extract_blockers(name, report, row["summary"]))
    row["warnings"].extend(extract_warnings(name, report, row["summary"]))
    return row


def milestone_summary(report: dict[str, Any]) -> dict[str, Any]:
    evidence = report.get("evidence") if isinstance(report.get("evidence"), list) else []
    return {
        "evidence_count": len(evidence),
        "blocked_evidence": [item.get("name", "") for item in evidence if isinstance(item, dict) and item.get("status") == "blocked"],
        "warning_evidence": [item.get("name", "") for item in evidence if isinstance(item, dict) and item.get("status") == "warn"],
    }


def backlog_summary(report: dict[str, Any]) -> dict[str, Any]:
    checklist = report.get("checklist_summary") if isinstance(report.get("checklist_summary"), dict) else {}
    tasks = report.get("tasks") if isinstance(report.get("tasks"), list) else []
    return {
        "task_count": report.get("task_count", len(tasks)),
        "release_blocking_count": checklist.get("release_blocking_count", 0),
        "blocked_sections": list(checklist.get("blocked_sections") or []),
        "warning_sections": list(checklist.get("warning_sections") or []),
        "top_tasks": [str(item.get("id") or item.get("summary") or "") for item in tasks[:5] if isinstance(item, dict)],
    }


def visual_gate_summary(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("visual_evidence_summary") if isinstance(report.get("visual_evidence_summary"), dict) else {}
    required = summary.get("required_matrix") if isinstance(summary.get("required_matrix"), dict) else {}
    dom = summary.get("dom_assertions") if isinstance(summary.get("dom_assertions"), dict) else {}
    baseline = summary.get("baseline") if isinstance(summary.get("baseline"), dict) else {}
    return {
        "missing_required": required.get("missing_count", 0),
        "missing_by_page": required.get("missing_by_page") if isinstance(required.get("missing_by_page"), dict) else {},
        "dom_failed": dom.get("failed", 0),
        "dom_missing": dom.get("missing", 0),
        "baseline_status": baseline.get("status", ""),
        "baseline_changed": baseline.get("changed", 0),
    }


def trace_summary(report: dict[str, Any]) -> dict[str, Any]:
    results = report.get("results") if isinstance(report.get("results"), list) else []
    failures = report.get("failures") if isinstance(report.get("failures"), list) else []
    latencies = [float(item.get("latency_ms") or 0) for item in results if isinstance(item, dict)]
    failed_layouts = sorted({
        str(item.get("layout") or "")
        for item in results
        if isinstance(item, dict) and (int(item.get("http_status") or 0) != 200 or item.get("error"))
    })
    return {
        "result_count": len(results),
        "failure_count": len(failures),
        "max_latency_ms": max(latencies) if latencies else 0,
        "failed_layouts": [item for item in failed_layouts if item],
    }


def onboarding_summary(report: dict[str, Any]) -> dict[str, Any]:
    checks = report.get("check_summary") if isinstance(report.get("check_summary"), dict) else {}
    actions = report.get("action_summary") if isinstance(report.get("action_summary"), dict) else {}
    return {
        "check_summary": checks,
        "action_count": actions.get("action_count", len(report.get("next_actions") or [])),
        "blocked_checks": list(actions.get("blocked_checks") or []),
        "warning_checks": list(actions.get("warning_checks") or []),
        "unknown_checks": list(actions.get("unknown_checks") or []),
    }


def extract_blockers(name: str, report: dict[str, Any], summary: dict[str, Any]) -> list[str]:
    blockers = [str(item) for item in report.get("failures", []) if str(item).strip()]
    if name == "open_source_milestone":
        blockers.extend(f"milestone evidence blocked: {item}" for item in summary.get("blocked_evidence", []))
    if name == "open_source_readiness_backlog":
        blockers.extend(f"release-blocking section: {item}" for item in summary.get("blocked_sections", []))
    if name == "visual_regression_gate":
        if summary.get("missing_required", 0):
            blockers.append(f"visual matrix missing screenshots: {summary['missing_required']}")
        if summary.get("dom_failed", 0):
            blockers.append(f"visual DOM assertions failed: {summary['dom_failed']}")
    if name == "trace_svg_stress":
        blockers.extend(f"trace stress failed layout: {item}" for item in summary.get("failed_layouts", []))
    if name == "onboarding_manifest":
        blockers.extend(f"onboarding blocked check: {item}" for item in summary.get("blocked_checks", []))
    return blockers


def extract_warnings(name: str, report: dict[str, Any], summary: dict[str, Any]) -> list[str]:
    warnings = [str(item) for item in report.get("warnings", []) if str(item).strip()]
    if name == "open_source_milestone":
        warnings.extend(f"milestone evidence warning: {item}" for item in summary.get("warning_evidence", []))
    if name == "open_source_readiness_backlog":
        warnings.extend(f"warning section: {item}" for item in summary.get("warning_sections", []))
    if name == "visual_regression_gate" and summary.get("baseline_changed", 0):
        warnings.append(f"visual baseline changed screenshots: {summary['baseline_changed']}")
    if name == "onboarding_manifest":
        warnings.extend(f"onboarding warning check: {item}" for item in summary.get("warning_checks", []))
        warnings.extend(f"onboarding unknown check: {item}" for item in summary.get("unknown_checks", []))
    return warnings


def overall_status(rows: list[dict[str, Any]]) -> str:
    if any(row["status"] == "blocked" or row["blockers"] for row in rows):
        return "blocked"
    if any(row["status"] == "warn" or row["warnings"] for row in rows):
        return "warn"
    return "pass"


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    inputs = {
        "open_source_milestone": Path(args.open_source_milestone),
        "open_source_readiness_backlog": Path(args.open_source_readiness_backlog),
        "visual_regression_gate": Path(args.visual_regression_gate),
        "trace_svg_stress": Path(args.trace_svg_stress),
        "onboarding_manifest": Path(args.onboarding_manifest),
    }
    rows = [
        evidence_row(name, path, load_json(path), args.allow_missing)
        for name, path in inputs.items()
    ]
    blockers = [
        {"evidence": row["name"], "message": item}
        for row in rows
        for item in row["blockers"]
    ]
    warnings = [
        {"evidence": row["name"], "message": item}
        for row in rows
        for item in row["warnings"]
    ]
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": overall_status(rows),
        "allow_missing": args.allow_missing,
        "evidence": rows,
        "blocker_count": len(blockers),
        "warning_count": len(warnings),
        "blockers": blockers,
        "warnings": warnings,
        "next_commands": [
            "make open-source-milestone ALLOW_MISSING=1",
            "make open-source-evidence-summary ALLOW_MISSING=1",
            "make visual-regression-gate",
            "make trace-svg-stress PROVIDAPT_SERVER_URL=http://127.0.0.1:18080",
            "make onboarding-wizard CHECK_RESULTS=build/onboarding/check-results.json",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Open Source Evidence Summary",
        "",
        f"- Status: `{report['status']}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Allow missing evidence: `{str(report['allow_missing']).lower()}`",
        f"- Blockers: `{report['blocker_count']}`",
        f"- Warnings: `{report['warning_count']}`",
        "",
        "| Evidence | Status | Present | Blockers | Warnings | Path |",
        "| --- | --- | --- | ---: | ---: | --- |",
    ]
    for row in report["evidence"]:
        lines.append(
            f"| {row['name']} | {row['status']} | {str(row['present']).lower()} | "
            f"{len(row['blockers'])} | {len(row['warnings'])} | `{row['path']}` |"
        )
    if report["blockers"]:
        lines.extend(["", "## Blockers", ""])
        lines.extend(f"- `{item['evidence']}`: {item['message']}" for item in report["blockers"])
    if report["warnings"]:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- `{item['evidence']}`: {item['message']}" for item in report["warnings"])
    lines.extend(["", "## Evidence Details", ""])
    for row in report["evidence"]:
        lines.extend([f"### {row['name']}", ""])
        if row.get("summary"):
            lines.append("```json")
            lines.append(json.dumps(row["summary"], indent=2, sort_keys=True))
            lines.append("```")
        else:
            lines.append("_No detail available._")
        lines.append("")
    lines.extend(["## Next Commands", ""])
    lines.extend(f"- `{command}`" for command in report["next_commands"])
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a short release evidence executive summary from local open-source evidence.")
    parser.add_argument("--open-source-milestone", default="build/open-source-readiness/open-source-milestone.json")
    parser.add_argument("--open-source-readiness-backlog", default="build/open-source-readiness/open-source-readiness-backlog.json")
    parser.add_argument("--visual-regression-gate", default="build/visual-regression/visual-regression-gate.json")
    parser.add_argument("--trace-svg-stress", default="build/trace-stress/trace-svg-stress.json")
    parser.add_argument("--onboarding-manifest", default="build/onboarding/onboarding-manifest.json")
    parser.add_argument("--allow-missing", action="store_true")
    parser.add_argument("--out-json", default="build/open-source-readiness/open-source-evidence-summary.json")
    parser.add_argument("--out-md", default="build/open-source-readiness/open-source-evidence-summary.md")
    args = parser.parse_args()
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} blockers={report['blocker_count']} warnings={report['warning_count']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
