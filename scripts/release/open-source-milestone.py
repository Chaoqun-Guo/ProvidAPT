#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.open_source_milestone.v1"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        return {}
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    return data if isinstance(data, dict) else {}


def status_value(report: dict[str, Any], allow_missing: bool) -> str:
    if not report:
        return "warn" if allow_missing else "blocked"
    if "task_count" in report and not report.get("status") and not report.get("source_status"):
        return "pass"
    status = str(report.get("status") or report.get("source_status") or "").lower()
    if status in {"pass", "planned"}:
        return "pass" if status == "pass" else "warn"
    if status in {"warn", "warning", "skipped"}:
        return "warn"
    return "blocked"


def model_lifecycle_detail(report: dict[str, Any]) -> dict[str, Any]:
    packet = report.get("promotion_packet") if isinstance(report.get("promotion_packet"), dict) else {}
    summary = packet.get("readiness_summary") if isinstance(packet.get("readiness_summary"), dict) else {}
    feedback = summary.get("feedback") if isinstance(summary.get("feedback"), dict) else {}
    evidence = summary.get("evidence") if isinstance(summary.get("evidence"), dict) else {}
    model = summary.get("model") if isinstance(summary.get("model"), dict) else report.get("model", {})
    return {
        "promotion_decision": summary.get("decision") or packet.get("decision") or report.get("promotion_decision", ""),
        "model": {
            "name": str((model or {}).get("name") or ""),
            "version": str((model or {}).get("version") or ""),
        },
        "drift_status": summary.get("drift_status") or report.get("drift_status", ""),
        "baseline_days": summary.get("baseline_days", report.get("baseline_days", 0)),
        "feedback_records": feedback.get("records", report.get("feedback_records", 0)),
        "reviewed_labels": feedback.get("reviewed", report.get("reviewed_labels", 0)),
        "feedback_labels": feedback.get("labels", report.get("feedback_labels", {})),
        "blocker_count": summary.get("blocker_count", len(report.get("failures", []))),
        "warning_count": summary.get("warning_count", len(report.get("warnings", []))),
        "missing_evidence": evidence.get("missing", []),
        "present_evidence": evidence.get("present", []),
    }


def visual_regression_detail(report: dict[str, Any]) -> dict[str, Any]:
    coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else {}
    comparison = report.get("comparison_summary") if isinstance(report.get("comparison_summary"), dict) else {}
    counts = comparison.get("counts") if isinstance(comparison.get("counts"), dict) else {}
    screenshots = report.get("screenshots") if isinstance(report.get("screenshots"), list) else []
    dom_total = 0
    dom_failed = 0
    page_status: dict[str, dict[str, int]] = {}
    for shot in screenshots:
        if not isinstance(shot, dict):
            continue
        page = str(shot.get("page") or "unknown")
        status = str(shot.get("status") or "unknown")
        page_status.setdefault(page, {})
        page_status[page][status] = page_status[page].get(status, 0) + 1
        dom = shot.get("dom_assertions") if isinstance(shot.get("dom_assertions"), dict) else {}
        if dom:
            dom_total += 1
            if str(dom.get("status") or "").lower() != "pass":
                dom_failed += 1
    return {
        "status": str(report.get("status") or ""),
        "complete_default_matrix": bool(coverage.get("complete_default_matrix")),
        "covered_count": coverage.get("covered_count", 0),
        "screenshot_count": coverage.get("screenshot_count", len(screenshots)),
        "viewport_classes": list(coverage.get("viewport_classes") or []),
        "missing_pages": list(coverage.get("missing_pages") or []),
        "missing_default_viewports": list(coverage.get("missing_default_viewports") or []),
        "comparison_status": comparison.get("status", ""),
        "comparison_counts": counts,
        "changed_count": counts.get("changed", 0),
        "new_count": counts.get("new", 0),
        "skipped_count": counts.get("skipped", 0),
        "missing_baseline_count": counts.get("missing_baseline", 0),
        "dom_assertions": {"total": dom_total, "failed": dom_failed},
        "page_status": dict(sorted(page_status.items())),
    }


def trace_svg_stress_detail(report: dict[str, Any]) -> dict[str, Any]:
    results = report.get("results") if isinstance(report.get("results"), list) else []
    failures = report.get("failures") if isinstance(report.get("failures"), list) else []
    latencies = [
        float(item.get("latency_ms") or 0)
        for item in results
        if isinstance(item, dict) and item.get("latency_ms") is not None
    ]
    node_counts = [
        int(item.get("node_count") or 0)
        for item in results
        if isinstance(item, dict) and item.get("node_count") is not None
    ]
    edge_counts = [
        int(item.get("edge_count") or 0)
        for item in results
        if isinstance(item, dict) and item.get("edge_count") is not None
    ]
    by_layout: dict[str, dict[str, int]] = {}
    by_alert: dict[str, int] = {}
    failed_layouts: list[str] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        layout = str(item.get("layout") or "unknown")
        alert_id = str(item.get("alert_id") or "unknown")
        status = "pass" if int(item.get("http_status") or 0) == 200 and not item.get("error") else "blocked"
        by_layout.setdefault(layout, {"pass": 0, "blocked": 0})
        by_layout[layout][status] = by_layout[layout].get(status, 0) + 1
        by_alert[alert_id] = by_alert.get(alert_id, 0) + 1
        if status != "pass" and layout not in failed_layouts:
            failed_layouts.append(layout)
    return {
        "status": str(report.get("status") or ""),
        "alert_source": str(report.get("alert_source") or ""),
        "alert_count": len(report.get("alert_ids") or []),
        "layout_count": len(report.get("layouts") or []),
        "result_count": len(results),
        "failure_count": len(failures),
        "max_latency_ms": max(latencies) if latencies else 0,
        "min_node_count": min(node_counts) if node_counts else 0,
        "max_node_count": max(node_counts) if node_counts else 0,
        "max_edge_count": max(edge_counts) if edge_counts else 0,
        "by_layout": dict(sorted(by_layout.items())),
        "by_alert": dict(sorted(by_alert.items())),
        "failed_layouts": sorted(failed_layouts),
        "thresholds": report.get("thresholds") if isinstance(report.get("thresholds"), dict) else {},
        "failures": [str(item) for item in failures[:10]],
    }


def development_backlog_detail(report: dict[str, Any]) -> dict[str, Any]:
    tasks = report.get("tasks") if isinstance(report.get("tasks"), list) else []
    by_status = report.get("by_status") if isinstance(report.get("by_status"), dict) else {}
    by_evidence_status = report.get("by_evidence_status") if isinstance(report.get("by_evidence_status"), dict) else {}
    planning = report.get("planning_summary") if isinstance(report.get("planning_summary"), dict) else {}
    grouped: dict[str, list[str]] = {
        "needs_fix": [],
        "needs_review": [],
        "needs_evidence": [],
        "blocked_external": [],
        "missing": [],
        "done": [],
    }
    for task in tasks:
        if not isinstance(task, dict):
            continue
        status = str(task.get("status") or "")
        task_id = str(task.get("id") or "")
        if status in grouped and task_id:
            grouped[status].append(task_id)
        if task.get("evidence_status") == "missing" and task_id:
            grouped["missing"].append(task_id)
    remaining = sorted(set(grouped["needs_fix"] + grouped["needs_review"] + grouped["needs_evidence"] + grouped["blocked_external"] + grouped["missing"]))
    return {
        "task_count": report.get("task_count", len(tasks)),
        "evidence_aware": bool((report.get("filters") or {}).get("evidence_aware")) if isinstance(report.get("filters"), dict) else False,
        "by_status": by_status,
        "by_evidence_status": by_evidence_status,
        "done": sorted(set(grouped["done"])),
        "needs_fix": sorted(set(grouped["needs_fix"])),
        "needs_review": sorted(set(grouped["needs_review"])),
        "needs_evidence": sorted(set(grouped["needs_evidence"])),
        "blocked_external": sorted(set(grouped["blocked_external"])),
        "missing_evidence": sorted(set(grouped["missing"])),
        "remaining": remaining,
        "remaining_count": len(remaining),
        "planning_summary": {
            "remaining_count": planning.get("remaining_count", len(remaining)),
            "next_local_tasks": list(planning.get("next_local_tasks") or []),
            "next_local_count": planning.get("next_local_count", 0),
            "external_blockers": list(planning.get("external_blockers") or []),
            "external_blocker_count": planning.get("external_blocker_count", 0),
            "by_evidence_key": planning.get("by_evidence_key") if isinstance(planning.get("by_evidence_key"), dict) else {},
        },
    }


def evidence_summary(name: str, path: Path, report: dict[str, Any], allow_missing: bool) -> dict[str, Any]:
    status = status_value(report, allow_missing)
    row: dict[str, Any] = {
        "name": name,
        "path": str(path),
        "present": bool(report),
        "status": status,
        "schema": report.get("schema", ""),
    }
    if "task_count" in report:
        row["task_count"] = report.get("task_count", 0)
    if "sections" in report and isinstance(report.get("sections"), dict):
        sections = report["sections"]
        row["section_count"] = len(sections)
        row["blocked_sections"] = sorted(
            key for key, value in sections.items()
            if isinstance(value, dict) and str(value.get("status") or "").lower() == "blocked"
        )
        row["warning_sections"] = sorted(
            key for key, value in sections.items()
            if isinstance(value, dict) and str(value.get("status") or "").lower() in {"warn", "warning"}
        )
    if name == "model_lifecycle" and report:
        row["model_lifecycle"] = model_lifecycle_detail(report)
    if name == "visual_regression_snapshots" and report:
        row["visual_regression"] = visual_regression_detail(report)
    if name == "trace_svg_stress" and report:
        row["trace_svg_stress"] = trace_svg_stress_detail(report)
    if name == "open_source_development_backlog" and report:
        row["development_backlog"] = development_backlog_detail(report)
    return row


def overall_status(evidence: list[dict[str, Any]]) -> str:
    statuses = [item["status"] for item in evidence]
    if any(status == "blocked" for status in statuses):
        return "blocked"
    if any(status == "warn" for status in statuses):
        return "warn"
    return "pass"


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    inputs = {
        "open_source_readiness": Path(args.open_source_readiness_gate),
        "open_source_readiness_backlog": Path(args.open_source_readiness_backlog),
        "open_source_development_backlog": Path(args.open_source_development_backlog),
        "release_gate_status": Path(args.release_gates),
        "release_evidence_consistency": Path(args.release_evidence_consistency_gate),
        "model_lifecycle": Path(args.model_lifecycle_gate),
        "visual_regression_snapshots": Path(args.visual_regression_snapshots),
        "trace_svg_stress": Path(args.trace_svg_stress),
    }
    evidence = [
        evidence_summary(name, path, load_json(path), args.allow_missing)
        for name, path in inputs.items()
    ]
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": overall_status(evidence),
        "allow_missing": args.allow_missing,
        "evidence": evidence,
        "next_commands": [
            "make open-source-readiness-gate",
            "make open-source-readiness-backlog",
            "make open-source-development-backlog LOCAL_ONLY=1",
            "make trace-svg-stress PROVIDAPT_SERVER_URL=http://127.0.0.1:18080",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Open Source Milestone",
        "",
        f"- Status: `{report['status']}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Allow missing evidence: `{str(report['allow_missing']).lower()}`",
        "",
        "| Evidence | Status | Present | Detail | Path |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in report["evidence"]:
        detail_parts = []
        if item.get("schema"):
            detail_parts.append(f"schema={item['schema']}")
        if "task_count" in item:
            detail_parts.append(f"tasks={item['task_count']}")
        if "section_count" in item:
            detail_parts.append(f"sections={item['section_count']}")
        if item.get("blocked_sections"):
            detail_parts.append("blocked=" + ",".join(item["blocked_sections"]))
        if item.get("warning_sections"):
            detail_parts.append("warnings=" + ",".join(item["warning_sections"]))
        if item.get("model_lifecycle"):
            detail = item["model_lifecycle"]
            model = detail.get("model") or {}
            model_name = ":".join(part for part in [model.get("name", ""), model.get("version", "")] if part)
            if model_name:
                detail_parts.append("model=" + model_name)
            if detail.get("promotion_decision"):
                detail_parts.append("decision=" + str(detail["promotion_decision"]))
            detail_parts.append(f"blockers={detail.get('blocker_count', 0)}")
            detail_parts.append(f"warnings={detail.get('warning_count', 0)}")
            detail_parts.append(f"baseline_days={detail.get('baseline_days', 0)}")
            labels = detail.get("feedback_labels") or {}
            if labels:
                label_text = ",".join(f"{label}:{count}" for label, count in sorted(labels.items()))
                detail_parts.append("feedback=" + label_text)
            if detail.get("missing_evidence"):
                detail_parts.append("missing_evidence=" + ",".join(detail["missing_evidence"]))
        if item.get("visual_regression"):
            detail = item["visual_regression"]
            detail_parts.append(f"coverage={detail.get('covered_count', 0)}/{detail.get('screenshot_count', 0)}")
            detail_parts.append(f"matrix_complete={str(detail.get('complete_default_matrix', False)).lower()}")
            if detail.get("viewport_classes"):
                detail_parts.append("viewports=" + ",".join(detail["viewport_classes"]))
            if detail.get("comparison_status"):
                detail_parts.append("baseline=" + str(detail["comparison_status"]))
            comparison_counts = detail.get("comparison_counts") or {}
            if comparison_counts:
                detail_parts.append("comparison=" + ",".join(f"{key}:{value}" for key, value in sorted(comparison_counts.items())))
            dom = detail.get("dom_assertions") or {}
            if dom:
                detail_parts.append(f"dom_failed={dom.get('failed', 0)}/{dom.get('total', 0)}")
            if detail.get("missing_default_viewports"):
                detail_parts.append("missing_viewports=" + ",".join(detail["missing_default_viewports"]))
            if detail.get("missing_pages"):
                detail_parts.append("missing_pages=" + ",".join(detail["missing_pages"]))
        if item.get("trace_svg_stress"):
            detail = item["trace_svg_stress"]
            detail_parts.append(f"trace_results={detail.get('result_count', 0)}")
            detail_parts.append(f"trace_failures={detail.get('failure_count', 0)}")
            detail_parts.append(f"max_latency_ms={detail.get('max_latency_ms', 0)}")
            detail_parts.append(f"nodes={detail.get('min_node_count', 0)}-{detail.get('max_node_count', 0)}")
            if detail.get("failed_layouts"):
                detail_parts.append("failed_layouts=" + ",".join(detail["failed_layouts"]))
        if item.get("development_backlog"):
            detail = item["development_backlog"]
            detail_parts.append(f"remaining={detail.get('remaining_count', 0)}")
            detail_parts.append(f"evidence_aware={str(detail.get('evidence_aware', False)).lower()}")
            planning = detail.get("planning_summary") or {}
            if planning.get("next_local_tasks"):
                detail_parts.append("next_local=" + ",".join(planning["next_local_tasks"]))
            if planning.get("external_blockers"):
                detail_parts.append("external_blockers=" + ",".join(planning["external_blockers"]))
            status_counts = detail.get("by_status") or {}
            if status_counts:
                detail_parts.append("statuses=" + ",".join(f"{key}:{value}" for key, value in sorted(status_counts.items())))
            evidence_counts = detail.get("by_evidence_status") or {}
            if evidence_counts:
                detail_parts.append("evidence=" + ",".join(f"{key}:{value}" for key, value in sorted(evidence_counts.items())))
        lines.append(
            f"| {item['name']} | {item['status']} | {str(item['present']).lower()} | "
            f"{'; '.join(detail_parts)} | `{item['path']}` |"
        )
    backlog = next((item.get("development_backlog") for item in report["evidence"] if item.get("development_backlog")), None)
    if backlog:
        lines.extend(["", "## Development Backlog", ""])
        planning = backlog.get("planning_summary") or {}
        lines.extend([
            f"- Remaining tasks: `{backlog['remaining_count']}`",
            f"- Evidence aware: `{str(backlog['evidence_aware']).lower()}`",
            f"- Next local tasks: `{', '.join(planning.get('next_local_tasks', [])) or 'none'}`",
            f"- External blockers: `{', '.join(planning.get('external_blockers', [])) or 'none'}`",
        ])
        if planning.get("by_evidence_key"):
            lines.extend(["", "### Evidence Keys"])
            for key, task_ids in sorted(planning["by_evidence_key"].items()):
                lines.append(f"- `{key}`: {', '.join(task_ids)}")
        for key, title in [
            ("needs_fix", "Needs Fix"),
            ("needs_review", "Needs Review"),
            ("needs_evidence", "Needs Evidence"),
            ("blocked_external", "Blocked External"),
            ("missing_evidence", "Missing Evidence"),
        ]:
            items = backlog.get(key) or []
            if items:
                lines.extend(["", f"### {title}"])
                lines.extend(f"- `{item}`" for item in items)
    trace = next((item.get("trace_svg_stress") for item in report["evidence"] if item.get("trace_svg_stress")), None)
    if trace:
        lines.extend(["", "## Trace SVG Stress", ""])
        lines.extend([
            f"- Status: `{trace.get('status', '')}`",
            f"- Alert source: `{trace.get('alert_source', '')}`",
            f"- Alerts: `{trace.get('alert_count', 0)}`",
            f"- Layouts: `{trace.get('layout_count', 0)}`",
            f"- Results: `{trace.get('result_count', 0)}`",
            f"- Failures: `{trace.get('failure_count', 0)}`",
            f"- Max latency ms: `{trace.get('max_latency_ms', 0)}`",
            f"- Node range: `{trace.get('min_node_count', 0)}-{trace.get('max_node_count', 0)}`",
        ])
        if trace.get("by_layout"):
            lines.extend(["", "### Layout Results"])
            for layout, counts in trace["by_layout"].items():
                lines.append(f"- `{layout}`: pass={counts.get('pass', 0)} blocked={counts.get('blocked', 0)}")
        if trace.get("failures"):
            lines.extend(["", "### Trace Failures"])
            lines.extend(f"- {item}" for item in trace["failures"])
    lines.extend(["", "## Next Commands", ""])
    lines.extend(f"- `{command}`" for command in report["next_commands"])
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate local open-source readiness evidence into one milestone report.")
    parser.add_argument("--open-source-readiness-gate", default="build/open-source-readiness/open-source-readiness-gate.json")
    parser.add_argument("--open-source-readiness-backlog", default="build/open-source-readiness/open-source-readiness-backlog.json")
    parser.add_argument("--open-source-development-backlog", default="build/open-source-readiness/open-source-development-backlog.json")
    parser.add_argument("--release-gates", default="build/release-gate-status.json")
    parser.add_argument("--release-evidence-consistency-gate", default="build/release-evidence/release-evidence-consistency-gate.json")
    parser.add_argument("--model-lifecycle-gate", default="build/evaluation/model-lifecycle-gate.json")
    parser.add_argument("--visual-regression-snapshots", default="build/visual-regression/visual-regression-snapshots.json")
    parser.add_argument("--trace-svg-stress", default="build/trace-stress/trace-svg-stress.json")
    parser.add_argument("--allow-missing", action="store_true")
    parser.add_argument("--out-json", default="build/open-source-readiness/open-source-milestone.json")
    parser.add_argument("--out-md", default="build/open-source-readiness/open-source-milestone.md")
    args = parser.parse_args()
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} evidence={len(report['evidence'])} out={out_json.parent}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
