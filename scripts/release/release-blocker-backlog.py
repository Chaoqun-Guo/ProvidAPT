#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.release_blocker_backlog.v1"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        raise SystemExit(f"missing release gate report: {path}")
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected JSON object")
    return data


def severity_for(status: str) -> str:
    if status == "blocked":
        return "release_blocking"
    if status == "warn":
        return "needs_owner_review"
    return "informational"


def build_backlog(report: dict[str, Any], source_label: str = "release") -> dict[str, Any]:
    tasks: list[dict[str, Any]] = []
    checklist: list[dict[str, Any]] = []
    for section_name, section in (report.get("sections") or {}).items():
        if not isinstance(section, dict):
            continue
        status = str(section.get("status") or "blocked").lower()
        messages = list(section.get("failures") or []) + list(section.get("warnings") or [])
        checklist.append({
            "section": section_name,
            "status": status,
            "severity": severity_for(status),
            "release_blocking": status == "blocked",
            "message_count": len(messages),
            "recommended_action": recommended_action(section_name),
        })
        if status == "pass":
            continue
        if not messages:
            messages = [f"{section_name} is {status}"]
        for index, message in enumerate(messages, start=1):
            tasks.append({
                "id": f"{section_name}-{index}",
                "section": section_name,
                "severity": severity_for(status),
                "status": status,
                "summary": message,
                "recommended_action": recommended_action(section_name),
            })
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "source_label": source_label,
        "source_status": report.get("status", "unknown"),
        "task_count": len(tasks),
        "checklist": checklist,
        "checklist_summary": checklist_summary(checklist),
        "tasks": tasks,
    }


def checklist_summary(checklist: list[dict[str, Any]]) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    for item in checklist:
        status = str(item.get("status") or "unknown")
        by_status[status] = by_status.get(status, 0) + 1
    return {
        "section_count": len(checklist),
        "release_blocking_count": sum(1 for item in checklist if item.get("release_blocking")),
        "by_status": by_status,
        "passing_sections": sorted(item["section"] for item in checklist if item.get("status") == "pass"),
        "blocked_sections": sorted(item["section"] for item in checklist if item.get("status") == "blocked"),
        "warning_sections": sorted(item["section"] for item in checklist if item.get("status") == "warn"),
    }


def recommended_action(section_name: str) -> str:
    return {
        "release_gates": "Attach passing CI, scanner, approval, and artifact gate evidence.",
        "dist_artifacts": "Rebuild final release artifacts and regenerate checksums, signatures, SBOMs, and readiness report.",
        "artifact_signing": "Run artifact-signing-gate and fix checksum, artifact hash, or signature evidence failures.",
        "release_evidence_consistency": "Run release-evidence-consistency-gate and regenerate stale dist, scan, signing, SBOM, or release readiness evidence.",
        "package_smoke": "Run package smoke tests on approved disposable Linux hosts or containers.",
        "production_readiness": "Run production-readiness-gate after secrets, TLS, PostgreSQL, and fleet evidence are available.",
        "ml_readiness": "Run ml-readiness-gate after VM capture, ground-truth matching, training, and evaluation.",
        "operations_readiness": "Run operations-readiness-gate after soak, fleet, upgrade, SIEM, and RBAC evidence are available.",
        "open_source_readiness": "Run open-source-readiness-gate after onboarding, docs, approval, and plugin evidence are available.",
        "legal_documents": "Complete legal/privacy documents and remove unresolved placeholders.",
        "delivery_documents": "Complete customer handoff, support, upgrade, and install documentation.",
        "release_gate_status": "Attach or regenerate current release gate status evidence for CI, scans, approvals, and artifacts.",
        "enterprise_readiness": "Run enterprise-readiness after release, secrets, PostgreSQL, detection, RBAC, reporting, SIEM, and upgrade evidence are available.",
        "model_lifecycle": "Run model-lifecycle-gate with closed-loop, deploy-gate, drift, baseline, feedback, and approval evidence.",
        "visual_baselines": "Capture the full Dashboard and Trace Viewer browser baseline matrix and rerun visual-regression-gate.",
        "onboarding_bundle": "Run onboarding-wizard and verify generated config and checklist outputs.",
        "plugin_release_gates": "Run plugin-release-gate for each shipped plugin or leave plugin evidence absent only when no plugins are distributed.",
        "open_source_documentation": "Complete required open-source docs and remove empty or missing files.",
        "external_approval": "Attach named approval evidence for the release scope.",
    }.get(section_name, "Assign an owner and attach passing evidence.")


def render_markdown(backlog: dict[str, Any]) -> str:
    summary = backlog.get("checklist_summary") or {}
    lines = [
        "# ProvidAPT Release Blocker Backlog",
        "",
        f"- Source: `{backlog.get('source_label', 'release')}`",
        f"- Source status: `{backlog['source_status']}`",
        f"- Task count: `{backlog['task_count']}`",
        f"- Sections: `{summary.get('section_count', 0)}`",
        f"- Release-blocking sections: `{summary.get('release_blocking_count', 0)}`",
        f"- Generated at: `{backlog['generated_at']}`",
        "",
        "## Checklist",
        "",
        "| Section | Status | Release Blocking | Messages | Recommended Action |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in backlog.get("checklist", []):
        action = str(item["recommended_action"]).replace("|", "\\|")
        lines.append(
            f"| {item['section']} | {item['status']} | {str(item['release_blocking']).lower()} | "
            f"{item['message_count']} | {action} |"
        )
    lines.extend([
        "",
        "## Tasks",
        "",
        "| ID | Severity | Section | Summary | Recommended Action |",
        "| --- | --- | --- | --- | --- |",
    ])
    for task in backlog["tasks"]:
        summary = str(task["summary"]).replace("|", "\\|")
        action = str(task["recommended_action"]).replace("|", "\\|")
        lines.append(f"| {task['id']} | {task['severity']} | {task['section']} | {summary} | {action} |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert release/readiness gate failures into an actionable blocker backlog.")
    parser.add_argument("--source-report", default="", help="Generic gate report with sections; overrides --customer-release-gate")
    parser.add_argument("--source-label", default="release")
    parser.add_argument("--customer-release-gate", default="build/customer-release/customer-release-gate.json")
    parser.add_argument("--out-json", default="build/customer-release/release-blocker-backlog.json")
    parser.add_argument("--out-md", default="build/customer-release/release-blocker-backlog.md")
    args = parser.parse_args()
    source_path = Path(args.source_report) if args.source_report else Path(args.customer_release_gate)
    backlog = build_backlog(load_json(source_path), args.source_label)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(backlog, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(backlog), encoding="utf-8")
    print(f"tasks={backlog['task_count']} source_status={backlog['source_status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
