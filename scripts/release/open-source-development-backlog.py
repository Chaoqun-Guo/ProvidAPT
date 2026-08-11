#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.open_source_development_backlog.v1"

TASKS: list[dict[str, Any]] = [
    {
        "id": "release-ci-evidence",
        "phase": "release",
        "priority": 1,
        "status": "blocked_external",
        "local": False,
        "summary": "Archive passing GitHub Actions evidence for the final commit.",
        "acceptance": "Release evidence links to passing CI runs for the final commit.",
        "command": "make github-actions-evidence RELEASE_EVIDENCE=docs/project/release-evidence-<version>.md",
        "external_dependency": "Authenticated GitHub Actions run metadata.",
    },
    {
        "id": "release-security-scans",
        "phase": "release",
        "priority": 1,
        "status": "needs_evidence",
        "local": True,
        "summary": "Regenerate govulncheck, Grype, Trivy, and scan manifest evidence for the current commit.",
        "acceptance": "Scan manifest references the final commit and all blocking findings are fixed or waived.",
        "command": "make release-gates",
        "external_dependency": "Grype/Trivy may need Docker or an approved scanner host.",
    },
    {
        "id": "release-final-artifacts",
        "phase": "release",
        "priority": 1,
        "status": "needs_evidence",
        "local": True,
        "summary": "Rebuild final dist artifacts, checksums, SBOMs, signatures, and handoff bundle from the release tag.",
        "acceptance": "Artifact signing and customer release gates pass against artifacts from the final tag.",
        "command": "make release-open-source && make artifact-signing-gate && make customer-release-gate",
        "external_dependency": "Final release tag and signing key custody.",
    },
    {
        "id": "release-owner-approval",
        "phase": "release",
        "priority": 1,
        "status": "blocked_external",
        "local": False,
        "summary": "Replace pending release approvals with named Engineering, Security, Legal/project-owner, and Maintainer decisions.",
        "acceptance": "docs/project/release-approval-record.md has named approvers, decisions, and dates.",
        "command": "edit docs/project/release-approval-record.md",
        "external_dependency": "Named owner sign-off.",
    },
    {
        "id": "visual-browser-baselines",
        "phase": "frontend",
        "priority": 2,
        "status": "needs_evidence",
        "local": True,
        "summary": "Generate stable Dashboard and Trace Viewer browser screenshot baselines with full viewport coverage.",
        "acceptance": "visual-regression-gate passes for mobile, 1366x768, 1920x1080, and ultrawide screenshots with complete coverage summary.",
        "command": "make visual-regression-snapshots PROVIDAPT_SERVER_URL=http://127.0.0.1:18080 && make visual-regression-gate",
        "external_dependency": "Local daemon and browser automation runtime.",
    },
    {
        "id": "trace-svg-stress-evidence",
        "phase": "investigation",
        "priority": 2,
        "status": "needs_evidence",
        "local": True,
        "summary": "Run Trace SVG layout stress against real alert IDs and record latency/node-count evidence.",
        "acceptance": "trace-svg-stress report passes all configured layout latency and node-count thresholds.",
        "command": "make trace-svg-stress PROVIDAPT_SERVER_URL=http://127.0.0.1:18080 ALERT_IDS=\"<alert-id>\"",
        "external_dependency": "Real alert IDs and API access when auth is enabled.",
    },
    {
        "id": "capture-field-evidence-refresh",
        "phase": "detection",
        "priority": 2,
        "status": "needs_evidence",
        "local": False,
        "summary": "Refresh three-VM capture/enrichment evidence for cmdline, exe_path, pathname, UID/GID, PID/PPID, network tuple, and event type.",
        "acceptance": "capture-enrichment-field-gate passes against current three-VM NDJSON evidence.",
        "command": "make collect-vm-capture-evidence PROVIDAPT_VM_HOSTS=\"ubuntu@vm-ubuntu-master centos@vm-centos-slave ubuntu@vm-ubuntu-slave\"",
        "external_dependency": "VM access and fresh runtime NDJSON.",
    },
    {
        "id": "model-lifecycle-baseline",
        "phase": "ml",
        "priority": 2,
        "status": "needs_evidence",
        "local": True,
        "summary": "Collect longer-lived model lifecycle evidence with drift, reviewed feedback labels, baseline window, and promotion packet.",
        "acceptance": "model-lifecycle-gate passes with required feedback, drift, baseline, approval evidence, and archived promotion_packet hashes.",
        "command": "make model-lifecycle-gate MODEL_CLOSED_LOOP_JSON=... MODEL_DEPLOY_GATE_JSON=...",
        "external_dependency": "Real reviewed analyst feedback and model owner approval when required.",
    },
    {
        "id": "siem-soar-certification",
        "phase": "operations",
        "priority": 3,
        "status": "blocked_external",
        "local": False,
        "summary": "Certify Splunk, Elastic, and webhook delivery in target SIEM/SOAR environments.",
        "acceptance": "Customer environment certification includes retry, backpressure, field mapping, and alert landing evidence.",
        "command": "make customer-env-certification-gate REQUIRE_SIEM_CERTIFICATION=1 SIEM_CERTIFICATION=...",
        "external_dependency": "Target SIEM/SOAR endpoints and customer environment access.",
    },
    {
        "id": "rbac-audit-hardening",
        "phase": "operations",
        "priority": 3,
        "status": "needs_evidence",
        "local": True,
        "summary": "Harden RBAC evidence for delegated admin, tenant isolation, audit export, and role review.",
        "acceptance": "policy-approval-gate and customer-env-certification-gate pass with audit export and role-review evidence.",
        "command": "make ops-rbac-audit PROVIDAPT_CONFIG=... && make policy-approval-gate",
        "external_dependency": "Representative tenant-scoped configuration and role review record.",
    },
    {
        "id": "soak-24-72h",
        "phase": "operations",
        "priority": 3,
        "status": "blocked_external",
        "local": False,
        "summary": "Collect 24-72 hour noisy-host soak evidence with CPU, memory, disk, and dropped-event budgets.",
        "acceptance": "soak-readiness passes against continuous long-duration samples.",
        "command": "make soak-sample ... && make soak-readiness SOAK_SAMPLES=...",
        "external_dependency": "Long-running noisy-host environment.",
    },
    {
        "id": "plugin-distribution",
        "phase": "ecosystem",
        "priority": 4,
        "status": "needs_evidence",
        "local": True,
        "summary": "Collect signed plugin distribution evidence with compatibility, least-privilege permissions, and rollback rehearsal.",
        "acceptance": "plugin-release-gate passes for a signed sample plugin with explicit permissions, distribution metadata, compatibility range, and rollback instructions.",
        "command": "make plugin-release-gate PLUGIN_MANIFEST=... PLUGIN_SIGNATURE=...",
        "external_dependency": "Signing key policy for real plugin distribution.",
    },
    {
        "id": "onboarding-first-run-polish",
        "phase": "onboarding",
        "priority": 4,
        "status": "in_progress",
        "local": True,
        "summary": "Continue smoothing first-run onboarding checks for Tailscale, SSH, API, TLS, secrets, and PostgreSQL.",
        "acceptance": "onboarding-wizard manifest contains actionable pass/warn/fail checks and ready-to-run config outputs.",
        "command": "make onboarding-wizard",
        "external_dependency": "Representative operator answers and deployment mode.",
    },
]


def selected_tasks(local_only: bool, phase: str) -> list[dict[str, Any]]:
    tasks = [dict(task) for task in TASKS]
    if local_only:
        tasks = [task for task in tasks if task["local"]]
    if phase:
        tasks = [task for task in tasks if task["phase"] == phase]
    return sorted(tasks, key=lambda task: (task["priority"], task["phase"], task["id"]))


def build_report(local_only: bool = False, phase: str = "") -> dict[str, Any]:
    tasks = selected_tasks(local_only, phase)
    by_phase: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for task in tasks:
        by_phase[task["phase"]] = by_phase.get(task["phase"], 0) + 1
        by_status[task["status"]] = by_status.get(task["status"], 0) + 1
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "filters": {"local_only": local_only, "phase": phase},
        "task_count": len(tasks),
        "by_phase": by_phase,
        "by_status": by_status,
        "tasks": tasks,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Open Source Development Backlog",
        "",
        f"- Task count: `{report['task_count']}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Local only: `{str(report['filters']['local_only']).lower()}`",
        f"- Phase filter: `{report['filters']['phase'] or 'all'}`",
        "",
        "## Summary",
        "",
        "| Group | Count |",
        "| --- | --- |",
    ]
    for phase, count in sorted(report["by_phase"].items()):
        lines.append(f"| phase:{phase} | {count} |")
    for status, count in sorted(report["by_status"].items()):
        lines.append(f"| status:{status} | {count} |")
    lines.extend([
        "",
        "## Tasks",
        "",
        "| Priority | ID | Phase | Status | Local | Summary | Acceptance | Command | External Dependency |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ])
    for task in report["tasks"]:
        row = [
            str(task["priority"]),
            task["id"],
            task["phase"],
            task["status"],
            "yes" if task["local"] else "no",
            task["summary"],
            task["acceptance"],
            f"`{task['command']}`",
            task["external_dependency"],
        ]
        lines.append("| " + " | ".join(escape_cell(value) for value in row) + " |")
    lines.append("")
    return "\n".join(lines)


def escape_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an actionable local/open-source development backlog.")
    parser.add_argument("--local-only", action="store_true", help="Show tasks that can make progress in local development.")
    parser.add_argument("--phase", default="", help="Filter by phase, for example release, frontend, operations, ml.")
    parser.add_argument("--out-json", default="build/open-source-readiness/open-source-development-backlog.json")
    parser.add_argument("--out-md", default="build/open-source-readiness/open-source-development-backlog.md")
    args = parser.parse_args()
    report = build_report(local_only=args.local_only, phase=args.phase)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"tasks={report['task_count']} local_only={str(args.local_only).lower()} phase={args.phase or 'all'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
