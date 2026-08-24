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


EVIDENCE_MAP = {
    "release-ci-evidence": ["github_actions_evidence"],
    "release-security-scans": ["release_gates"],
    "release-final-artifacts": ["release_evidence_consistency_gate", "artifact_signing_gate", "customer_release_gate"],
    "release-owner-approval": ["external_approval"],
    "visual-browser-baselines": ["visual_regression_gate"],
    "trace-svg-stress-evidence": ["trace_svg_stress"],
    "capture-field-evidence-refresh": ["capture_enrichment_gate"],
    "model-lifecycle-baseline": ["model_lifecycle_gate"],
    "siem-soar-certification": ["siem_verify", "customer_env_certification_gate"],
    "rbac-audit-hardening": ["rbac_audit", "policy_approval_gate", "customer_env_certification_gate"],
    "soak-24-72h": ["soak_readiness"],
    "plugin-distribution": ["plugin_catalog_gate"],
    "onboarding-first-run-polish": ["onboarding_manifest"],
}


def load_json(path_value: str) -> dict[str, Any]:
    if not path_value:
        return {}
    path = Path(path_value)
    if not path.exists() or path.stat().st_size == 0:
        return {}
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    return data if isinstance(data, dict) else {}


def evidence_status(report: dict[str, Any]) -> str:
    if not report:
        return "missing"
    status = str(report.get("status") or report.get("source_status") or "").lower()
    if status in {"pass", "ready"}:
        return "pass"
    if status in {"warn", "warning", "planned"}:
        return "warn"
    if status in {"blocked", "fail", "failed", "review_required"}:
        return "blocked"
    if report.get("schema") or report.get("outputs") or report.get("check_summary"):
        return "present"
    return "missing"


def release_security_evidence_status(report: dict[str, Any]) -> str:
    if not report:
        return "missing"
    if report.get("schema") == "providapt.release_security_local_gate.v1":
        return evidence_status(report)
    gates = report.get("gates")
    if not isinstance(gates, list):
        return evidence_status(report)
    required = {"govulncheck_evidence", "grype_evidence", "trivy_evidence"}
    statuses: dict[str, str] = {}
    for gate in gates:
        if not isinstance(gate, dict):
            continue
        name = str(gate.get("name") or "")
        if name in required:
            statuses[name] = str(gate.get("status") or "").lower()
    if set(statuses) != required:
        return "missing"
    if all(statuses[name] == "pass" for name in required):
        return "pass"
    if any(statuses[name] in {"blocked", "fail", "failed"} for name in required):
        return "blocked"
    if any(statuses[name] in {"warn", "warning"} for name in required):
        return "warn"
    return "missing"


def aggregate_evidence_status(statuses: list[str]) -> str:
    if not statuses:
        return ""
    if any(status == "blocked" for status in statuses):
        return "blocked"
    if all(status in {"pass", "present"} for status in statuses):
        return "pass"
    if any(status == "warn" for status in statuses):
        return "warn"
    if any(status in {"pass", "present"} for status in statuses):
        return "partial"
    return "missing"


def apply_evidence_status(tasks: list[dict[str, Any]], evidence_paths: dict[str, str]) -> list[dict[str, Any]]:
    updated: list[dict[str, Any]] = []
    for task in tasks:
        item = dict(task)
        evidence_keys = EVIDENCE_MAP.get(item["id"], [])
        evidence_items = []
        statuses: list[str] = []
        for key in evidence_keys:
            path = evidence_paths.get(key, "")
            report = load_json(path)
            if item["id"] == "release-security-scans" and key == "release_gates":
                status = release_security_evidence_status(report)
            else:
                status = evidence_status(report)
            statuses.append(status)
            evidence_items.append({"key": key, "path": path, "status": status})
        status = aggregate_evidence_status(statuses)
        item["evidence_keys"] = evidence_keys
        item["evidence"] = evidence_items
        item["evidence_key"] = ",".join(evidence_keys)
        item["evidence_path"] = ";".join(entry["path"] for entry in evidence_items if entry.get("path"))
        item["evidence_status"] = status
        if status == "pass":
            item["status"] = "done"
        elif status == "warn":
            item["status"] = "needs_review"
        elif status == "blocked":
            item["status"] = "needs_fix"
        elif status == "partial":
            item["status"] = "needs_review"
        updated.append(item)
    return updated


def planning_summary(tasks: list[dict[str, Any]]) -> dict[str, Any]:
    remaining = [
        task for task in tasks
        if task.get("status") not in {"done"}
    ]
    next_local_details = sorted(
        [
            planning_task_detail(task) for task in remaining
            if task.get("local")
            and task.get("status") in {"needs_evidence", "needs_review", "needs_fix", "in_progress"}
        ],
        key=lambda item: (item["rank"], item["priority"], item["id"]),
    )
    next_local = [item["id"] for item in next_local_details]
    external = [
        task["id"] for task in remaining
        if not task.get("local") or task.get("status") == "blocked_external"
    ]
    by_evidence_key: dict[str, list[str]] = {}
    for task in remaining:
        for item in task.get("evidence", []):
            status = item.get("status")
            if status in {"missing", "blocked", "warn"}:
                by_evidence_key.setdefault(item.get("key", "unknown"), []).append(task["id"])
    return {
        "remaining_count": len(remaining),
        "next_local_tasks": next_local[:5],
        "next_local_details": next_local_details[:5],
        "next_local_count": len(next_local),
        "external_blockers": external,
        "external_blocker_count": len(external),
        "by_evidence_key": {key: sorted(set(value)) for key, value in sorted(by_evidence_key.items())},
    }


def planning_task_detail(task: dict[str, Any]) -> dict[str, Any]:
    status = str(task.get("status") or "")
    evidence_status = str(task.get("evidence_status") or "")
    evidence_items = task.get("evidence") if isinstance(task.get("evidence"), list) else []
    missing_keys = [
        str(item.get("key") or "unknown") for item in evidence_items
        if item.get("status") in {"missing", "blocked", "warn"}
    ]
    status_rank = {
        "needs_fix": 0,
        "needs_review": 1,
        "needs_evidence": 2,
        "in_progress": 3,
    }.get(status, 9)
    evidence_rank = {
        "blocked": 0,
        "warn": 1,
        "partial": 1,
        "missing": 2,
        "": 3,
    }.get(evidence_status, 3)
    rank = status_rank * 10 + evidence_rank
    reason = status
    if evidence_status:
        reason = f"{status}/{evidence_status}"
    if missing_keys:
        reason += " via " + ",".join(missing_keys)
    return {
        "id": task["id"],
        "phase": task.get("phase", ""),
        "priority": task.get("priority", 99),
        "status": status,
        "evidence_status": evidence_status,
        "rank": rank,
        "reason": reason,
        "command": task.get("command", ""),
    }


def build_report(local_only: bool = False, phase: str = "", evidence_paths: dict[str, str] | None = None) -> dict[str, Any]:
    tasks = selected_tasks(local_only, phase)
    evidence_paths = evidence_paths or {}
    if evidence_paths:
        tasks = apply_evidence_status(tasks, evidence_paths)
    by_phase: dict[str, int] = {}
    by_status: dict[str, int] = {}
    by_evidence_status: dict[str, int] = {}
    for task in tasks:
        by_phase[task["phase"]] = by_phase.get(task["phase"], 0) + 1
        by_status[task["status"]] = by_status.get(task["status"], 0) + 1
        if task.get("evidence_status"):
            by_evidence_status[task["evidence_status"]] = by_evidence_status.get(task["evidence_status"], 0) + 1
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "filters": {"local_only": local_only, "phase": phase, "evidence_aware": bool(evidence_paths)},
        "task_count": len(tasks),
        "by_phase": by_phase,
        "by_status": by_status,
        "by_evidence_status": by_evidence_status,
        "planning_summary": planning_summary(tasks),
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
    for status, count in sorted(report.get("by_evidence_status", {}).items()):
        lines.append(f"| evidence:{status} | {count} |")
    planning = report.get("planning_summary") or {}
    lines.extend([
        "",
        "## Planning Summary",
        "",
        f"- Remaining tasks: `{planning.get('remaining_count', 0)}`",
        f"- Next local tasks: `{', '.join(planning.get('next_local_tasks', [])) or 'none'}`",
        f"- External blockers: `{', '.join(planning.get('external_blockers', [])) or 'none'}`",
    ])
    if planning.get("next_local_details"):
        lines.extend([
            "",
            "| Next Local Task | Phase | Status | Evidence | Rank | Reason | Command |",
            "| --- | --- | --- | --- | ---: | --- | --- |",
        ])
        for item in planning["next_local_details"]:
            lines.append(
                "| {id} | {phase} | {status} | {evidence_status} | {rank} | {reason} | `{command}` |".format(
                    id=escape_cell(item.get("id", "")),
                    phase=escape_cell(item.get("phase", "")),
                    status=escape_cell(item.get("status", "")),
                    evidence_status=escape_cell(item.get("evidence_status", "")),
                    rank=item.get("rank", 0),
                    reason=escape_cell(item.get("reason", "")),
                    command=escape_cell(item.get("command", "")),
                )
            )
    if planning.get("by_evidence_key"):
        lines.extend(["", "| Evidence Key | Tasks |", "| --- | --- |"])
        for key, task_ids in planning["by_evidence_key"].items():
            lines.append(f"| {key} | {', '.join(task_ids)} |")
    lines.extend([
        "",
        "## Tasks",
        "",
        "| Priority | ID | Phase | Status | Evidence | Local | Summary | Acceptance | Command | External Dependency |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ])
    for task in report["tasks"]:
        evidence = task.get("evidence_status", "")
        if task.get("evidence"):
            evidence = ",".join(f"{item['key']}:{item['status']}" for item in task["evidence"])
        row = [
            str(task["priority"]),
            task["id"],
            task["phase"],
            task["status"],
            evidence,
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
    parser.add_argument("--github-actions-evidence", default="")
    parser.add_argument("--release-gates", default="")
    parser.add_argument("--release-evidence-consistency-gate", default="")
    parser.add_argument("--artifact-signing-gate", default="")
    parser.add_argument("--customer-release-gate", default="")
    parser.add_argument("--visual-regression-gate", default="")
    parser.add_argument("--trace-svg-stress", default="")
    parser.add_argument("--capture-enrichment-gate", default="")
    parser.add_argument("--model-lifecycle-gate", default="")
    parser.add_argument("--siem-verify", default="")
    parser.add_argument("--rbac-audit", default="")
    parser.add_argument("--policy-approval-gate", default="")
    parser.add_argument("--soak-readiness", default="")
    parser.add_argument("--customer-env-certification-gate", default="")
    parser.add_argument("--plugin-catalog-gate", default="")
    parser.add_argument("--onboarding-manifest", default="")
    parser.add_argument("--external-approval", default="")
    parser.add_argument("--out-json", default="build/open-source-readiness/open-source-development-backlog.json")
    parser.add_argument("--out-md", default="build/open-source-readiness/open-source-development-backlog.md")
    args = parser.parse_args()
    evidence_paths = {
        "github_actions_evidence": args.github_actions_evidence,
        "release_gates": args.release_gates,
        "release_evidence_consistency_gate": args.release_evidence_consistency_gate,
        "artifact_signing_gate": args.artifact_signing_gate,
        "customer_release_gate": args.customer_release_gate,
        "visual_regression_gate": args.visual_regression_gate,
        "trace_svg_stress": args.trace_svg_stress,
        "capture_enrichment_gate": args.capture_enrichment_gate,
        "model_lifecycle_gate": args.model_lifecycle_gate,
        "siem_verify": args.siem_verify,
        "rbac_audit": args.rbac_audit,
        "policy_approval_gate": args.policy_approval_gate,
        "soak_readiness": args.soak_readiness,
        "customer_env_certification_gate": args.customer_env_certification_gate,
        "plugin_catalog_gate": args.plugin_catalog_gate,
        "onboarding_manifest": args.onboarding_manifest,
        "external_approval": args.external_approval,
    }
    report = build_report(local_only=args.local_only, phase=args.phase, evidence_paths={key: value for key, value in evidence_paths.items() if value})
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"tasks={report['task_count']} local_only={str(args.local_only).lower()} phase={args.phase or 'all'} evidence_aware={str(report['filters']['evidence_aware']).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
