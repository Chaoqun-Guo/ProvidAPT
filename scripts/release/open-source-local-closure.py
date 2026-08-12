#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


SCHEMA = "providapt.open_source_local_closure.v1"


ToolResolver = Callable[[str], bool]


@dataclass(frozen=True)
class TaskSpec:
    task_id: str
    title: str
    command: str
    required_tools: tuple[str, ...] = ()
    required_inputs: tuple[str, ...] = ()
    evidence_paths: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


TASKS = (
    TaskSpec(
        task_id="release-security-scans",
        title="Current commit security scans",
        command="RUN_SCANS=1 make release-open-source && make release-gates",
        required_tools=("govulncheck", "grype", "trivy"),
        evidence_paths=("build/security/scan-manifest.json", "build/release-gate-status.json"),
        notes=("Re-run on the final commit; apply explicit waivers only through release-gate waiver evidence.",),
    ),
    TaskSpec(
        task_id="release-final-artifacts",
        title="Final tagged release artifacts",
        command="git tag <release-tag> && make release-open-source && make artifact-signing-gate && make release-evidence-consistency-gate",
        required_tools=("git", "go", "syft"),
        required_inputs=("release_tag", "signature"),
        evidence_paths=("dist/checksums.txt", "dist/checksums.txt.sig", "dist/release-readiness.md", "build/artifact-signing/artifact-signing-gate.json"),
        notes=("Build from a clean final tag; do not reuse release-candidate artifacts.",),
    ),
    TaskSpec(
        task_id="visual-browser-baselines",
        title="Browser screenshot baselines",
        command="make visual-regression-snapshots PROVIDAPT_SERVER_URL=... && make visual-regression-gate",
        required_inputs=("server_url",),
        evidence_paths=("build/visual-regression/visual-regression-snapshots.json", "build/visual-regression/visual-regression-gate.json"),
        notes=("Capture mobile, 1366x768, 1920x1080, and ultrawide Dashboard and Trace Viewer screenshots.",),
    ),
    TaskSpec(
        task_id="trace-svg-stress-evidence",
        title="Trace SVG stress evidence",
        command='make trace-svg-stress PROVIDAPT_SERVER_URL=... ALERT_IDS="..."',
        required_inputs=("server_url", "alert_ids"),
        evidence_paths=("build/trace-stress/trace-svg-stress.json",),
        notes=("Use real alert IDs with large enough traces to exercise all layout modes.",),
    ),
    TaskSpec(
        task_id="model-lifecycle-baseline",
        title="Model lifecycle baseline",
        command="make model-lifecycle-gate MODEL_CLOSED_LOOP_JSON=... MODEL_DEPLOY_GATE_JSON=... MODEL_DRIFT_JSON=... REQUIRE_MODEL_APPROVAL=1 MODEL_APPROVAL=...",
        required_inputs=("model_closed_loop", "model_deploy_gate", "model_drift", "model_approval"),
        evidence_paths=("build/evaluation/model-lifecycle-gate.json",),
        notes=("Use real analyst feedback, a stable baseline window, drift evidence, and named promotion approval.",),
    ),
    TaskSpec(
        task_id="rbac-audit-hardening",
        title="RBAC, tenant isolation, audit, and role review",
        command="make ops-rbac-audit PROVIDAPT_CONFIG=... && make policy-approval-gate && make customer-env-certification-gate REQUIRE_DELEGATED_ADMIN=1 REQUIRE_AUDIT_EXPORT=1 REQUIRE_ROLE_REVIEW=1",
        required_inputs=("providapt_config", "rbac_audit", "policy_approval_gate", "audit_export", "role_review"),
        evidence_paths=("build/rbac/rbac-audit.json", "build/policy-approval/policy-approval-gate.json", "build/customer-certification/customer-environment-certification-gate.json"),
        notes=("Use real tenant-scoped keys, delegated admin records, audit export rows, and approved role-review entries.",),
    ),
    TaskSpec(
        task_id="plugin-distribution",
        title="Plugin distribution readiness",
        command="make plugin-release-gate PLUGIN_MANIFEST=... PLUGIN_SIGNATURE=... && make plugin-catalog-gate PLUGIN_GATES=...",
        required_inputs=("plugin_manifest", "plugin_signature", "plugin_gates"),
        evidence_paths=("build/plugins/plugin-release-gate.json", "build/plugins/plugin-catalog-gate.json"),
        notes=("Validate signed distribution metadata, permission model, compatibility range, and rollback instructions.",),
    ),
    TaskSpec(
        task_id="onboarding-first-run-polish",
        title="First-run onboarding operator flow",
        command="make onboarding-wizard CHECK_RESULTS=...",
        required_inputs=(),
        evidence_paths=("build/onboarding/onboarding-manifest.json",),
        notes=("Can run locally without a deployment; add CHECK_RESULTS from a real first-run session for release evidence.",),
    ),
)


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def default_tool_resolver(tool: str) -> bool:
    return shutil.which(tool) is not None


def current_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return ""
    return result.stdout.strip()


def input_value(args: argparse.Namespace, key: str) -> str:
    value = getattr(args, key, "")
    return str(value or "").strip()


def evidence_status(paths: tuple[str, ...]) -> tuple[str, list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    statuses: list[str] = []
    for raw in paths:
        path = Path(raw)
        report = load_json(path) if path.suffix == ".json" else {}
        status = str(report.get("status") or "").lower() if report else ""
        present = path.exists() and path.stat().st_size > 0
        rows.append(
            {
                "path": raw,
                "present": present,
                "status": status or ("present" if present else "missing"),
                "schema": report.get("schema", "") if report else "",
            }
        )
        if status:
            statuses.append(status)
    if statuses and all(item in {"pass", "ready"} for item in statuses):
        return "pass", rows
    if statuses and any(item in {"fail", "failed", "blocked", "error"} for item in statuses):
        return "blocked_existing_evidence", rows
    if any(row["present"] for row in rows):
        return "partial_evidence", rows
    return "missing_evidence", rows


def unable_reason(
    status: str,
    missing_tools: list[str],
    missing_inputs: list[str],
    ev_status: str,
    blockers: list[str],
    warnings: list[str],
) -> str:
    if status == "pass":
        return ""
    if missing_tools:
        return "Required local tools are not installed or not on PATH: " + ", ".join(missing_tools)
    if missing_inputs:
        return "Required release evidence inputs were not supplied: " + ", ".join(missing_inputs)
    if ev_status == "blocked_existing_evidence":
        return "Existing evidence is blocked or failed; inspect the referenced gate output and rerun or attach an approved waiver."
    if ev_status == "partial_evidence":
        return "Partial evidence exists, but the task needs a rerun with complete release inputs before it can pass."
    if ev_status == "missing_evidence":
        return "No local evidence has been generated for this task yet."
    return "; ".join(blockers or warnings)


def completion_requirement(spec: TaskSpec, missing_inputs: list[str]) -> str:
    if missing_inputs:
        return "Supply " + ", ".join(missing_inputs) + " and rerun: " + spec.command
    return spec.notes[0] if spec.notes else spec.command


def task_row(spec: TaskSpec, args: argparse.Namespace, tool_resolver: ToolResolver) -> dict[str, Any]:
    missing_tools = [tool for tool in spec.required_tools if not tool_resolver(tool)]
    missing_inputs = [key for key in spec.required_inputs if not input_value(args, key)]
    ev_status, ev_rows = evidence_status(spec.evidence_paths)
    blockers: list[str] = []
    warnings: list[str] = []
    if missing_tools:
        blockers.append("missing tools: " + ", ".join(missing_tools))
    if missing_inputs:
        blockers.append("missing inputs: " + ", ".join(missing_inputs))
    if ev_status == "blocked_existing_evidence":
        blockers.append("existing evidence is blocked or failed")
    elif ev_status in {"partial_evidence", "missing_evidence"}:
        warnings.append(ev_status.replace("_", " "))

    if blockers:
        if missing_tools:
            status = "blocked_missing_tool"
        elif missing_inputs:
            status = "blocked_missing_input"
        else:
            status = "blocked_existing_evidence"
    elif ev_status == "pass":
        status = "pass"
    elif ev_status == "partial_evidence":
        status = "ready_to_rerun"
    else:
        status = "ready_to_run"
    reason = unable_reason(status, missing_tools, missing_inputs, ev_status, blockers, warnings)

    return {
        "id": spec.task_id,
        "title": spec.title,
        "status": status,
        "command": spec.command,
        "required_tools": list(spec.required_tools),
        "missing_tools": missing_tools,
        "required_inputs": list(spec.required_inputs),
        "missing_inputs": missing_inputs,
        "evidence_status": ev_status,
        "evidence": ev_rows,
        "blockers": blockers,
        "warnings": warnings,
        "unable_reason": reason,
        "completion_requirement": completion_requirement(spec, missing_inputs),
        "notes": list(spec.notes),
    }


def overall_status(rows: list[dict[str, Any]]) -> str:
    if any(row["blockers"] for row in rows):
        return "blocked"
    if any(row["warnings"] for row in rows):
        return "warn"
    return "pass"


def build_report(args: argparse.Namespace, tool_resolver: ToolResolver = default_tool_resolver) -> dict[str, Any]:
    rows = [task_row(spec, args, tool_resolver) for spec in TASKS]
    available_tools = sorted({tool for spec in TASKS for tool in spec.required_tools if tool_resolver(tool)})
    missing_tools = sorted({tool for row in rows for tool in row["missing_tools"]})
    missing_inputs = sorted({item for row in rows for item in row["missing_inputs"]})
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "commit": current_commit(),
        "status": overall_status(rows),
        "task_count": len(rows),
        "available_tools": available_tools,
        "missing_tools": missing_tools,
        "missing_inputs": missing_inputs,
        "tasks": rows,
        "next_commands": [row["command"] for row in rows if row["status"] != "pass"],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Open Source Local Closure Matrix",
        "",
        f"- Status: `{report['status']}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Commit: `{report.get('commit') or 'unknown'}`",
        f"- Tasks: `{report['task_count']}`",
        "",
        "| Task | Status | Evidence | Missing Tools | Missing Inputs | Unable Reason |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in report["tasks"]:
        missing_tools = ", ".join(row["missing_tools"]) or "-"
        missing_inputs = ", ".join(row["missing_inputs"]) or "-"
        lines.append(
            f"| `{row['id']}` | `{row['status']}` | `{row['evidence_status']}` | "
            f"{missing_tools} | {missing_inputs} | {escape_cell(row.get('unable_reason') or '-')} |"
        )
    if report["missing_tools"]:
        lines.extend(["", "## Missing Tools", ""])
        lines.extend(f"- `{tool}`" for tool in report["missing_tools"])
    if report["missing_inputs"]:
        lines.extend(["", "## Missing Inputs", ""])
        lines.extend(f"- `{item}`" for item in report["missing_inputs"])
    lines.extend(["", "## Task Details", ""])
    for row in report["tasks"]:
        lines.extend([f"### {row['id']}", ""])
        lines.append(f"- Command: `{row['command']}`")
        for blocker in row["blockers"]:
            lines.append(f"- Blocker: {blocker}")
        for warning in row["warnings"]:
            lines.append(f"- Warning: {warning}")
        if row.get("unable_reason"):
            lines.append(f"- Unable reason: {row['unable_reason']}")
        lines.append(f"- Completion requirement: {row['completion_requirement']}")
        for note in row["notes"]:
            lines.append(f"- Note: {note}")
        lines.append("")
    lines.extend(["## Next Commands", ""])
    lines.extend(f"- `{command}`" for command in report["next_commands"])
    lines.append("")
    return "\n".join(lines)


def escape_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Create an honest local closure matrix for the remaining open-source release tasks.")
    p.add_argument("--server-url", default="")
    p.add_argument("--alert-ids", default="")
    p.add_argument("--release-tag", default="")
    p.add_argument("--signature", default="")
    p.add_argument("--model-closed-loop", default="")
    p.add_argument("--model-deploy-gate", default="")
    p.add_argument("--model-drift", default="")
    p.add_argument("--model-approval", default="")
    p.add_argument("--providapt-config", default="")
    p.add_argument("--rbac-audit", default="")
    p.add_argument("--policy-approval-gate", default="")
    p.add_argument("--audit-export", default="")
    p.add_argument("--role-review", default="")
    p.add_argument("--plugin-manifest", default="")
    p.add_argument("--plugin-signature", default="")
    p.add_argument("--plugin-gates", default="")
    p.add_argument("--out-json", default="build/open-source-readiness/open-source-local-closure.json")
    p.add_argument("--out-md", default="build/open-source-readiness/open-source-local-closure.md")
    return p


def main() -> int:
    args = parser().parse_args()
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} tasks={report['task_count']} missing_tools={len(report['missing_tools'])} missing_inputs={len(report['missing_inputs'])}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
