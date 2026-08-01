#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.policy_approval_gate.v1"
DEFAULT_REQUIRED_ACTIONS = [
    "policy.publish",
    "policy.rollback",
    "upgrade.preflight",
    "upgrade.apply",
    "upgrade.rollback",
    "backup.prepare_cutover",
]


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    return data if isinstance(data, dict) else {}


def load_audit_records(path_value: str) -> list[dict[str, Any]]:
    if not path_value:
        return []
    path = Path(path_value)
    if not path.exists() or path.stat().st_size == 0:
        return []
    text = path.read_text(encoding="utf-8-sig").strip()
    if not text:
        return []
    if text.startswith("{"):
        data = json.loads(text)
        entries = data.get("entries") if isinstance(data, dict) else []
        return [entry for entry in entries if isinstance(entry, dict)]
    records: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}:{line_no}: invalid JSON: {exc}") from exc
        if isinstance(item, dict):
            records.append(item)
    return records


def status_value(report: dict[str, Any], allowed: set[str] | None = None) -> str:
    if not report:
        return "blocked"
    status = str(report.get("status", "")).lower()
    pass_values = allowed or {"pass", "warn"}
    if status in pass_values:
        return "pass" if status == "pass" else "warn"
    return "blocked"


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    rbac = load_json(Path(args.rbac_audit))
    compliance = load_json(Path(args.compliance_status))
    approvals = compliance.get("approvals") if isinstance(compliance.get("approvals"), dict) else {}
    audit_records = load_audit_records(args.audit_log)
    required_actions = args.required_action or DEFAULT_REQUIRED_ACTIONS
    configured_actions = set(str(item) for item in approvals.get("required_actions", []) if str(item).strip())
    missing_actions = [action for action in required_actions if action not in configured_actions]
    approval_history = approvals.get("history") if isinstance(approvals.get("history"), list) else []
    failures: list[str] = []
    warnings: list[str] = []
    if status_value(rbac) == "blocked":
        failures.append("rbac audit evidence is missing or blocked")
    if not bool(approvals.get("enabled")):
        failures.append("approval workflow is not enabled")
    if missing_actions:
        failures.append("approval workflow missing required actions: " + ", ".join(missing_actions))
    if int(rbac.get("tenant_scoped_keys") or 0) < args.min_tenant_scoped_keys:
        failures.append(f"tenant-scoped keys below minimum {args.min_tenant_scoped_keys}")
    if int(rbac.get("tenant_count") or 0) < args.min_tenants:
        failures.append(f"tenant count below minimum {args.min_tenants}")
    if not approval_history:
        warnings.append("approval workflow has no resolved approval history yet")
    audit_matches = [
        record for record in audit_records
        if str(record.get("source", "")).lower() in {"policy", "compliance", "upgrade", "backup"}
        or "approval" in json.dumps(record, sort_keys=True).lower()
    ]
    if args.require_audit_log and not audit_matches:
        failures.append("approval/audit evidence is missing from audit log")
    status = "pass" if not failures else "blocked"
    if status == "pass" and warnings:
        status = "warn"
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "rbac_status": status_value(rbac),
        "approval_enabled": bool(approvals.get("enabled")),
        "required_actions": sorted(configured_actions),
        "missing_required_actions": missing_actions,
        "tenant_scoped_keys": int(rbac.get("tenant_scoped_keys") or 0),
        "tenant_count": int(rbac.get("tenant_count") or 0),
        "approval_history": len(approval_history),
        "audit_matches": len(audit_matches),
        "failures": failures,
        "warnings": warnings,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Policy Approval Gate",
        "",
        f"- Status: `{report['status']}`",
        f"- RBAC: `{report['rbac_status']}`",
        f"- Approval enabled: `{report['approval_enabled']}`",
        f"- Tenant-scoped keys: `{report['tenant_scoped_keys']}`",
        f"- Tenants: `{report['tenant_count']}`",
        f"- Approval history: `{report['approval_history']}`",
        f"- Audit matches: `{report['audit_matches']}`",
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
    parser = argparse.ArgumentParser(description="Gate RBAC, tenant scope, audit, and policy approval workflow evidence.")
    parser.add_argument("--rbac-audit", default="build/rbac/rbac-audit.json")
    parser.add_argument("--compliance-status", default="build/compliance/compliance-status.json")
    parser.add_argument("--audit-log", default="")
    parser.add_argument("--required-action", action="append", default=[])
    parser.add_argument("--min-tenant-scoped-keys", type=int, default=1)
    parser.add_argument("--min-tenants", type=int, default=1)
    parser.add_argument("--require-audit-log", action="store_true")
    parser.add_argument("--out-json", default="build/policy-approval/policy-approval-gate.json")
    parser.add_argument("--out-md", default="build/policy-approval/policy-approval-gate.md")
    args = parser.parse_args()
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"policy approval gate: status={report['status']} tenants={report['tenant_count']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
