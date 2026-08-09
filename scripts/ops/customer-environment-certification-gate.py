#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.customer_environment_certification.v1"


def load_json(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    target = Path(path)
    if not target.exists() or target.stat().st_size == 0:
        return {}
    data = json.loads(target.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise SystemExit(f"{target}: expected JSON object")
    return data


def evidence_file(path: str | None) -> dict[str, Any]:
    if not path:
        return {"present": False, "path": ""}
    target = Path(path)
    return {"present": target.exists() and target.stat().st_size > 0, "path": str(target)}


def status(report: dict[str, Any]) -> str:
    return str(report.get("status") or "").lower()


def passish(report: dict[str, Any], allowed: set[str] | None = None) -> bool:
    return bool(report) and status(report) in (allowed or {"pass"})


def section(name: str, ok: bool, failures: list[str], warnings: list[str] | None = None, **details: Any) -> dict[str, Any]:
    return {
        "name": name,
        "status": "pass" if ok else "blocked",
        "failures": failures,
        "warnings": warnings or [],
        "details": details,
    }


def rbac_section(args: argparse.Namespace) -> dict[str, Any]:
    report = load_json(args.rbac_audit)
    policy = load_json(args.policy_approval_gate)
    audit_export = evidence_file(args.audit_export)
    role_review = evidence_file(args.role_review)
    failures: list[str] = []
    if not passish(report, {"pass", "warn"}):
        failures.append("RBAC audit evidence is missing or blocked")
    if int(report.get("tenant_count") or 0) < args.min_tenants:
        failures.append(f"tenant_count below {args.min_tenants}")
    if int(report.get("tenant_scoped_keys") or 0) < args.min_tenant_scoped_keys:
        failures.append(f"tenant_scoped_keys below {args.min_tenant_scoped_keys}")
    if args.require_delegated_admin and int(report.get("custom_role_count") or 0) <= 0:
        failures.append("delegated admin/custom role evidence is missing")
    if not passish(policy, {"pass", "warn"}):
        failures.append("policy approval gate evidence is missing or blocked")
    if args.require_audit_export and not audit_export["present"]:
        failures.append("audit export evidence is missing")
    if args.require_role_review and not role_review["present"]:
        failures.append("role review evidence is missing")
    return section(
        "rbac_audit_multi_tenant",
        not failures,
        failures,
        tenant_count=report.get("tenant_count", 0),
        tenant_scoped_keys=report.get("tenant_scoped_keys", 0),
        custom_role_count=report.get("custom_role_count", 0),
        audit_export=audit_export,
        role_review=role_review,
        policy_status=status(policy) or "missing",
    )


def siem_section(args: argparse.Namespace) -> dict[str, Any]:
    report = load_json(args.siem_verify)
    certification = load_json(args.siem_certification)
    failures: list[str] = []
    if not passish(report, {"pass", "warn"}):
        failures.append("SIEM verification evidence is missing or blocked")
    delivered = int(report.get("delivered") or report.get("forwarded") or 0)
    dead_letter = int(report.get("dead_letter") or report.get("dead_letters") or 0)
    if delivered < args.min_siem_delivered:
        failures.append(f"SIEM delivered count {delivered} below {args.min_siem_delivered}")
    if dead_letter > args.max_siem_dead_letter:
        failures.append(f"SIEM dead-letter count {dead_letter} above {args.max_siem_dead_letter}")
    if args.require_siem_certification:
        if not certification:
            failures.append("target SIEM/SOAR certification evidence is missing")
        else:
            for key in ("field_mapping", "retry", "backpressure", "alert_landing"):
                if str(certification.get(key, "")).lower() not in {"pass", "passed", "verified"}:
                    failures.append(f"SIEM certification {key} is not verified")
    return section(
        "siem_soar_certification",
        not failures,
        failures,
        provider=report.get("provider", certification.get("provider", "")),
        delivered=delivered,
        dead_letter=dead_letter,
        certification_status=status(certification) or "missing",
    )


def upgrade_section(args: argparse.Namespace) -> dict[str, Any]:
    report = load_json(args.upgrade_rollout)
    failures: list[str] = []
    if not passish(report, {"pass", "planned"}):
        failures.append("upgrade rollout evidence is missing or blocked")
    batches = report.get("batches") if isinstance(report.get("batches"), list) else []
    if not any(batch.get("name") == "canary" for batch in batches if isinstance(batch, dict)):
        failures.append("canary batch is missing")
    if not report.get("pause_resume_controls"):
        failures.append("pause/resume controls are missing from rollout plan")
    rollback = report.get("rollback") if isinstance(report.get("rollback"), dict) else {}
    if not rollback.get("batches"):
        failures.append("rollback batch plan is missing")
    if args.require_agent_groups and not any((batch.get("agents") for batch in batches if isinstance(batch, dict))):
        failures.append("agent group/batch membership is missing")
    return section(
        "upgrade_orchestration",
        not failures,
        failures,
        target_version=report.get("target_version", ""),
        batches=len(batches),
        eligible_agents=report.get("eligible_agents", 0),
    )


def soak_section(args: argparse.Namespace) -> dict[str, Any]:
    report = load_json(args.soak_readiness)
    checks = report.get("checks") if isinstance(report.get("checks"), dict) else {}
    duration = (checks.get("duration") or {}).get("observed", report.get("duration_hours", 0))
    dropped = (checks.get("drops") or {}).get("observed", report.get("dropped_events", 0))
    failures: list[str] = []
    if not passish(report):
        failures.append("soak readiness evidence is missing or blocked")
    if float(duration or 0) < args.min_soak_hours:
        failures.append(f"soak duration {duration}h below {args.min_soak_hours}h")
    if int(dropped or 0) > args.max_dropped_events:
        failures.append(f"dropped events {dropped} above {args.max_dropped_events}")
    return section("soak_performance", not failures, failures, duration_hours=duration, dropped_events=dropped)


def foundation_section(args: argparse.Namespace) -> dict[str, Any]:
    production = load_json(args.production_readiness_gate)
    deployment = load_json(args.deployment_diagnostics_gate)
    backup = load_json(args.backup_readiness_gate)
    failures: list[str] = []
    if not passish(production):
        failures.append("production readiness gate is missing or blocked")
    if not passish(deployment, {"pass", "warn"}):
        failures.append("deployment diagnostics gate is missing or blocked")
    if args.require_tls and not bool((deployment or {}).get("tls_enabled", False)):
        failures.append("TLS is not enabled in deployment diagnostics")
    if args.require_state_backend and not str((deployment or {}).get("control_plane_state_backend", "")).strip():
        failures.append("state backend evidence is missing")
    if not passish(backup, {"pass", "warn"}):
        failures.append("backup readiness gate is missing or blocked")
    return section(
        "secret_tls_postgres_backup",
        not failures,
        failures,
        production_status=status(production) or "missing",
        deployment_status=status(deployment) or "missing",
        backup_status=status(backup) or "missing",
        tls_enabled=bool((deployment or {}).get("tls_enabled", False)),
    )


def plugin_section(args: argparse.Namespace) -> dict[str, Any]:
    if not args.plugin_gate:
        return section("plugin_ecosystem", not args.require_plugin_gate, ["plugin release gate evidence is missing"] if args.require_plugin_gate else [], warnings=["no plugin shipped"])
    report = load_json(args.plugin_gate)
    permissions = ((report.get("plugin") or {}).get("permissions") or []) if isinstance(report.get("plugin"), dict) else []
    failures: list[str] = []
    if not passish(report):
        failures.append("plugin release gate is missing or blocked")
    if args.require_plugin_signature and not bool(report.get("signature_present")):
        failures.append("plugin signature is missing")
    if args.require_plugin_permissions and not permissions:
        failures.append("plugin permission model is missing")
    return section("plugin_ecosystem", not failures, failures, plugin=(report.get("plugin") or {}).get("name", ""), permissions=permissions)


def onboarding_section(args: argparse.Namespace) -> dict[str, Any]:
    report = load_json(args.onboarding_manifest)
    checks = report.get("environment_checks") if isinstance(report.get("environment_checks"), list) else []
    failures: list[str] = []
    if not report:
        failures.append("onboarding manifest is missing")
    if len(checks) < args.min_onboarding_checks:
        failures.append(f"onboarding environment checks below {args.min_onboarding_checks}")
    required_names = set(args.required_onboarding_check or [])
    present_names = {str(item.get("name") or "") for item in checks if isinstance(item, dict)}
    missing = sorted(required_names - present_names)
    if missing:
        failures.append("onboarding checks missing: " + ", ".join(missing))
    return section("customer_onboarding", not failures, failures, checks=len(checks), mode=report.get("mode", ""))


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    sections = [
        rbac_section(args),
        siem_section(args),
        upgrade_section(args),
        soak_section(args),
        foundation_section(args),
        plugin_section(args),
        onboarding_section(args),
    ]
    failures = [f"{section['name']}: {failure}" for section in sections for failure in section["failures"]]
    warnings = [f"{section['name']}: {warning}" for section in sections for warning in section["warnings"]]
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": "blocked" if failures else "warn" if warnings else "pass",
        "sections": {section["name"]: section for section in sections},
        "failures": failures,
        "warnings": warnings,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Customer Environment Certification Gate",
        "",
        f"- Status: `{report['status']}`",
        f"- Generated at: `{report['generated_at']}`",
        "",
        "| Section | Status | Detail |",
        "| --- | --- | --- |",
    ]
    for name, section in report["sections"].items():
        detail = ", ".join(f"{key}={value}" for key, value in section["details"].items())
        lines.append(f"| {name} | {section['status']} | {detail} |")
    if report["failures"]:
        lines.extend(["", "## Failures", ""])
        lines.extend(f"- {item}" for item in report["failures"])
    if report["warnings"]:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {item}" for item in report["warnings"])
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Gate customer production certification evidence across security, operations, SIEM, upgrade, plugin, and onboarding areas.")
    parser.add_argument("--rbac-audit", default="build/rbac/rbac-audit.json")
    parser.add_argument("--policy-approval-gate", default="build/policy-approval/policy-approval-gate.json")
    parser.add_argument("--audit-export", default="")
    parser.add_argument("--role-review", default="")
    parser.add_argument("--require-delegated-admin", action="store_true")
    parser.add_argument("--require-audit-export", action="store_true")
    parser.add_argument("--require-role-review", action="store_true")
    parser.add_argument("--min-tenants", type=int, default=1)
    parser.add_argument("--min-tenant-scoped-keys", type=int, default=1)
    parser.add_argument("--siem-verify", default="build/siem/siem-verification.json")
    parser.add_argument("--siem-certification", default="")
    parser.add_argument("--require-siem-certification", action="store_true")
    parser.add_argument("--min-siem-delivered", type=int, default=1)
    parser.add_argument("--max-siem-dead-letter", type=int, default=0)
    parser.add_argument("--upgrade-rollout", default="build/upgrade/rollout-plan.json")
    parser.add_argument("--require-agent-groups", action="store_true")
    parser.add_argument("--soak-readiness", default="build/performance/soak-readiness.json")
    parser.add_argument("--min-soak-hours", type=float, default=24.0)
    parser.add_argument("--max-dropped-events", type=int, default=0)
    parser.add_argument("--production-readiness-gate", default="build/production-readiness/production-readiness-gate.json")
    parser.add_argument("--deployment-diagnostics-gate", default="build/deploy/deployment-diagnostics-gate.json")
    parser.add_argument("--backup-readiness-gate", default="build/backup/backup-readiness-gate.json")
    parser.add_argument("--require-tls", action="store_true")
    parser.add_argument("--require-state-backend", action="store_true")
    parser.add_argument("--plugin-gate", default="")
    parser.add_argument("--require-plugin-gate", action="store_true")
    parser.add_argument("--require-plugin-signature", action="store_true")
    parser.add_argument("--require-plugin-permissions", action="store_true")
    parser.add_argument("--onboarding-manifest", default="build/onboarding/onboarding-manifest.json")
    parser.add_argument("--min-onboarding-checks", type=int, default=5)
    parser.add_argument("--required-onboarding-check", action="append", default=[])
    parser.add_argument("--out-json", default="build/customer-certification/customer-environment-certification-gate.json")
    parser.add_argument("--out-md", default="build/customer-certification/customer-environment-certification-gate.md")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"customer environment certification: status={report['status']} sections={len(report['sections'])}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
