#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.operations_readiness.v1"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    return data if isinstance(data, dict) else {}


def status_value(report: dict[str, Any], pass_values: set[str] | None = None) -> str:
    if not report:
        return "blocked"
    status = str(report.get("status", "")).lower()
    allowed = pass_values or {"pass"}
    if status in allowed:
        return "pass"
    if status in {"warn", "warning"}:
        return "warn"
    return "blocked"


def ml_detail(report: dict[str, Any]) -> dict[str, Any]:
    sections = report.get("sections") if isinstance(report.get("sections"), dict) else {}
    dataset = sections.get("dataset_quality", {}) if isinstance(sections.get("dataset_quality"), dict) else {}
    metrics = sections.get("model_metrics", {}) if isinstance(sections.get("model_metrics"), dict) else {}
    deploy = sections.get("model_deploy_gate", {}) if isinstance(sections.get("model_deploy_gate"), dict) else {}
    warnings = list(dataset.get("warnings") or []) + list(deploy.get("warnings") or [])
    return {
        "status": status_value(report),
        "graphs": dataset.get("records", 0),
        "source_events": dataset.get("source_events", 0),
        "truth_match_rate_percent": dataset.get("truth_match_rate_percent", 0),
        "precision_percent": metrics.get("precision_percent", 0),
        "recall_percent": metrics.get("recall_percent", 0),
        "f1_percent": metrics.get("f1_percent", 0),
        "warnings": warnings,
    }


def soak_detail(report: dict[str, Any]) -> dict[str, Any]:
    checks = report.get("checks") if isinstance(report.get("checks"), dict) else {}
    return {
        "status": status_value(report),
        "samples": report.get("sample_count", 0),
        "duration_hours": (checks.get("duration") or {}).get("observed", 0),
        "max_cpu_percent": (checks.get("cpu") or {}).get("observed", 0),
        "max_memory_mb": (checks.get("memory") or {}).get("observed", 0),
        "max_disk_mb": (checks.get("disk") or {}).get("observed", 0),
        "dropped_events": (checks.get("drops") or {}).get("observed", 0),
    }


def fleet_detail(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": status_value(report),
        "agents": report.get("agent_count", report.get("agents", 0)),
        "healthy": report.get("healthy_count", report.get("healthy", 0)),
        "stale": report.get("stale_count", report.get("stale", 0)),
    }


def upgrade_detail(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": status_value(report, {"pass", "planned"}),
        "target_version": report.get("target_version", ""),
        "fleet_size": report.get("fleet_size", 0),
        "eligible_agents": report.get("eligible_agents", 0),
        "batches": len(report.get("batches", [])) if isinstance(report.get("batches"), list) else 0,
    }


def simple_detail(report: dict[str, Any], **fields: str) -> dict[str, Any]:
    row: dict[str, Any] = {"status": status_value(report)}
    for out_name, source_name in fields.items():
        row[out_name] = report.get(source_name, 0)
    return row


def overall_status(sections: dict[str, dict[str, Any]]) -> str:
    statuses = [section.get("status") for section in sections.values()]
    if any(status == "blocked" for status in statuses):
        return "blocked"
    if any(status == "warn" for status in statuses):
        return "warn"
    return "pass"


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    sections = {
        "production_foundation": simple_detail(load_json(Path(args.production_readiness_gate)), healthy_agents="healthy_agents"),
        "detection_ml": ml_detail(load_json(Path(args.ml_readiness_gate))),
        "fleet_health": fleet_detail(load_json(Path(args.fleet_verification))),
        "soak_stability": soak_detail(load_json(Path(args.soak_readiness))),
        "upgrade_rollout": upgrade_detail(load_json(Path(args.upgrade_rollout))),
        "siem_soar_delivery": simple_detail(load_json(Path(args.siem_verify)), delivered="delivered", dead_letter="dead_letter"),
        "rbac_audit": simple_detail(load_json(Path(args.rbac_audit)), keys="key_count", tenant_scoped_keys="tenant_scoped_keys"),
        "install_delivery": simple_detail(load_json(Path(args.install_delivery_check))),
        "observability_pack": simple_detail(load_json(Path(args.observability_pack_check))),
        "security_hardening": simple_detail(load_json(Path(args.security_hardening_gate))),
    }
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": overall_status(sections),
        "sections": sections,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Operations Readiness",
        "",
        f"- Status: `{report['status']}`",
        f"- Generated at: `{report['generated_at']}`",
        "",
        "| Section | Status | Detail |",
        "| --- | --- | --- |",
    ]
    for name, section in report["sections"].items():
        detail = ", ".join(f"{key}={value}" for key, value in section.items() if key != "status" and key != "warnings")
        lines.append(f"| {name} | {section['status']} | {detail} |")
    warnings = [
        f"{name}: {item}"
        for name, section in report["sections"].items()
        for item in section.get("warnings", [])
    ]
    if warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {item}" for item in warnings)
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate production operations readiness evidence.")
    parser.add_argument("--production-readiness-gate", default="build/production-readiness/production-readiness-gate.json")
    parser.add_argument("--ml-readiness-gate", default="build/ml-readiness/ml-readiness-gate.json")
    parser.add_argument("--fleet-verification", default="build/deploy/vm-fleet-verification.json")
    parser.add_argument("--soak-readiness", default="build/performance/soak-readiness.json")
    parser.add_argument("--upgrade-rollout", default="build/upgrade/rollout-plan.json")
    parser.add_argument("--siem-verify", default="build/siem/siem-verification.json")
    parser.add_argument("--rbac-audit", default="build/rbac/rbac-audit.json")
    parser.add_argument("--install-delivery-check", default="build/install-delivery/install-delivery-check.json")
    parser.add_argument("--observability-pack-check", default="build/observability/observability-pack-check.json")
    parser.add_argument("--security-hardening-gate", default="build/security-hardening/security-hardening-gate.json")
    parser.add_argument("--out-json", default="build/operations-readiness/operations-readiness-gate.json")
    parser.add_argument("--out-md", default="build/operations-readiness/operations-readiness-gate.md")
    args = parser.parse_args()
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} sections={','.join(report['sections'])}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
