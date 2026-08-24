#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.open_source_operations_report.v1"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    return data if isinstance(data, dict) else {}


def status_from_release_gates(report: dict[str, Any]) -> tuple[str, list[str]]:
    gates = report.get("gates", [])
    blocked = [gate.get("name", "gate") for gate in gates if gate.get("status") in {"blocked", "fail"}]
    return ("pass" if not blocked and gates else "blocked", blocked)


def backend_status(manifest: dict[str, Any]) -> str:
    outputs = manifest.get("outputs", {})
    expected = {"systemd_dropin", "docker_compose", "kubernetes_secret"}
    return "pass" if expected.issubset(set(outputs)) else "blocked"


def postgres_status(report: dict[str, Any]) -> str:
    backup = (report.get("backup") or {}).get("status")
    restore = (report.get("restore") or {}).get("status")
    if backup == "pass" and restore in {"pass", "skipped"}:
        return "pass" if restore == "pass" else "warn"
    return "blocked"


def detection_status(report: dict[str, Any]) -> str:
    return "pass" if report.get("status") == "pass" else ("warn" if report else "blocked")


def optional_status(report: dict[str, Any]) -> str:
    if not report:
        return "blocked"
    status = str(report.get("status", "")).lower()
    return status if status in {"pass", "warn", "blocked"} else "blocked"


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    release = load_json(Path(args.release_gates))
    secrets = load_json(Path(args.secret_manifest))
    postgres = load_json(Path(args.postgres_drill))
    detection = load_json(Path(args.detection_quality))
    rbac = load_json(Path(args.rbac_audit))
    report_plan = load_json(Path(args.report_plan))
    siem = load_json(Path(args.siem_verify))
    upgrade = load_json(Path(args.upgrade_rollout))
    release_status, blocked_gates = status_from_release_gates(release)
    sections = {
        "release_gates": {"status": release_status, "blocked": blocked_gates},
        "secret_backends": {"status": backend_status(secrets), "variables": secrets.get("variable_count", 0)},
        "postgres_drill": {"status": postgres_status(postgres), "backup": (postgres.get("backup") or {}).get("status", "missing"), "restore": (postgres.get("restore") or {}).get("status", "missing")},
        "detection_quality": {"status": detection_status(detection), "precision": detection.get("precision_percent", 0), "recall": detection.get("recall_percent", 0)},
        "rbac_audit": {"status": optional_status(rbac), "keys": rbac.get("key_count", 0), "tenant_scoped_keys": rbac.get("tenant_scoped_keys", 0)},
        "scheduled_reports": {"status": optional_status(report_plan), "cadence": report_plan.get("cadence", "missing"), "formats": ",".join(report_plan.get("formats", [])) if isinstance(report_plan.get("formats"), list) else "missing"},
        "siem_soar_delivery": {"status": optional_status(siem), "endpoint": siem.get("endpoint", "missing"), "delivered": siem.get("delivered", 0), "dead_letter": siem.get("dead_letter", 0)},
        "upgrade_rollout": {"status": "pass" if upgrade.get("status") == "planned" else optional_status(upgrade), "target_version": upgrade.get("target_version", "missing"), "batches": len(upgrade.get("batches", [])) if isinstance(upgrade.get("batches"), list) else 0},
    }
    status = "pass"
    if any(value["status"] == "blocked" for value in sections.values()):
        status = "blocked"
    elif any(value["status"] == "warn" for value in sections.values()):
        status = "warn"
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "sections": sections,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Open Source Operations Report",
        "",
        f"- Status: `{report['status']}`",
        f"- Generated at: `{report['generated_at']}`",
        "",
        "| Section | Status | Detail |",
        "| --- | --- | --- |",
    ]
    for name, row in report["sections"].items():
        detail = ", ".join(f"{key}={value}" for key, value in row.items() if key != "status")
        lines.append(f"| {name} | {row['status']} | {detail} |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate open-source operations readiness evidence.")
    parser.add_argument("--release-gates", default="build/release-gate-status.json")
    parser.add_argument("--secret-manifest", default="build/secrets/secret-backend-manifest.json")
    parser.add_argument("--postgres-drill", default="build/postgres/postgres-drill.json")
    parser.add_argument("--detection-quality", default="build/evaluation/detection-quality.json")
    parser.add_argument("--rbac-audit", default="build/rbac/rbac-audit.json")
    parser.add_argument("--report-plan", default="build/reports/scheduled-report-plan.json")
    parser.add_argument("--siem-verify", default="build/siem/siem-verification.json")
    parser.add_argument("--upgrade-rollout", default="build/upgrade/rollout-plan.json")
    parser.add_argument("--out-json", default="build/open-source-operations.json")
    parser.add_argument("--out-md", default="build/open-source-operations.md")
    args = parser.parse_args()
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} out_json={out_json} out_md={out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
