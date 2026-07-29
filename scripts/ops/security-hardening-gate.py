#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.security_hardening_gate.v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def read(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8-sig", errors="replace")


def load_json(path: str) -> dict[str, Any]:
    if not path:
        return {}
    target = Path(path)
    if not target.exists() or target.stat().st_size == 0:
        return {}
    data = json.loads(target.read_text(encoding="utf-8-sig"))
    return data if isinstance(data, dict) else {}


def check_config(path: Path) -> dict[str, Any]:
    data = read(path)
    failures: list[str] = []
    warnings: list[str] = []
    required = {
        "api auth": "auth_enabled: true",
        "tls": "enable: true",
        "storage encryption": "encrypt: true",
        "approval workflow": "require_approvals: true",
        "support redaction": "redact_archives: true",
    }
    if not data:
        failures.append("production config is missing")
    for name, marker in required.items():
        if marker not in data:
            failures.append(f"{name} is not visibly enabled")
    for marker in ("replace-with", "change-me"):
        if marker in data:
            warnings.append(f"placeholder marker remains: {marker}")
    return {"status": "blocked" if failures else ("warn" if warnings else "pass"), "path": str(path), "failures": failures, "warnings": warnings}


def check_systemd(path: Path) -> dict[str, Any]:
    data = read(path)
    failures: list[str] = []
    warnings: list[str] = []
    if not data:
        failures.append("systemd service is missing")
    for marker in ["PrivateTmp=true", "ProtectHome=true", "RuntimeDirectory=providapt", "ReadWritePaths="]:
        if marker not in data:
            failures.append(f"missing systemd hardening marker {marker}")
    for marker in ["NoNewPrivileges=false", "ProtectKernelTunables=false", "ProtectKernelModules=false", "ProtectControlGroups=false"]:
        if marker in data:
            warnings.append(f"{marker} is required for some eBPF modes; document approval before GA")
    if "CapabilityBoundingSet=" not in data:
        failures.append("CapabilityBoundingSet is missing")
    return {"status": "blocked" if failures else ("warn" if warnings else "pass"), "path": str(path), "failures": failures, "warnings": warnings}


def check_env(path: Path) -> dict[str, Any]:
    data = read(path)
    failures: list[str] = []
    warnings: list[str] = []
    if not data:
        failures.append("service environment file is missing")
    if 'PROVIDAPT_SKIP_PRIVILEGE_DROP=""' not in data:
        warnings.append("privilege drop default is not visibly locked on")
    if 'PROVIDAPT_SKIP_SANITY_CHECKS=""' not in data:
        warnings.append("sanity check bypass default is not visibly empty")
    return {"status": "blocked" if failures else ("warn" if warnings else "pass"), "path": str(path), "failures": failures, "warnings": warnings}


def check_rbac(report: dict[str, Any]) -> dict[str, Any]:
    if not report:
        return {"status": "skipped", "message": "RBAC audit not supplied"}
    status = str(report.get("status", "")).lower()
    failures = list(report.get("failures") or [])
    warnings = list(report.get("warnings") or [])
    if status == "blocked":
        return {"status": "blocked", "failures": failures or ["RBAC audit is blocked"], "warnings": warnings}
    if status == "warn" or warnings:
        return {"status": "warn", "failures": [], "warnings": warnings}
    return {"status": "pass", "failures": [], "warnings": []}


def overall(sections: dict[str, dict[str, Any]]) -> str:
    statuses = [section.get("status") for section in sections.values() if section.get("status") != "skipped"]
    if "blocked" in statuses:
        return "blocked"
    if "warn" in statuses:
        return "warn"
    return "pass"


def render_markdown(report: dict[str, Any]) -> str:
    lines = ["# ProvidAPT Security Hardening Gate", "", f"- Status: `{report['status']}`", f"- Generated at: `{report['generated_at']}`", ""]
    for name, section in report["sections"].items():
        lines.extend([f"## {name.replace('_', ' ').title()}", "", f"- Status: `{section['status']}`"])
        if section.get("failures"):
            lines.append("- Failures: " + "; ".join(section["failures"]))
        if section.get("warnings"):
            lines.append("- Warnings: " + "; ".join(section["warnings"]))
        if section.get("message"):
            lines.append("- Message: " + str(section["message"]))
        lines.append("")
    return "\n".join(lines)


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    sections = {
        "configuration": check_config(Path(args.config)),
        "systemd_sandbox": check_systemd(Path(args.service)),
        "environment": check_env(Path(args.env_file)),
        "rbac": check_rbac(load_json(args.rbac_audit)),
    }
    return {"schema": SCHEMA, "generated_at": utc_now(), "status": overall(sections), "sections": sections}


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate production security hardening evidence.")
    parser.add_argument("--config", default="examples/config/providapt.production.yaml")
    parser.add_argument("--service", default="deploy/linux/providapt.service")
    parser.add_argument("--env-file", default="deploy/linux/providapt.env")
    parser.add_argument("--rbac-audit", default="")
    parser.add_argument("--out-json", default="build/security-hardening/security-hardening-gate.json")
    parser.add_argument("--out-md", default="build/security-hardening/security-hardening-gate.md")
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
