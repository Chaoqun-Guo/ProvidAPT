#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.deployment_diagnostics_gate.v1"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    return data if isinstance(data, dict) else {}


def diagnostics_from_status(status: dict[str, Any]) -> dict[str, Any]:
    diagnostics = status.get("diagnostics") if isinstance(status.get("diagnostics"), dict) else {}
    return diagnostics if diagnostics else status


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    status_doc = load_json(Path(args.status_json))
    diag = diagnostics_from_status(status_doc)
    failures: list[str] = []
    warnings: list[str] = []
    if not diag:
        failures.append("runtime diagnostics evidence is missing")
    if args.require_tls and not bool(diag.get("tls_enabled")):
        failures.append("TLS is not enabled")
    if args.require_storage_encryption and not bool(diag.get("storage_encrypted")):
        failures.append("storage encryption is not enabled")
    if args.require_policy_sync:
        if not bool(diag.get("policy_enabled")):
            failures.append("policy sync is not enabled")
        if int(diag.get("applied_policy_version") or 0) < 1:
            failures.append("no applied policy version recorded")
    kernel_mode = str(diag.get("kernel_attachment_mode") or "").strip()
    if args.require_kernel_attach and kernel_mode in {"", "disabled", "none", "stub"}:
        failures.append("kernel attachment mode is not production-ready")
    if args.require_support_bundle and not bool(diag.get("support_bundle_enabled")):
        failures.append("support bundle diagnostics are not enabled")
    control_mode = str(diag.get("control_plane_mode") or "").strip()
    control_backend = str(diag.get("control_plane_state_backend") or "").strip()
    if args.require_control_plane and not control_mode:
        failures.append("control plane mode is missing")
    if args.require_state_backend and not control_backend:
        failures.append("control plane state backend is missing")
    if not str(diag.get("version") or "").strip():
        warnings.append("runtime version is missing from diagnostics")
    if not str(diag.get("output_dir") or "").strip():
        warnings.append("output directory is missing from diagnostics")
    status = "pass" if not failures else "blocked"
    if status == "pass" and warnings:
        status = "warn"
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "version": diag.get("version", ""),
        "open_source_control_plane": bool(diag.get("open_source_control_plane")),
        "tls_enabled": bool(diag.get("tls_enabled")),
        "kernel_attachment_mode": kernel_mode,
        "policy_enabled": bool(diag.get("policy_enabled")),
        "applied_policy_version": int(diag.get("applied_policy_version") or 0),
        "storage_encrypted": bool(diag.get("storage_encrypted")),
        "control_plane_mode": control_mode,
        "control_plane_state_backend": control_backend,
        "support_bundle_enabled": bool(diag.get("support_bundle_enabled")),
        "failures": failures,
        "warnings": warnings,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Deployment Diagnostics Gate",
        "",
        f"- Status: `{report['status']}`",
        f"- Version: `{report['version']}`",
        f"- Kernel mode: `{report['kernel_attachment_mode']}`",
        f"- Control plane access: `{'open-source' if report['open_source_control_plane'] else 'custom'}`",
        f"- TLS: `{report['tls_enabled']}`",
        f"- Storage encrypted: `{report['storage_encrypted']}`",
        f"- Policy version: `{report['applied_policy_version']}`",
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
    parser = argparse.ArgumentParser(description="Gate runtime deployment diagnostics from /api/v1/status evidence.")
    parser.add_argument("--status-json", default="build/deploy/status.json")
    parser.add_argument("--require-tls", action="store_true")
    parser.add_argument("--require-storage-encryption", action="store_true")
    parser.add_argument("--require-policy-sync", action="store_true")
    parser.add_argument("--require-kernel-attach", action="store_true")
    parser.add_argument("--require-support-bundle", action="store_true")
    parser.add_argument("--require-control-plane", action="store_true")
    parser.add_argument("--require-state-backend", action="store_true")
    parser.add_argument("--out-json", default="build/deploy/deployment-diagnostics-gate.json")
    parser.add_argument("--out-md", default="build/deploy/deployment-diagnostics-gate.md")
    args = parser.parse_args()
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"deployment diagnostics gate: status={report['status']} kernel={report['kernel_attachment_mode']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
