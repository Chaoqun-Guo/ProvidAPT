#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.security_hardening_pack.v1"


def load_json(path_value: str) -> dict[str, Any]:
    if not path_value:
        return {}
    path = Path(path_value)
    if not path.exists() or path.stat().st_size == 0:
        return {}
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    return data if isinstance(data, dict) else {}


def check(title: str, status: str, recommendations: list[str]) -> dict[str, Any]:
    return {"status": status, "recommendations": recommendations}


def build_pack(args: argparse.Namespace) -> dict[str, Any]:
    gate = load_json(args.hardening_gate)
    gate_status = str(gate.get("status") or "missing")
    checks = {
        "systemd": check("systemd", gate_status, [
            "Enable PrivateTmp, ProtectHome, RuntimeDirectory, CapabilityBoundingSet, and narrow ReadWritePaths.",
            "Document any eBPF capability exception before exposing the service.",
        ]),
        "firewall": check("firewall", "advisory", [
            "Allow REST and gRPC only from trusted Tailscale CIDRs or operator hosts.",
            "Block direct public access unless a reviewed reverse proxy and TLS policy are in front.",
        ]),
        "tailscale_acl": check("tailscale_acl", "advisory", [
            "Restrict dashboard/API access to operator groups.",
            "Keep SSH ACLs separate from dashboard/API ACLs and log ACL changes.",
        ]),
        "tls": check("tls", gate_status, [
            "Require TLS for agent telemetry and policy endpoints.",
            "Track certificate expiry and rotation evidence in release evidence.",
        ]),
        "secret_permissions": check("secret_permissions", gate_status, [
            "Keep secret files owned by root or providapt with mode 0600.",
            "Do not commit generated secrets, passwords, tokens, or tailnet details.",
        ]),
        "log_redaction": check("log_redaction", "advisory", [
            "Run support diagnostics and support bundle gates before sharing logs.",
            "Scan logs for token, password, DSN, and private key markers.",
        ]),
        "sbom_scans": check("sbom_scans", "advisory", [
            "Regenerate SBOM, checksums, govulncheck, Grype, and Trivy evidence for the final tag.",
            "Record waivers with owner, expiry, and remediation plan.",
        ]),
    }
    status = "blocked" if gate_status == "blocked" else "warn" if gate_status in {"warn", "missing"} else "pass"
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "hardening_gate": args.hardening_gate,
        "tailscale_acl": args.tailscale_acl,
        "checks": checks,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Open Source Security Hardening Pack",
        "",
        f"- Status: `{report['status']}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Tailscale ACL: `{report.get('tailscale_acl') or 'operator supplied'}`",
        "",
    ]
    for name, item in report["checks"].items():
        lines.extend([f"## {name.replace('_', ' ').title()}", "", f"- Status: `{item['status']}`"])
        lines.extend(f"- {rec}" for rec in item["recommendations"])
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an open-source deployment security hardening pack.")
    parser.add_argument("--hardening-gate", default="build/security-hardening/security-hardening-gate.json")
    parser.add_argument("--tailscale-acl", default="")
    parser.add_argument("--out-json", default="build/security-hardening/security-hardening-pack.json")
    parser.add_argument("--out-md", default="build/security-hardening/security-hardening-pack.md")
    args = parser.parse_args()
    report = build_pack(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"security hardening pack: status={report['status']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
