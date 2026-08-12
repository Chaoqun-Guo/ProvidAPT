#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.onboarding_bundle.v1"


def config_yaml(args: argparse.Namespace) -> str:
    state_backend = args.postgres_dsn if args.postgres_dsn else "/var/log/providapt/control-plane-state.json"
    return f"""output:
  dir: {args.log_dir}
  format: json
  max_file_bytes: 16777216
  retain_max_bytes: {args.log_retain_bytes}
  alert_max_file_bytes: 8388608
  alert_retain_max_bytes: {args.alert_retain_bytes}
api:
  grpc: ":{args.grpc_port}"
  rest: ":{args.rest_port}"
  auth_enabled: true
  auth_keys:
    - ${{PROVIDAPT_API_AUTH_KEYS}}
  auth_roles:
    ${{PROVIDAPT_API_AUTH_KEYS}}: admin
control_plane:
  mode: {args.mode}
  role: leader
  state_backend: {state_backend}
storage:
  encrypt: true
  key_file: /etc/providapt/storage.key
policy:
  enabled: true
  endpoint: http://127.0.0.1:{args.rest_port}
  api_key: ${{PROVIDAPT_POLICY_API_KEY}}
  poll_interval: 30s
support_bundle:
  redact_archives: true
  retain_archives: 5
capture:
  enable_net: true
  enable_file: true
  enable_proc: true
"""


def build_bundle(args: argparse.Namespace) -> dict[str, object]:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    config_path = out_dir / "providapt.onboarding.yaml"
    checklist_path = out_dir / "onboarding-checklist.md"
    report_path = out_dir / "onboarding-report.md"
    manifest_path = out_dir / "onboarding-manifest.json"
    result_template_path = out_dir / "onboarding-check-results.template.json"
    config_path.write_text(config_yaml(args), encoding="utf-8")
    check_results = load_check_results(getattr(args, "check_results", ""))
    checks = apply_check_results(environment_checks(args), check_results)
    summary = check_summary(checks)
    actions = next_actions(checks)
    result_template_path.write_text(json.dumps(check_result_template(checks), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checklist = f"""# ProvidAPT First-Run Onboarding Checklist

- Confirm Linux kernel supports selected attachment mode.
- Fill and validate secrets with `make ops-secret-template` and `make ops-secret-validate`.
- Install TLS certificates or run `make ops-tls-bootstrap` for lab bootstrap.
- Start PostgreSQL when `postgres_dsn` is configured.
- Start server on REST port `{args.rest_port}` and gRPC port `{args.grpc_port}`.
- Open dashboard and confirm all agents report healthy.
- Run `make enterprise-readiness` before customer handoff.
- Fill `onboarding-check-results.template.json` with observed results, then
  rerun `make onboarding-wizard CHECK_RESULTS={result_template_path}`.

## Environment Checks

{chr(10).join(f"- **{item['name']}** ({item['severity']}): `{item['command']}` - {item['purpose']}. Next: {item['next_step']}" for item in checks)}
"""
    checklist_path.write_text(checklist, encoding="utf-8")
    report_path.write_text(render_report(args, checks, summary, actions), encoding="utf-8")
    manifest = {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": onboarding_status(summary),
        "mode": args.mode,
        "rest_port": args.rest_port,
        "grpc_port": args.grpc_port,
        "postgres": bool(args.postgres_dsn),
        "check_results_path": getattr(args, "check_results", ""),
        "check_summary": summary,
        "environment_checks": checks,
        "next_actions": actions,
        "outputs": {
            "config": str(config_path),
            "checklist": str(checklist_path),
            "report": str(report_path),
            "check_results_template": str(result_template_path),
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def environment_checks(args: argparse.Namespace) -> list[dict[str, str]]:
    checks = [
        check("tailscale", "tailscale status", "verify tailnet connectivity", "Fix Tailscale login, DNS, or ACLs before VM checks."),
        check("ssh", "ssh -o BatchMode=yes <user>@<vm-host> true", "verify passwordless VM access", "Install or repair SSH keys for every target VM."),
        check("api", f"curl -fsS http://127.0.0.1:{args.rest_port}/api/v1/status", "verify REST API health", "Start providaptd and confirm local firewall rules."),
        check("dashboard", f"curl -fsS http://127.0.0.1:{args.rest_port}/dashboard", "verify dashboard shell is reachable", "Check REST bind address, auth settings, and reverse proxy routing."),
        check("tls", "make ops-tls-check CERTS=\"build/tls/server.crt build/tls/agent.crt\"", "verify certificate validity", "Run make ops-tls-bootstrap for lab certificates or install production certificates."),
        check("secrets", "make ops-secret-validate SECRET_ENV=build/providapt.secrets.env", "verify required secret references", "Generate a template with make ops-secret-template and replace placeholders."),
    ]
    if args.postgres_dsn:
        checks.append(check("postgres", "make ops-postgres-drill", "verify backup and restore path", "Set PROVIDAPT_DATABASE_DSN and optional PROVIDAPT_RESTORE_DSN before the drill."))
    return checks


def load_check_results(path_value: str) -> dict[str, dict[str, Any]]:
    if not path_value:
        return {}
    path = Path(path_value)
    if not path.exists() or path.stat().st_size == 0:
        return {}
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    entries = data.get("checks", data) if isinstance(data, dict) else data
    if not isinstance(entries, list):
        return {}
    results: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or entry.get("check") or "").strip()
        if not name:
            continue
        status = str(entry.get("status") or "").strip().lower()
        if status not in {"pass", "warn", "fail", "unknown", "skipped"}:
            status = "unknown"
        results[name] = {
            "status": status,
            "observed": str(entry.get("observed") or entry.get("message") or "").strip(),
            "evidence": str(entry.get("evidence") or entry.get("path") or "").strip(),
        }
    return results


def apply_check_results(checks: list[dict[str, str]], results: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    enriched: list[dict[str, str]] = []
    for item in checks:
        check_item = dict(item)
        result = results.get(item["name"], {})
        check_item["status"] = str(result.get("status") or "unknown")
        check_item["observed"] = str(result.get("observed") or "")
        check_item["evidence"] = str(result.get("evidence") or "")
        enriched.append(check_item)
    return enriched


def check_summary(checks: list[dict[str, str]]) -> dict[str, int]:
    summary = {"pass": 0, "warn": 0, "fail": 0, "unknown": 0, "skipped": 0, "total": len(checks)}
    for item in checks:
        status = item.get("status", "unknown")
        if status not in summary:
            status = "unknown"
        summary[status] += 1
    return summary


def check_result_template(checks: list[dict[str, str]]) -> dict[str, object]:
    return {
        "schema": "providapt.onboarding_check_results.v1",
        "checks": [
            {
                "name": item["name"],
                "status": item.get("status", "unknown"),
                "command": item["command"],
                "observed": item.get("observed", ""),
                "evidence": item.get("evidence", ""),
            }
            for item in checks
        ],
    }


def next_actions(checks: list[dict[str, str]]) -> list[dict[str, str]]:
    actions: list[dict[str, str]] = []
    priority = {"fail": 1, "unknown": 2, "warn": 3, "skipped": 4}
    for item in checks:
        status = item.get("status", "unknown")
        if status == "pass":
            continue
        actions.append({
            "check": item.get("name", ""),
            "status": status,
            "severity": item.get("severity", ""),
            "command": item.get("command", ""),
            "next_step": item.get("next_step", ""),
        })
    return sorted(actions, key=lambda item: (priority.get(item["status"], 5), item["check"]))


def onboarding_status(summary: dict[str, int]) -> str:
    if summary.get("fail", 0) > 0:
        return "blocked"
    if summary.get("warn", 0) > 0 or summary.get("unknown", 0) > 0 or summary.get("skipped", 0) > 0:
        return "warn"
    return "pass"


def render_report(args: argparse.Namespace, checks: list[dict[str, str]], summary: dict[str, int], actions: list[dict[str, str]]) -> str:
    lines = [
        "# ProvidAPT Onboarding Report",
        "",
        f"- Status: `{onboarding_status(summary)}`",
        f"- Mode: `{args.mode}`",
        f"- REST port: `{args.rest_port}`",
        f"- gRPC port: `{args.grpc_port}`",
        f"- Checks: `{summary['pass']} pass / {summary['warn']} warn / {summary['fail']} fail / {summary['unknown']} unknown / {summary['skipped']} skipped`",
        "",
        "| Check | Status | Severity | Purpose | Observed | Evidence | Next Step |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in checks:
        lines.append(
            "| {name} | {status} | {severity} | {purpose} | {observed} | {evidence} | {next_step} |".format(
                name=escape_cell(item.get("name", "")),
                status=escape_cell(item.get("status", "")),
                severity=escape_cell(item.get("severity", "")),
                purpose=escape_cell(item.get("purpose", "")),
                observed=escape_cell(item.get("observed", "")),
                evidence=escape_cell(item.get("evidence", "")),
                next_step=escape_cell(item.get("next_step", "")),
            )
        )
    if actions:
        lines.extend([
            "",
            "## Next Actions",
            "",
            "| Check | Status | Command | Next Step |",
            "| --- | --- | --- | --- |",
        ])
        for item in actions:
            lines.append(
                "| {check} | {status} | `{command}` | {next_step} |".format(
                    check=escape_cell(item.get("check", "")),
                    status=escape_cell(item.get("status", "")),
                    command=escape_cell(item.get("command", "")),
                    next_step=escape_cell(item.get("next_step", "")),
                )
            )
    lines.append("")
    return "\n".join(lines)


def escape_cell(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def check(name: str, command: str, purpose: str, next_step: str, severity: str = "required") -> dict[str, str]:
    return {
        "name": name,
        "command": command,
        "purpose": purpose,
        "next_step": next_step,
        "severity": severity,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate first-run ProvidAPT onboarding config and checklist.")
    parser.add_argument("--out-dir", default="build/onboarding")
    parser.add_argument("--mode", choices=["standalone", "cluster"], default="standalone")
    parser.add_argument("--rest-port", type=int, default=18080)
    parser.add_argument("--grpc-port", type=int, default=50051)
    parser.add_argument("--log-dir", default="/var/log/providapt")
    parser.add_argument("--log-retain-bytes", type=int, default=268435456)
    parser.add_argument("--alert-retain-bytes", type=int, default=67108864)
    parser.add_argument("--postgres-dsn", default="")
    parser.add_argument("--check-results", default="", help="Optional JSON check result list to merge into the onboarding report.")
    args = parser.parse_args()
    manifest = build_bundle(args)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
