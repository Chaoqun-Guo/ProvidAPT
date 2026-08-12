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
    operator_flow_path = out_dir / "onboarding-operator-flow.md"
    result_template_path = out_dir / "onboarding-check-results.template.json"
    config_path.write_text(config_yaml(args), encoding="utf-8")
    check_results = load_check_results(getattr(args, "check_results", ""))
    checks = apply_check_results(environment_checks(args), check_results)
    summary = check_summary(checks)
    actions = next_actions(checks)
    action_summary = onboarding_action_summary(actions)
    flow = operator_flow(args, checks, action_summary)
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
- Follow `onboarding-operator-flow.md` for the staged first-run sequence and
  copy final observations back into the check-results JSON.

## Environment Checks

{chr(10).join(f"- **{item['name']}** ({item['severity']}): `{item['command']}` - {item['purpose']}. Next: {item['next_step']}" for item in checks)}
"""
    checklist_path.write_text(checklist, encoding="utf-8")
    operator_flow_path.write_text(render_operator_flow(flow), encoding="utf-8")
    report_path.write_text(render_report(args, checks, summary, actions, action_summary), encoding="utf-8")
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
        "operator_flow": flow,
        "next_actions": actions,
        "action_summary": action_summary,
        "outputs": {
            "config": str(config_path),
            "checklist": str(checklist_path),
            "report": str(report_path),
            "operator_flow": str(operator_flow_path),
            "check_results_template": str(result_template_path),
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def environment_checks(args: argparse.Namespace) -> list[dict[str, str]]:
    vm_targets = vm_hosts(args)
    ssh_command = " && ".join(f"ssh -o BatchMode=yes {target} true" for target in vm_targets) if vm_targets else "ssh -o BatchMode=yes <user>@<vm-host> true"
    checks = [
        check("tailscale", "tailscale status", "verify tailnet connectivity", "Fix Tailscale login, DNS, or ACLs before VM checks."),
        check("ssh", ssh_command, "verify passwordless VM access", "Install or repair SSH keys for every target VM."),
        check("api", f"curl -fsS http://127.0.0.1:{args.rest_port}/api/v1/status", "verify REST API health", "Start providaptd and confirm local firewall rules."),
        check("dashboard", f"curl -fsS http://127.0.0.1:{args.rest_port}/dashboard", "verify dashboard shell is reachable", "Check REST bind address, auth settings, and reverse proxy routing."),
        check("tls", "make ops-tls-check CERTS=\"build/tls/server.crt build/tls/agent.crt\"", "verify certificate validity", "Run make ops-tls-bootstrap for lab certificates or install production certificates."),
        check("secrets", "make ops-secret-validate SECRET_ENV=build/providapt.secrets.env", "verify required secret references", "Generate a template with make ops-secret-template and replace placeholders."),
    ]
    if args.postgres_dsn:
        checks.append(check("postgres", "make ops-postgres-drill", "verify backup and restore path", "Set PROVIDAPT_DATABASE_DSN and optional PROVIDAPT_RESTORE_DSN before the drill."))
    return checks


def vm_hosts(args: argparse.Namespace) -> list[str]:
    raw = str(getattr(args, "vm_hosts", "") or "").strip()
    if not raw:
        return []
    return [item.strip() for item in raw.replace(",", " ").split() if item.strip()]


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


def onboarding_action_summary(actions: list[dict[str, str]]) -> dict[str, object]:
    by_status: dict[str, list[str]] = {}
    by_severity: dict[str, list[str]] = {}
    for item in actions:
        check_name = str(item.get("check") or "")
        status = str(item.get("status") or "unknown")
        severity = str(item.get("severity") or "unknown")
        by_status.setdefault(status, []).append(check_name)
        by_severity.setdefault(severity, []).append(check_name)
    return {
        "action_count": len(actions),
        "blocked_checks": sorted(by_status.get("fail", [])),
        "warning_checks": sorted(by_status.get("warn", [])),
        "unknown_checks": sorted(by_status.get("unknown", [])),
        "skipped_checks": sorted(by_status.get("skipped", [])),
        "by_status": {key: sorted(value) for key, value in sorted(by_status.items())},
        "by_severity": {key: sorted(value) for key, value in sorted(by_severity.items())},
        "top_actions": actions[:5],
    }


def onboarding_status(summary: dict[str, int]) -> str:
    if summary.get("fail", 0) > 0:
        return "blocked"
    if summary.get("warn", 0) > 0 or summary.get("unknown", 0) > 0 or summary.get("skipped", 0) > 0:
        return "warn"
    return "pass"


def check_status(checks: list[dict[str, str]], names: list[str]) -> str:
    selected = [item.get("status", "unknown") for item in checks if item.get("name") in names]
    if not selected:
        return "unknown"
    if any(status == "fail" for status in selected):
        return "blocked"
    if any(status in {"warn", "unknown", "skipped"} for status in selected):
        return "pending"
    return "ready"


def operator_flow(args: argparse.Namespace, checks: list[dict[str, str]], action_summary: dict[str, object]) -> list[dict[str, object]]:
    targets = vm_hosts(args)
    target_note = ", ".join(targets) if targets else "<user>@<vm-host>"
    return [
        flow_step(
            "prepare",
            "Prepare environment",
            ["make verify-env", "make ops-secret-template"],
            ["Linux hosts with Tailscale joined", f"VM SSH targets: {target_note}"],
            "Tailscale and SSH checks are pass or intentionally documented",
            check_status(checks, ["tailscale", "ssh"]),
        ),
        flow_step(
            "configure",
            "Generate configuration",
            ["make onboarding-wizard OUT_DIR=build/onboarding", "make ops-secret-validate SECRET_ENV=build/providapt.secrets.env"],
            ["PROVIDAPT_API_AUTH_KEYS from the operator secret store", "TLS material or lab bootstrap certificates"],
            "Config, secrets, and TLS checks are ready for first daemon start",
            check_status(checks, ["secrets", "tls"]),
        ),
        flow_step(
            "start",
            "Start control plane",
            [f"providaptd -config build/onboarding/providapt.onboarding.yaml", f"curl -fsS http://127.0.0.1:{args.rest_port}/api/v1/status"],
            ["REST and gRPC ports available", "PostgreSQL DSN when configured"],
            "API check passes and dashboard shell responds",
            check_status(checks, ["api", "dashboard"]),
        ),
        flow_step(
            "verify",
            "Verify operations evidence",
            ["make visual-regression-snapshots PROVIDAPT_SERVER_URL=http://127.0.0.1:18080 DRY_RUN=1", "make open-source-local-closure"],
            ["Observed check results copied into onboarding-check-results.template.json"],
            "Onboarding report has no failed checks and unknowns are reduced to accepted warnings",
            "blocked" if action_summary.get("blocked_checks") else ("pending" if action_summary.get("unknown_checks") else "ready"),
        ),
        flow_step(
            "handoff",
            "Package handoff evidence",
            ["make open-source-milestone ALLOW_MISSING=1", "make open-source-evidence-summary ALLOW_MISSING=1"],
            ["onboarding-manifest.json", "onboarding-report.md", "onboarding-operator-flow.md"],
            "Manifest, report, and evidence summary are attached to release or lab handoff",
            "blocked" if action_summary.get("blocked_checks") else ("ready" if not action_summary.get("action_count") else "pending"),
        ),
    ]


def flow_step(
    step_id: str,
    title: str,
    commands: list[str],
    inputs: list[str],
    completion: str,
    status: str,
) -> dict[str, object]:
    return {
        "id": step_id,
        "title": title,
        "status": status,
        "commands": commands,
        "inputs": inputs,
        "completion": completion,
    }


def render_operator_flow(flow: list[dict[str, object]]) -> str:
    lines = [
        "# ProvidAPT First-Run Operator Flow",
        "",
        "| Step | Status | Completion |",
        "| --- | --- | --- |",
    ]
    for item in flow:
        lines.append(f"| {escape_cell(str(item['title']))} | `{escape_cell(str(item['status']))}` | {escape_cell(str(item['completion']))} |")
    for item in flow:
        lines.extend(["", f"## {item['title']}", "", f"- Status: `{item['status']}`", "- Inputs:"])
        lines.extend(f"  - {value}" for value in item.get("inputs", []))
        lines.append("- Commands:")
        lines.extend(f"  - `{value}`" for value in item.get("commands", []))
        lines.append(f"- Done when: {item['completion']}")
    lines.append("")
    return "\n".join(lines)


def render_report(
    args: argparse.Namespace,
    checks: list[dict[str, str]],
    summary: dict[str, int],
    actions: list[dict[str, str]],
    action_summary: dict[str, object],
) -> str:
    lines = [
        "# ProvidAPT Onboarding Report",
        "",
        f"- Status: `{onboarding_status(summary)}`",
        f"- Mode: `{args.mode}`",
        f"- REST port: `{args.rest_port}`",
        f"- gRPC port: `{args.grpc_port}`",
        f"- Checks: `{summary['pass']} pass / {summary['warn']} warn / {summary['fail']} fail / {summary['unknown']} unknown / {summary['skipped']} skipped`",
        f"- Next actions: `{action_summary.get('action_count', 0)}`",
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
    if action_summary.get("by_status"):
        lines.extend([
            "",
            "## Action Summary",
            "",
            "| Status | Checks |",
            "| --- | --- |",
        ])
        for status, checks_for_status in action_summary["by_status"].items():
            lines.append(f"| {escape_cell(status)} | {escape_cell(', '.join(checks_for_status))} |")
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
    if action_summary.get("top_actions"):
        lines.extend([
            "",
            "## Operator Flow",
            "",
            "See `onboarding-operator-flow.md` for the staged first-run sequence.",
        ])
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
    parser.add_argument("--vm-hosts", default="", help="Optional space- or comma-separated SSH targets for concrete VM connectivity checks.")
    parser.add_argument("--check-results", default="", help="Optional JSON check result list to merge into the onboarding report.")
    args = parser.parse_args()
    manifest = build_bundle(args)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
