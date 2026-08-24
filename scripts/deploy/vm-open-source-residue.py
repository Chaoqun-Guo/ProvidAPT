#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.vm_open_source_residue.v1"

FORBIDDEN_MARKERS = [
    "providapt-auth-server",
    "providapt-auth-",
    "30-api-auth.conf",
    "90-api-key-rotation.conf",
    "PROVIDAPT_" + "API_AUTH_ENABLED",
    "PROVIDAPT_" + "AUTH_ENABLED",
    "auth_" + "enabled",
    "api" + "KeyInput",
    "providapt_api_" + "key",
    "X-" + "API-" + "Key",
    "local API " + "policy",
    "missing or invalid " + "API " + "key",
]

SSH_COMMAND = (
    "hostname; "
    "ps -eo user,pid,ppid,comm,args 2>/dev/null | grep -E 'providapt|activation|license|api-key|auth-server' | grep -v grep || true; "
    "systemctl --no-pager --type=service --all 2>/dev/null | grep -i providapt || true; "
    "ls -la /etc/systemd/system/providapt.service.d /lib/systemd/system/providapt.service.d "
    "/usr/lib/systemd/system/providapt.service.d 2>/dev/null || true"
)

CLEANUP_SCRIPT = """#!/usr/bin/env bash
set -euo pipefail

dropin_dir="/etc/systemd/system/providapt.service.d"
if [ -d "$dropin_dir" ]; then
  rm -f "$dropin_dir/30-api-auth.conf" "$dropin_dir/90-api-key-rotation.conf"
fi

if command -v pkill >/dev/null 2>&1; then
  pkill -f '/providapt-auth-server|providapt-auth-server|activation-server|license-server' 2>/dev/null || true
fi

systemctl daemon-reload
systemctl restart providapt.service
systemctl --no-pager --full status providapt.service
"""


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def run_ssh(host: str, timeout: int) -> dict[str, Any]:
    command = ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={timeout}", host, SSH_COMMAND]
    proc = subprocess.run(command, text=True, capture_output=True, timeout=timeout + 8, check=False)
    output = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
    return {
        "host": host,
        "status": "pass" if proc.returncode == 0 else "blocked",
        "returncode": proc.returncode,
        "output": output,
        "findings": marker_findings(output),
    }


def marker_findings(text: str) -> list[str]:
    lower_text = text.lower()
    return [marker for marker in FORBIDDEN_MARKERS if marker.lower() in lower_text]


def fetch_text(url: str, timeout: float = 10.0) -> tuple[int, str, str]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", errors="replace"), response.headers.get("content-type", "")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace"), exc.headers.get("content-type", "")


def check_http(base_url: str) -> dict[str, Any]:
    endpoints = [
        "/dashboard",
        "/assets/dashboard.js",
        "/assets/dashboard-api.js",
        "/assets/trace-viewer.js",
        "/api/v1/status",
        "/api/v1/control/policies",
        "/api/v1/evaluation/ground-truth?limit=500",
    ]
    failures: list[str] = []
    checks: list[dict[str, Any]] = []
    for endpoint in endpoints:
        url = base_url.rstrip("/") + endpoint
        try:
            status, body, content_type = fetch_text(url)
        except urllib.error.URLError as exc:
            failures.append(f"{endpoint}: fetch failed: {exc}")
            checks.append({"endpoint": endpoint, "status": "blocked", "error": str(exc)})
            continue
        findings = marker_findings(body)
        if status in (401, 403):
            failures.append(f"{endpoint}: HTTP {status}")
        if findings:
            failures.append(f"{endpoint}: legacy markers {', '.join(findings)}")
        checks.append({
            "endpoint": endpoint,
            "http_status": status,
            "content_type": content_type,
            "legacy_markers": findings,
        })
    return {"base_url": base_url, "status": "pass" if not failures else "blocked", "checks": checks, "failures": failures}


def load_snapshot(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    return {
        "host": path.name,
        "status": "pass",
        "returncode": 0,
        "output": text,
        "findings": marker_findings(text),
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    host_reports: list[dict[str, Any]] = []
    for path in args.snapshot:
        host_reports.append(load_snapshot(Path(path)))
    for host in args.host:
        host_reports.append(run_ssh(host, args.timeout_seconds))
    http_report = check_http(args.server_url) if args.server_url else None
    failures: list[str] = []
    for host in host_reports:
        if host["status"] != "pass":
            failures.append(f"{host['host']}: ssh check failed with {host['returncode']}")
        if host["findings"]:
            failures.append(f"{host['host']}: legacy markers {', '.join(host['findings'])}")
    if http_report and http_report["status"] != "pass":
        failures.extend(http_report["failures"])
    return {
        "schema": SCHEMA,
        "generated_at": now(),
        "status": "pass" if not failures else "blocked",
        "hosts": host_reports,
        "http": http_report,
        "forbidden_markers": FORBIDDEN_MARKERS,
        "failures": failures,
        "remediation": [
            "Remove stale API auth/key systemd drop-ins from providapt.service.d.",
            "Stop and disable any providapt-auth-server or activation server process.",
            "Restart providapt.service after confirming REST binds to the open-source daemon.",
            "Verify /dashboard and control-plane API endpoints return HTTP 200 without legacy access headers.",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT VM Open Source Residue Check",
        "",
        f"- Status: `{report['status']}`",
        f"- Generated: `{report['generated_at']}`",
        "",
    ]
    if report["failures"]:
        lines.extend(["## Failures", ""])
        lines.extend(f"- {item}" for item in report["failures"])
        lines.append("")
    lines.extend(["## Hosts", "", "| Host | Status | Legacy markers |", "| --- | --- | --- |"])
    for host in report["hosts"]:
        markers = ", ".join(host["findings"]) if host["findings"] else "none"
        lines.append(f"| `{host['host']}` | `{host['status']}` | `{markers}` |")
    if report.get("http"):
        lines.extend(["", "## HTTP Checks", "", "| Endpoint | HTTP | Legacy markers |", "| --- | ---: | --- |"])
        for check in report["http"]["checks"]:
            markers = ", ".join(check.get("legacy_markers") or []) or "none"
            lines.append(f"| `{check['endpoint']}` | `{check.get('http_status', 'blocked')}` | `{markers}` |")
    lines.extend(["", "## Remediation", ""])
    lines.extend(f"- {item}" for item in report["remediation"])
    if report.get("cleanup_script"):
        lines.extend([
            "",
            "## Cleanup Script",
            "",
            f"`{report['cleanup_script']}`",
            "",
            "Run this script on each affected VM with sudo, then rerun the residue check.",
        ])
    lines.append("")
    return "\n".join(lines)


def write_cleanup_script(path_value: str) -> str:
    if not path_value:
        return ""
    path = Path(path_value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(CLEANUP_SCRIPT, encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect VM residue from removed commercial/API-key control-plane features.")
    parser.add_argument("--host", action="append", default=[], help="SSH target, for example ubuntu@vm-ubuntu-master.")
    parser.add_argument("--snapshot", action="append", default=[], help="Local text snapshot to scan instead of SSH.")
    parser.add_argument("--server-url", default="", help="Optional control-plane URL to scan over HTTP.")
    parser.add_argument("--timeout-seconds", type=int, default=12)
    parser.add_argument("--emit-cleanup-script", default="", help="Write a sudo cleanup helper for affected VMs.")
    parser.add_argument("--out-json", default="build/deploy/vm-open-source-residue.json")
    parser.add_argument("--out-md", default="build/deploy/vm-open-source-residue.md")
    args = parser.parse_args()
    report = build_report(args)
    cleanup_script = write_cleanup_script(args.emit_cleanup_script)
    if cleanup_script:
        report["cleanup_script"] = cleanup_script
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} hosts={len(report['hosts'])} failures={len(report['failures'])}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
