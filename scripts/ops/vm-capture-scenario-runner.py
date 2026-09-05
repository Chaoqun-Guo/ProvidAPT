#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


SCHEMA = "providapt.vm_capture_scenarios.v1"
SCENARIOS = ("shell_activity", "file_mutation", "network_activity", "process_chain", "permission_change")


Runner = Callable[[list[str], float], subprocess.CompletedProcess[str]]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def default_runner(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, text=True, capture_output=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(cmd, 124, exc.stdout or "", exc.stderr or f"timeout after {timeout}s")


def build_remote_script(server_url: str, marker_prefix: str) -> str:
    marker = marker_prefix.replace("'", "").replace("/", "_")
    return f"""set -eu
marker={shell_quote(marker)}
server={shell_quote(server_url.rstrip('/'))}
workdir="/tmp/${{marker}}-$$"
mkdir -p "$workdir"
cleanup() {{ rm -rf "$workdir"; }}
trap cleanup EXIT

record() {{
  scenario="$1"
  shift
  if "$@"; then
    printf 'scenario=%s status=pass marker=%s\\n' "$scenario" "$marker"
  else
    rc="$?"
    printf 'scenario=%s status=fail rc=%s marker=%s\\n' "$scenario" "$rc" "$marker"
    return "$rc"
  fi
}}

record shell_activity sh -c 'printf "%s\\n" "$0" >/dev/null' providapt-shell-scenario
record file_mutation sh -c 'f="$1/file.txt"; printf "providapt scenario\\n" > "$f"; mv "$f" "$1/file-renamed.txt"; rm -f "$1/file-renamed.txt"' sh "$workdir"
record network_activity sh -c 'curl -fsS --max-time 3 "$1/api/v1/status" >/dev/null' sh "$server"
record process_chain sh -c 'sh -c "true"'
record permission_change sh -c 'f="$1/permission.txt"; : > "$f"; chmod 640 "$f"; chmod 600 "$f"' sh "$workdir"
"""


def parse_scenario_statuses(stdout: str) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for line in stdout.splitlines():
        fields: dict[str, str] = {}
        for token in line.strip().split():
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            fields[key] = value
        scenario = fields.get("scenario")
        status = fields.get("status")
        if scenario in SCENARIOS and status:
            statuses[scenario] = status
    return statuses


def run_host(host: str, server_url: str, marker_prefix: str, timeout: float, runner: Runner = default_runner) -> dict[str, Any]:
    marker = f"{marker_prefix}-{safe_host_label(host)}"
    remote_script = build_remote_script(server_url, marker)
    ssh_opts = ["-o", "BatchMode=yes", "-o", f"ConnectTimeout={max(1, int(timeout))}"]
    cmd = ["ssh", *ssh_opts, host, "sh", "-lc", shell_quote(remote_script)]
    result = runner(cmd, timeout)
    statuses = parse_scenario_statuses(result.stdout)
    failures: list[str] = []
    if result.returncode != 0:
        failures.append(f"scenario command failed: {result.stderr.strip() or result.returncode}")
    for scenario in SCENARIOS:
        observed = statuses.get(scenario)
        if not observed:
            failures.append(f"missing scenario {scenario}")
        elif observed != "pass":
            failures.append(f"scenario {scenario} returned {observed}")
    return {
        "host": host,
        "marker": marker,
        "scenario_statuses": statuses,
        "stdout": result.stdout[-4000:],
        "stderr": result.stderr[-4000:],
        "returncode": result.returncode,
        "status": "pass" if not failures else "blocked",
        "failures": failures,
    }


def safe_host_label(host: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in host)


def build_report(args: argparse.Namespace, runner: Runner = default_runner) -> dict[str, Any]:
    hosts = [
        run_host(host, args.server_url, args.marker_prefix, args.timeout_seconds, runner)
        for host in args.host
    ]
    failures = [f"{item['host']}: {failure}" for item in hosts for failure in item["failures"]]
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "status": "blocked" if failures else "pass",
        "server_url": args.server_url,
        "expected_scenarios": list(SCENARIOS),
        "hosts": hosts,
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# VM Capture Scenario Runner",
        "",
        f"- Status: `{report['status']}`",
        f"- Generated at: `{report['generated_at']}`",
        "",
        "| Host | Status | Scenarios |",
        "| --- | --- | --- |",
    ]
    for host in report["hosts"]:
        statuses = host.get("scenario_statuses") or {}
        scenario_text = ", ".join(f"{name}={statuses.get(name, 'missing')}" for name in SCENARIOS)
        lines.append(f"| {host['host']} | `{host['status']}` | {scenario_text} |")
    if report["failures"]:
        lines.extend(["", "## Failures", ""])
        lines.extend(f"- {item}" for item in report["failures"])
    lines.append("")
    return "\n".join(lines)


def write_outputs(report: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "vm-capture-scenarios.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "vm-capture-scenarios.md").write_text(render_markdown(report), encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run low-noise capture behavior scenarios on VM hosts over SSH.")
    parser.add_argument("--host", action="append", required=True)
    parser.add_argument("--server-url", default="http://vm-ubuntu-master:18080")
    parser.add_argument("--marker-prefix", default="providapt-capture-scenario")
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    parser.add_argument("--out-dir", default="build/vm-capture-scenarios")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = build_report(args)
    write_outputs(report, Path(args.out_dir))
    print(f"vm capture scenarios: status={report['status']} hosts={len(report['hosts'])}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
