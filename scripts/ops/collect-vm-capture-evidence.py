#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


SCHEMA = "providapt.vm_capture_evidence.v1"
EVENT_GLOBS = ("providapt-*.ndjson", "providapt-*.jsonl")


Runner = Callable[[list[str], float], subprocess.CompletedProcess[str]]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def default_runner(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, text=True, capture_output=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(cmd, 124, exc.stdout or "", exc.stderr or f"timeout after {timeout}s")


def safe_host_label(host: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in host)


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def remote_list_command(remote_dir: str) -> str:
    quoted = remote_dir.replace("'", "'\"'\"'")
    patterns = " ".join(f"'{quoted}/{pattern}'" for pattern in EVENT_GLOBS)
    return f"sh -lc 'ls -1t {patterns} 2>/dev/null || true'"


def collect_host(
    host: str,
    remote_dir: str,
    out_dir: Path,
    timeout: float,
    max_files: int,
    lines_per_file: int,
    network_lines: int,
    runner: Runner = default_runner,
) -> dict[str, Any]:
    host_dir = out_dir / safe_host_label(host)
    host_dir.mkdir(parents=True, exist_ok=True)
    ssh_opts = ["-o", "BatchMode=yes", "-o", f"ConnectTimeout={max(1, int(timeout))}"]
    listing = runner(["ssh", *ssh_opts, host, remote_list_command(remote_dir)], timeout)
    files = [line.strip() for line in listing.stdout.splitlines() if line.strip()]
    selected_files = files[:max_files] if max_files > 0 else files
    copied: list[str] = []
    failures: list[str] = []
    if listing.returncode != 0:
        failures.append(f"ssh list failed: {listing.stderr.strip() or listing.returncode}")
    for remote_file in selected_files:
        local = host_dir / Path(remote_file).name
        tail_cmd = f"sh -lc 'tail -n {int(lines_per_file)} {shell_quote(remote_file)}'"
        copy = runner(["ssh", *ssh_opts, host, tail_cmd], timeout)
        if copy.returncode == 0 and copy.stdout.strip():
            local.write_text(copy.stdout if copy.stdout.endswith("\n") else copy.stdout + "\n", encoding="utf-8")
            copied.append(str(local))
        else:
            failures.append(f"sample copy failed for {remote_file}: {copy.stderr.strip() or copy.returncode}")
    if selected_files and network_lines > 0:
        network_local = host_dir / "network-sample.ndjson"
        grep_files = " ".join(shell_quote(path) for path in selected_files)
        network_cmd = f"sh -lc 'grep -h \"\\\"type\\\":\\\"net_\" {grep_files} 2>/dev/null | tail -n {int(network_lines)} || true'"
        network = runner(["ssh", *ssh_opts, host, network_cmd], timeout)
        if network.returncode == 0 and network.stdout.strip():
            network_local.write_text(network.stdout if network.stdout.endswith("\n") else network.stdout + "\n", encoding="utf-8")
            copied.append(str(network_local))
    return {
        "host": host,
        "remote_dir": remote_dir,
        "listed_files": files,
        "selected_files": selected_files,
        "lines_per_file": lines_per_file,
        "network_lines": network_lines,
        "copied_files": copied,
        "status": "pass" if copied and not failures else "blocked",
        "failures": failures or ([] if copied else ["no event NDJSON/JSONL files copied"]),
    }


def run_capture_gate(out_dir: Path, timeout: float, runner: Runner = default_runner) -> dict[str, Any]:
    events_dir = out_dir / "events"
    if events_dir.exists():
        shutil.rmtree(events_dir)
    events_dir.mkdir(parents=True, exist_ok=True)
    for path in out_dir.glob("*/*"):
        if path.suffix in {".ndjson", ".jsonl"} and path.parent.name != "events":
            target = events_dir / f"{path.parent.name}-{path.name}"
            if target.exists():
                target.unlink()
            shutil.copy2(path, target)
    cmd = [
        sys.executable,
        "scripts/ops/capture-enrichment-field-gate.py",
        "--events",
        str(events_dir),
        "--out-json",
        str(out_dir / "capture-enrichment-field-gate.json"),
        "--out-md",
        str(out_dir / "capture-enrichment-field-gate.md"),
    ]
    result = runner(cmd, timeout)
    report_path = out_dir / "capture-enrichment-field-gate.json"
    report: dict[str, Any] = {}
    if report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
    return {
        "command": cmd,
        "returncode": result.returncode,
        "stdout": result.stdout[-2000:],
        "stderr": result.stderr[-2000:],
        "report": report,
    }


def build_report(args: argparse.Namespace, runner: Runner = default_runner) -> dict[str, Any]:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    hosts = [
        collect_host(host, args.remote_dir, out_dir, args.timeout_seconds, args.max_files, args.lines_per_file, args.network_lines, runner)
        for host in args.host
    ]
    failures = [f"{item['host']}: {failure}" for item in hosts for failure in item["failures"]]
    gate_result: dict[str, Any] = {}
    if not args.skip_gate:
        gate_result = run_capture_gate(out_dir, args.gate_timeout_seconds, runner)
        gate_status = str((gate_result.get("report") or {}).get("status") or "")
        if gate_result.get("returncode") != 0 or gate_status == "blocked":
            failures.append("capture enrichment field gate did not pass")
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "status": "blocked" if failures else "pass",
        "remote_dir": args.remote_dir,
        "hosts": hosts,
        "capture_gate": gate_result,
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# VM Capture Evidence",
        "",
        f"- Status: `{report['status']}`",
        f"- Remote dir: `{report['remote_dir']}`",
        "",
        "| Host | Status | Files copied |",
        "| --- | --- | ---: |",
    ]
    for host in report["hosts"]:
        lines.append(f"| {host['host']} | {host['status']} | {len(host['copied_files'])} |")
    gate = report.get("capture_gate") or {}
    if gate:
        lines.extend(["", f"- Capture enrichment gate: `{(gate.get('report') or {}).get('status', 'unknown')}`"])
    if report["failures"]:
        lines.extend(["", "## Failures", ""])
        lines.extend(f"- {item}" for item in report["failures"])
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect real ProvidAPT NDJSON capture evidence from VM hosts over SSH/SCP.")
    parser.add_argument("--host", action="append", required=True)
    parser.add_argument("--remote-dir", default="/var/log/providapt")
    parser.add_argument("--out-dir", default="build/vm-capture-evidence")
    parser.add_argument("--timeout-seconds", type=float, default=15.0)
    parser.add_argument("--gate-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--max-files", type=int, default=5, help="Maximum latest event files to sample per host; 0 means all listed files")
    parser.add_argument("--lines-per-file", type=int, default=5000, help="Tail this many lines from each selected remote file")
    parser.add_argument("--network-lines", type=int, default=200, help="Also collect up to this many net_* lines from selected files per host")
    parser.add_argument("--skip-gate", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = build_report(args)
    out_dir = Path(args.out_dir)
    out_json = out_dir / "vm-capture-evidence.json"
    out_md = out_dir / "vm-capture-evidence.md"
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"vm capture evidence: status={report['status']} hosts={len(report['hosts'])}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
