#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.release_security_local_gate.v1"


def load_manifest_module() -> Any:
    path = Path(__file__).with_name("security-scan-manifest.py")
    spec = importlib.util.spec_from_file_location("security_scan_manifest", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git_value(repo: Path, args: list[str], fallback: str = "") -> str:
    try:
        result = subprocess.run(["git", *args], cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    except (OSError, subprocess.CalledProcessError):
        return fallback
    return result.stdout.strip().splitlines()[0] if result.stdout.strip() else fallback


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def write_attempt(path: Path, record: dict[str, Any]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "schema": "providapt.security_scan_attempt.v1",
        "generated_at": now(),
        **record,
    }
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return record


def command_label(command: list[str]) -> str:
    return " ".join(command)


def run_command(command: list[str], cwd: Path, stdout_path: Path, stderr_path: Path, timeout: int) -> dict[str, Any]:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
        try:
            proc = subprocess.run(command, cwd=cwd, stdout=stdout, stderr=stderr, text=True, timeout=timeout, check=False)
            exit_code = proc.returncode
            status = "pass" if exit_code == 0 and stdout_path.exists() and stdout_path.stat().st_size > 0 else "failed"
            error = ""
        except subprocess.TimeoutExpired as exc:
            exit_code = 124
            status = "timeout"
            error = f"command timed out after {timeout}s"
            if exc.stdout:
                stdout.write(exc.stdout if isinstance(exc.stdout, str) else exc.stdout.decode(errors="replace"))
            if exc.stderr:
                stderr.write(exc.stderr if isinstance(exc.stderr, str) else exc.stderr.decode(errors="replace"))
        except OSError as exc:
            exit_code = 127
            status = "failed"
            error = str(exc)
    return {
        "status": status,
        "exit_code": exit_code,
        "duration_seconds": round(time.monotonic() - start, 3),
        "command": command_label(command),
        "output": str(stdout_path),
        "error_output": str(stderr_path),
        "error": error,
    }


def missing_tool_attempt(scanner: str, tool: str, output: Path, error_output: Path) -> dict[str, Any]:
    return {
        "scanner": scanner,
        "status": "missing_tool",
        "exit_code": 127,
        "duration_seconds": 0,
        "command": tool,
        "output": str(output),
        "error_output": str(error_output),
        "error": f"{tool} is not installed",
    }


def aggregate_attempt(scanner: str, attempts: list[dict[str, Any]], output: Path, error_output: Path) -> dict[str, Any]:
    statuses = [str(attempt.get("status") or "failed") for attempt in attempts]
    if all(status == "pass" for status in statuses):
        status = "pass"
    elif any(status == "timeout" for status in statuses):
        status = "timeout"
    elif any(status == "missing_tool" for status in statuses):
        status = "missing_tool"
    else:
        status = "failed"
    exit_codes = [int(attempt.get("exit_code") or 0) for attempt in attempts]
    errors = [str(attempt.get("error") or "").strip() for attempt in attempts if str(attempt.get("error") or "").strip()]
    return {
        "scanner": scanner,
        "status": status,
        "exit_code": 0 if status == "pass" else next((code for code in exit_codes if code != 0), 1),
        "duration_seconds": round(sum(float(attempt.get("duration_seconds") or 0) for attempt in attempts), 3),
        "command": " && ".join(str(attempt.get("command") or "") for attempt in attempts),
        "output": str(output),
        "error_output": str(error_output),
        "error": "; ".join(errors),
        "steps": attempts,
    }


def run_govulncheck(args: argparse.Namespace, security_dir: Path, project_dir: Path) -> dict[str, Any]:
    output = security_dir / "govulncheck.txt"
    json_output = security_dir / "govulncheck.json"
    error_output = security_dir / "govulncheck.err"
    json_error = security_dir / "govulncheck-json.err"
    if shutil.which("govulncheck") is None:
        return write_attempt(
            security_dir / "govulncheck-attempt.json",
            missing_tool_attempt("govulncheck", "govulncheck", output, error_output),
        )
    tags = args.go_tags
    text_command = ["govulncheck", f"-tags={tags}", "./..."] if tags else ["govulncheck", "./..."]
    json_command = ["govulncheck", "-json", f"-tags={tags}", "./..."] if tags else ["govulncheck", "-json", "./..."]
    text_attempt = run_command(text_command, project_dir, output, error_output, args.timeout)
    json_attempt = run_command(json_command, project_dir, json_output, json_error, args.timeout)
    return write_attempt(
        security_dir / "govulncheck-attempt.json",
        aggregate_attempt("govulncheck", [text_attempt, json_attempt], output, error_output),
    )


def run_grype(args: argparse.Namespace, security_dir: Path, project_dir: Path) -> dict[str, Any]:
    output = security_dir / "grype-source.json"
    error_output = security_dir / "grype-source.err"
    if shutil.which("grype") is None:
        return write_attempt(
            security_dir / "grype-source-attempt.json",
            missing_tool_attempt("grype_source", "grype", output, error_output),
        )
    command = ["grype", f"dir:{project_dir}", "-o", "json"]
    return write_attempt(
        security_dir / "grype-source-attempt.json",
        {"scanner": "grype_source", **run_command(command, project_dir, output, error_output, args.timeout)},
    )


def run_trivy(args: argparse.Namespace, security_dir: Path, project_dir: Path) -> dict[str, Any]:
    output = security_dir / "trivy-fs.json"
    error_output = security_dir / "trivy-fs.err"
    if shutil.which("trivy") is None:
        return write_attempt(
            security_dir / "trivy-fs-attempt.json",
            missing_tool_attempt("trivy_fs", "trivy", output, error_output),
        )
    command = ["trivy", "fs", "--format", "json", "--output", str(output), str(project_dir)]
    attempt = run_command(command, project_dir, Path(os.devnull), error_output, args.timeout)
    attempt["output"] = str(output)
    if attempt["exit_code"] == 0 and output.exists() and output.stat().st_size > 0:
        attempt["status"] = "pass"
    return write_attempt(
        security_dir / "trivy-fs-attempt.json",
        {"scanner": "trivy_fs", **attempt},
    )


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Release Security Local Gate",
        "",
        f"- Status: `{report['status']}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Version: `{report['version']}`",
        f"- Commit: `{report['full_commit']}`",
        f"- Manifest: `{report['manifest_path']}`",
        "",
        "| Scanner | Status | Exit Code | Duration | Output | Error |",
        "| --- | --- | ---: | ---: | --- | --- |",
    ]
    for attempt in report["attempts"]:
        lines.append(
            "| `{scanner}` | `{status}` | {exit_code} | {duration} | `{output}` | {error} |".format(
                scanner=attempt.get("scanner", ""),
                status=attempt.get("status", ""),
                exit_code=attempt.get("exit_code", ""),
                duration=attempt.get("duration_seconds", ""),
                output=attempt.get("output", ""),
                error=str(attempt.get("error") or "").replace("|", "\\|").replace("\n", " "),
            )
        )
    if report["blocked"]:
        lines.extend(["", "## Blocked Items", ""])
        lines.extend(f"- `{item}`" for item in report["blocked"])
    if report["next_actions"]:
        lines.extend(["", "## Next Actions", ""])
        lines.extend(f"- {item}" for item in report["next_actions"])
    lines.append("")
    return "\n".join(lines)


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    project_dir = Path(args.project_dir).resolve()
    security_dir = Path(args.security_dir)
    security_dir.mkdir(parents=True, exist_ok=True)
    attempts = []
    if not args.skip_govulncheck:
        attempts.append(run_govulncheck(args, security_dir, project_dir))
    if not args.skip_grype:
        attempts.append(run_grype(args, security_dir, project_dir))
    if not args.skip_trivy:
        attempts.append(run_trivy(args, security_dir, project_dir))

    manifest_module = load_manifest_module()
    manifest_args = argparse.Namespace(
        security_dir=str(security_dir),
        version=args.version,
        commit=args.commit,
        full_commit=args.full_commit,
        allow_partial=True,
        out_json=str(security_dir / "scan-manifest.json"),
        out_md=str(security_dir / "scan-manifest.md"),
    )
    manifest = manifest_module.build_report(manifest_args)
    Path(manifest_args.out_json).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    Path(manifest_args.out_md).write_text(manifest_module.render_markdown(manifest), encoding="utf-8")

    blocked = sorted(set(manifest.get("missing_reports", []) + manifest.get("invalid_reports", [])))
    failed_attempts = [attempt for attempt in attempts if attempt.get("status") not in {"pass"}]
    status = "pass" if manifest.get("status") == "pass" and not failed_attempts else "blocked"
    next_actions: list[str] = []
    if failed_attempts:
        next_actions.append("Install missing scanners or rerun failed scanners after fixing local database/network access.")
    if blocked:
        next_actions.append("Regenerate complete scanner reports or attach an approved waiver through make release-gates RELEASE_WAIVER=...")
    return {
        "schema": SCHEMA,
        "generated_at": now(),
        "version": manifest.get("version"),
        "commit": manifest.get("commit"),
        "full_commit": manifest.get("full_commit"),
        "status": status,
        "security_dir": str(security_dir),
        "manifest_path": manifest_args.out_json,
        "manifest_status": manifest.get("status"),
        "blocked": blocked,
        "attempts": attempts,
        "next_actions": next_actions,
    }


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run local release security scanners and generate structured scan evidence.")
    p.add_argument("--project-dir", default=".")
    p.add_argument("--security-dir", default="build/security")
    p.add_argument("--version", default="")
    p.add_argument("--commit", default="")
    p.add_argument("--full-commit", default="")
    p.add_argument("--go-tags", default="bpf")
    p.add_argument("--timeout", type=int, default=900)
    p.add_argument("--skip-govulncheck", action="store_true")
    p.add_argument("--skip-grype", action="store_true")
    p.add_argument("--skip-trivy", action="store_true")
    p.add_argument("--allow-partial", action="store_true")
    p.add_argument("--out-json", default="build/security/release-security-local-gate.json")
    p.add_argument("--out-md", default="build/security/release-security-local-gate.md")
    return p


def main() -> int:
    args = parser().parse_args()
    repo = Path(args.project_dir).resolve()
    if not args.full_commit:
        args.full_commit = git_value(repo, ["rev-parse", "HEAD"], "unknown")
    if not args.commit:
        args.commit = git_value(repo, ["rev-parse", "--short", "HEAD"], str(args.full_commit)[:12])
    if not args.version:
        args.version = git_value(repo, ["describe", "--tags", "--always"], args.commit)
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} manifest={report['manifest_status']} blocked={len(report['blocked'])}")
    return 0 if report["status"] == "pass" or args.allow_partial else 1


if __name__ == "__main__":
    raise SystemExit(main())
