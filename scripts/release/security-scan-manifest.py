#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.security_scan_manifest.v1"
REPORTS = {
    "govulncheck_text": "govulncheck.txt",
    "govulncheck_json": "govulncheck.json",
    "grype_source": "grype-source.json",
    "trivy_fs": "trivy-fs.json",
}


def git_value(args: list[str], fallback: str = "") -> str:
    try:
        result = subprocess.run(["git", *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    except (OSError, subprocess.CalledProcessError):
        return fallback
    return result.stdout.strip().splitlines()[0] if result.stdout.strip() else fallback


def file_record(path: Path) -> dict[str, Any]:
    present = path.exists() and path.stat().st_size > 0
    record: dict[str, Any] = {
        "path": str(path),
        "present": present,
        "size_bytes": path.stat().st_size if path.exists() else 0,
        "status": "present" if present else "missing",
    }
    if present and path.suffix == ".json":
        try:
            json.loads(path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as exc:
            if not is_json_stream(path):
                record["status"] = "invalid_json"
                record["error"] = str(exc)
    return record


def is_json_stream(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError:
        return False
    decoder = json.JSONDecoder()
    index = 0
    saw_value = False
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        try:
            _, index = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            return False
        saw_value = True
    return saw_value


def tool_versions() -> dict[str, dict[str, str]]:
    versions: dict[str, dict[str, str]] = {}
    commands = {
        "govulncheck": ["govulncheck", "-version"],
        "grype": ["grype", "version", "-o", "json"],
        "trivy": ["trivy", "--version"],
    }
    for name, command in commands.items():
        path = shutil.which(name)
        record = {"path": path or "", "version": ""}
        if path:
            try:
                result = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
                record["version"] = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
            except (OSError, subprocess.TimeoutExpired):
                record["version"] = ""
        versions[name] = record
    return versions


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    security_dir = Path(args.security_dir)
    records = {name: file_record(security_dir / filename) for name, filename in REPORTS.items()}
    reports = {name: "present" if record["status"] == "present" else "missing" for name, record in records.items()}
    invalid = [name for name, record in records.items() if record["status"] == "invalid_json"]
    missing = [name for name, status in reports.items() if status != "present"]
    status = "pass" if not missing and not invalid else "blocked"
    full_commit = args.full_commit or git_value(["rev-parse", "HEAD"], "unknown")
    short_commit = args.commit or git_value(["rev-parse", "--short", "HEAD"], full_commit[:12])
    version = args.version or git_value(["describe", "--tags", "--always"], short_commit)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "version": version,
        "commit": short_commit,
        "full_commit": full_commit,
        "status": status,
        "reports": reports,
        "report_details": records,
        "missing_reports": missing,
        "invalid_reports": invalid,
        "tools": tool_versions(),
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Security Scan Manifest",
        "",
        f"- Status: `{report['status']}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Version: `{report['version']}`",
        f"- Commit: `{report['full_commit']}`",
        "",
        "| Report | Status | Size | Path |",
        "| --- | --- | ---: | --- |",
    ]
    for name, record in report["report_details"].items():
        lines.append(f"| `{name}` | `{record['status']}` | {record['size_bytes']} | `{record['path']}` |")
    if report["missing_reports"]:
        lines.extend(["", "## Missing Reports", ""])
        lines.extend(f"- `{name}`" for name in report["missing_reports"])
    if report["invalid_reports"]:
        lines.extend(["", "## Invalid Reports", ""])
        lines.extend(f"- `{name}`" for name in report["invalid_reports"])
    lines.append("")
    return "\n".join(lines)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Generate a current-commit security scan manifest from existing scanner outputs.")
    p.add_argument("--security-dir", default="build/security")
    p.add_argument("--version", default="")
    p.add_argument("--commit", default="")
    p.add_argument("--full-commit", default="")
    p.add_argument("--allow-partial", action="store_true")
    p.add_argument("--out-json", default="build/security/scan-manifest.json")
    p.add_argument("--out-md", default="build/security/scan-manifest.md")
    return p


def main() -> int:
    args = parser().parse_args()
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} missing={len(report['missing_reports'])} invalid={len(report['invalid_reports'])}")
    return 0 if report["status"] == "pass" or args.allow_partial else 1


if __name__ == "__main__":
    raise SystemExit(main())
