#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.support_diagnostics.v1"
SECRET_KEY_RE = re.compile(r"(api[_-]?key|token|secret|password|dsn|credential)", re.IGNORECASE)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_json(path: str) -> dict[str, Any]:
    if not path:
        return {}
    target = Path(path)
    if not target.exists():
        return {}
    try:
        data = json.loads(target.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def redact_line(line: str) -> tuple[str, str]:
    if "=" in line:
        key, _value = line.split("=", 1)
        if SECRET_KEY_RE.search(key):
            return key.strip(), key + "=<redacted>"
    if ":" in line:
        key, _value = line.split(":", 1)
        if SECRET_KEY_RE.search(key):
            return key.strip(), key + ": <redacted>"
    return "", line.rstrip("\n")


def config_summary(path: str) -> dict[str, Any]:
    target = Path(path) if path else None
    if not target or not target.exists():
        return {"path": str(target) if target else "", "present": False, "redacted_keys": [], "line_count": 0, "preview": []}
    redacted_keys: list[str] = []
    preview: list[str] = []
    for line in target.read_text(encoding="utf-8", errors="replace").splitlines():
        key, redacted = redact_line(line)
        if key:
            redacted_keys.append(key)
        if len(preview) < 40:
            preview.append(redacted)
    return {
        "path": str(target),
        "present": True,
        "redacted_keys": sorted(dict.fromkeys(redacted_keys)),
        "line_count": len(target.read_text(encoding="utf-8", errors="replace").splitlines()),
        "preview": preview,
    }


def log_summary(path: str) -> dict[str, Any]:
    target = Path(path) if path else None
    if not target or not target.exists():
        return {"path": str(target) if target else "", "present": False, "error_lines": 0, "warning_lines": 0, "tail": []}
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    safe_tail = [redact_line(line)[1] for line in lines[-80:]]
    return {
        "path": str(target),
        "present": True,
        "error_lines": sum(1 for line in lines if "error" in line.lower()),
        "warning_lines": sum(1 for line in lines if "warn" in line.lower()),
        "tail": safe_tail,
    }


def disk_summary(paths: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for value in paths:
        target = Path(value)
        if not target.exists():
            rows.append({"path": value, "present": False})
            continue
        usage = shutil.disk_usage(target)
        rows.append({
            "path": str(target),
            "present": True,
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "used_percent": round(usage.used * 100.0 / usage.total, 2) if usage.total else 0.0,
        })
    return rows


def port_summary(ports: list[str]) -> dict[str, dict[str, str]]:
    return {str(port): {"status": "not_checked", "note": "port ownership is checked in VM runbooks"} for port in ports}


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    status = load_json(args.status_json)
    report = {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "status": "pass",
        "version": {
            "version": status.get("version", ""),
            "commit": status.get("commit", ""),
        },
        "fleet": {
            "agent_count": len(status.get("agents", [])) if isinstance(status.get("agents"), list) else 0,
        },
        "connectivity": {
            "server_url": args.server_url,
            "status": "not_checked" if args.server_url else "not_configured",
        },
        "ports": port_summary(args.port or []),
        "disks": disk_summary(args.disk_path or []),
        "config": config_summary(args.config),
        "logs": log_summary(args.log),
    }
    if not report["config"]["present"] and not report["logs"]["present"] and not status:
        report["status"] = "warn"
    return report


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Support Diagnostics",
        "",
        f"- Status: `{report['status']}`",
        f"- Version: `{report['version']['version'] or 'unknown'}`",
        f"- Commit: `{report['version']['commit'] or 'unknown'}`",
        f"- Agents: `{report['fleet']['agent_count']}`",
        f"- Server URL: `{report['connectivity']['server_url'] or 'not configured'}`",
        f"- Redacted config keys: `{', '.join(report['config']['redacted_keys']) or 'none'}`",
        f"- Log errors: `{report['logs']['error_lines']}`",
        "",
        "## Ports",
        "",
        "| Port | Status | Note |",
        "| --- | --- | --- |",
    ]
    for port, item in sorted(report["ports"].items()):
        lines.append(f"| {port} | {item['status']} | {item['note']} |")
    lines.extend(["", "## Disks", "", "| Path | Used | Free |", "| --- | ---: | ---: |"])
    for disk in report["disks"]:
        if disk.get("present"):
            lines.append(f"| {disk['path']} | {disk['used_percent']}% | {disk['free_bytes']} |")
        else:
            lines.append(f"| {disk['path']} | missing | missing |")
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a redacted ProvidAPT one-click support diagnostics report.")
    parser.add_argument("--status-json", default="")
    parser.add_argument("--config", default="")
    parser.add_argument("--log", default="")
    parser.add_argument("--server-url", default="")
    parser.add_argument("--port", action="append", default=[])
    parser.add_argument("--disk-path", action="append", default=[])
    parser.add_argument("--out-json", default="build/support/support-diagnostics.json")
    parser.add_argument("--out-md", default="build/support/support-diagnostics.md")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"support diagnostics: status={report['status']} agents={report['fleet']['agent_count']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
