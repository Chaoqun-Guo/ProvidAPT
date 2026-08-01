#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.support_bundle_gate.v1"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    return data if isinstance(data, dict) else {}


def history(summary: dict[str, Any]) -> list[dict[str, Any]]:
    items = summary.get("history")
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    summary = load_json(Path(args.support_summary))
    items = history(summary)
    failures: list[str] = []
    warnings: list[str] = []
    archive_path = str(summary.get("last_archive_path") or "").strip()
    bundle_path = str(summary.get("last_bundle_path") or "").strip()
    if not summary:
        failures.append("support bundle summary evidence is missing")
    if not archive_path and args.require_archive:
        failures.append("support bundle archive path is missing")
    if args.check_files and archive_path and not Path(archive_path).exists():
        failures.append(f"support bundle archive does not exist: {archive_path}")
    if args.check_files and bundle_path and not Path(bundle_path).exists():
        failures.append(f"support bundle directory does not exist: {bundle_path}")
    if args.require_redacted and not bool(summary.get("redacted")):
        failures.append("support bundle archive must be redacted")
    last_status = str(summary.get("last_status") or "").lower()
    if last_status in {"failed", "error", "blocked"}:
        failures.append("latest support bundle action failed")
    if args.require_download and not str(summary.get("download_url") or "").strip():
        failures.append("support bundle download URL is missing")
    export_events = [
        item for item in items
        if "support_bundle_export" in str(item.get("action") or "").lower()
        and str(item.get("status") or "").lower() in {"success", "archived", "created"}
    ]
    if args.require_audit and not export_events:
        failures.append("support bundle export audit history is missing")
    if not items:
        warnings.append("support bundle audit history is empty")
    status = "pass" if not failures else "blocked"
    if status == "pass" and warnings:
        status = "warn"
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "last_bundle_path": bundle_path,
        "last_archive_path": archive_path,
        "last_status": summary.get("last_status", ""),
        "redacted": bool(summary.get("redacted")),
        "history_count": len(items),
        "export_events": len(export_events),
        "failures": failures,
        "warnings": warnings,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Support Bundle Gate",
        "",
        f"- Status: `{report['status']}`",
        f"- Archive: `{report['last_archive_path']}`",
        f"- Redacted: `{report['redacted']}`",
        f"- Export audit events: `{report['export_events']}`",
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
    parser = argparse.ArgumentParser(description="Gate support bundle archive, redaction, audit, and download evidence.")
    parser.add_argument("--support-summary", default="build/support/support-bundle-summary.json")
    parser.add_argument("--require-archive", action="store_true")
    parser.add_argument("--require-redacted", action="store_true")
    parser.add_argument("--require-audit", action="store_true")
    parser.add_argument("--require-download", action="store_true")
    parser.add_argument("--check-files", action="store_true")
    parser.add_argument("--out-json", default="build/support/support-bundle-gate.json")
    parser.add_argument("--out-md", default="build/support/support-bundle-gate.md")
    args = parser.parse_args()
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"support bundle gate: status={report['status']} redacted={report['redacted']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
