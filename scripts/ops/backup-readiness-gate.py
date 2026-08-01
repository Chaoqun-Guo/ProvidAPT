#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.backup_readiness_gate.v1"


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


def has_history_action(items: list[dict[str, Any]], action_fragments: tuple[str, ...], statuses: set[str]) -> bool:
    for item in items:
        action = str(item.get("action") or item.get("message") or "").lower()
        status = str(item.get("status") or "").lower()
        if all(fragment in action for fragment in action_fragments) and (not statuses or status in statuses):
            return True
    return False


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    summary = load_json(Path(args.backup_summary))
    items = history(summary)
    failures: list[str] = []
    warnings: list[str] = []
    if not summary:
        failures.append("backup summary evidence is missing")
    if not str(summary.get("last_backup_path") or "").strip():
        failures.append("no backup archive path recorded")
    if int(summary.get("size_bytes") or 0) < args.min_backup_bytes:
        failures.append(f"backup size below minimum {args.min_backup_bytes} bytes")
    if str(summary.get("last_status") or "").lower() in {"failed", "error", "blocked"}:
        failures.append("latest backup action failed")
    if args.require_restore and not str(summary.get("last_restore_path") or "").strip():
        failures.append("restore staging path is missing")
    if args.require_restore and not has_history_action(items, ("restore",), {"restored_staging", "success", "pass"}):
        failures.append("restore staging history is missing")
    if args.require_cutover and not has_history_action(items, ("cutover",), {"cutover_ready", "success", "pass"}):
        failures.append("cutover preparation history is missing")
    if args.require_download and not str(summary.get("download_url") or "").strip():
        failures.append("backup download URL is missing")
    if not items:
        warnings.append("backup audit history is empty")
    status = "pass" if not failures else "blocked"
    if status == "pass" and warnings:
        status = "warn"
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "last_backup_path": summary.get("last_backup_path", ""),
        "last_restore_path": summary.get("last_restore_path", ""),
        "last_status": summary.get("last_status", ""),
        "size_bytes": int(summary.get("size_bytes") or 0),
        "history_count": len(items),
        "restore_required": args.require_restore,
        "cutover_required": args.require_cutover,
        "failures": failures,
        "warnings": warnings,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Backup Readiness Gate",
        "",
        f"- Status: `{report['status']}`",
        f"- Backup: `{report['last_backup_path']}`",
        f"- Restore staging: `{report['last_restore_path']}`",
        f"- Size: `{report['size_bytes']}` bytes",
        f"- History entries: `{report['history_count']}`",
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
    parser = argparse.ArgumentParser(description="Gate backup, restore staging, and cutover-readiness evidence.")
    parser.add_argument("--backup-summary", default="build/backup/backup-summary.json")
    parser.add_argument("--min-backup-bytes", type=int, default=1)
    parser.add_argument("--require-restore", action="store_true")
    parser.add_argument("--require-cutover", action="store_true")
    parser.add_argument("--require-download", action="store_true")
    parser.add_argument("--out-json", default="build/backup/backup-readiness-gate.json")
    parser.add_argument("--out-md", default="build/backup/backup-readiness-gate.md")
    args = parser.parse_args()
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"backup readiness gate: status={report['status']} size={report['size_bytes']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
