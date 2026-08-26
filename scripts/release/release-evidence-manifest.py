#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.release_evidence_manifest.v1"
SUPPORTED_SUFFIXES = {".json", ".md"}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    if path.suffix.lower() != ".json" or not path.exists() or path.stat().st_size == 0:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def first_markdown_value(text: str, prefix: str) -> str:
    for line in text.splitlines():
        if line.lower().startswith(prefix.lower()):
            return line.split(":", 1)[1].strip().strip("`") if ":" in line else ""
    return ""


def markdown_status(path: Path) -> str:
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    status = first_markdown_value(text, "Status")
    if not status:
        return "unknown"
    normalized = status.lower()
    if "pass" in normalized or "ready" in normalized:
        return "pass"
    if "warn" in normalized:
        return "warn"
    if "block" in normalized or "fail" in normalized:
        return "blocked"
    return normalized.split()[0]


def evidence_kind(path: Path, report: dict[str, Any]) -> str:
    schema = str(report.get("schema") or "")
    if schema:
        return schema.replace("providapt.", "").replace(".v1", "")
    name = path.stem.lower()
    for prefix in ("release-", "open-source-", "vm-"):
        if name.startswith(prefix):
            return name
    return name.replace("_", "-")


def discover_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if not path.exists():
            continue
        if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES:
            files.append(path)
            continue
        if path.is_dir():
            files.extend(
                item
                for item in path.rglob("*")
                if item.is_file() and item.suffix.lower() in SUPPORTED_SUFFIXES
            )
    return sorted(set(files), key=lambda item: str(item))


def evidence_entry(path: Path, root: Path) -> dict[str, Any]:
    report = load_json(path)
    status = str(report.get("status") or report.get("source_status") or "").lower()
    if not status and path.suffix.lower() == ".md":
        status = markdown_status(path)
    if not status:
        status = "unknown"
    rel = path.relative_to(root) if path.is_relative_to(root) else path
    return {
        "path": str(rel),
        "absolute_path": str(path),
        "kind": evidence_kind(path, report),
        "format": path.suffix.lower().lstrip("."),
        "status": status,
        "schema": str(report.get("schema") or ""),
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def build_manifest(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.root).resolve()
    input_paths = [Path(item).resolve() for item in args.evidence]
    files = [path for path in discover_files(input_paths) if not should_exclude(path, args.exclude)]
    entries = [evidence_entry(path, root) for path in files]
    status_counts: dict[str, int] = {}
    for entry in entries:
        status = str(entry["status"])
        status_counts[status] = status_counts.get(status, 0) + 1
    blockers = [
        f"{entry['path']} status is {entry['status']}"
        for entry in entries
        if entry["status"] in {"blocked", "fail", "failed"}
    ]
    if args.require_evidence and not entries:
        blockers.append("release evidence manifest has no indexed evidence")
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "root": str(root),
        "status": "pass" if not blockers else "blocked",
        "evidence_count": len(entries),
        "status_counts": dict(sorted(status_counts.items())),
        "evidence": entries,
        "blockers": blockers,
    }


def should_exclude(path: Path, patterns: list[str]) -> bool:
    text = str(path)
    return any(pattern and pattern in text for pattern in patterns)


def render_markdown(manifest: dict[str, Any]) -> str:
    lines = [
        "# Release Evidence Manifest",
        "",
        f"- Status: `{manifest['status']}`",
        f"- Evidence files: `{manifest['evidence_count']}`",
        f"- Status counts: `{json.dumps(manifest['status_counts'], sort_keys=True)}`",
        "",
        "| Kind | Status | Format | SHA-256 | Path |",
        "| --- | --- | --- | --- | --- |",
    ]
    for entry in manifest["evidence"]:
        lines.append(
            f"| {entry['kind']} | {entry['status']} | {entry['format']} | "
            f"`{entry['sha256']}` | `{entry['path']}` |"
        )
    if manifest["blockers"]:
        lines.extend(["", "## Blockers", ""])
        lines.extend(f"- {item}" for item in manifest["blockers"])
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a signed-release friendly manifest of release evidence files.")
    parser.add_argument("--root", default=".", help="Repository root used for relative paths")
    parser.add_argument("--evidence", action="append", default=[], help="Evidence file or directory to index")
    parser.add_argument("--exclude", action="append", default=["/node_modules/", "/.git/"], help="Substring to exclude from indexing")
    parser.add_argument("--require-evidence", action="store_true", help="Block when no evidence files are found")
    parser.add_argument("--out-json", default="build/release-evidence/evidence-manifest.json")
    parser.add_argument("--out-md", default="build/release-evidence/evidence-manifest.md")
    args = parser.parse_args()
    if not args.evidence:
        args.evidence = ["docs/project", "build"]
    manifest = build_manifest(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(manifest), encoding="utf-8")
    print(f"release evidence manifest: status={manifest['status']} evidence={manifest['evidence_count']}")
    return 0 if manifest["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
