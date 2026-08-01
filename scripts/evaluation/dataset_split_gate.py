#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.dataset_split_gate.v1"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    return data if isinstance(data, dict) else {}


def split_total(summary: dict[str, Any], name: str) -> int:
    row = summary.get(name)
    if isinstance(row, dict):
        return int(row.get("total") or row.get("malicious", 0) + row.get("benign", 0) or 0)
    return 0


def file_inventory(manifest: dict[str, Any]) -> dict[str, Any]:
    files = manifest.get("files")
    if isinstance(files, dict):
        return files
    return {}


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    manifest = load_json(Path(args.manifest))
    failures: list[str] = []
    warnings: list[str] = []
    if not manifest:
        failures.append("dataset manifest is missing")
    dataset_version = str(manifest.get("dataset_version") or "").strip()
    if args.require_version and not dataset_version:
        failures.append("dataset_version is required")
    record_count = int(manifest.get("record_count") or 0)
    if record_count < args.min_records:
        failures.append(f"record_count {record_count} is below minimum {args.min_records}")
    split_summary = manifest.get("split_summary") if isinstance(manifest.get("split_summary"), dict) else {}
    splits = split_summary.get("splits") if isinstance(split_summary.get("splits"), dict) else split_summary
    train_count = int(manifest.get("train_count") or split_total(splits, "train") or 0)
    test_count = int(manifest.get("test_count") or split_total(splits, "test") or 0)
    val_count = split_total(splits, "val")
    if args.require_train and train_count < args.min_train:
        failures.append(f"train split {train_count} is below minimum {args.min_train}")
    if args.require_test and test_count < args.min_test:
        failures.append(f"test split {test_count} is below minimum {args.min_test}")
    if args.require_val and val_count < args.min_val:
        failures.append(f"validation split {val_count} is below minimum {args.min_val}")
    inventory = file_inventory(manifest)
    missing_hashes = [
        name for name, item in inventory.items()
        if isinstance(item, dict) and (not item.get("sha256") or int(item.get("bytes") or 0) <= 0)
    ]
    if args.require_file_hashes and missing_hashes:
        failures.append("dataset file inventory missing bytes or sha256: " + ", ".join(sorted(missing_hashes)))
    if not inventory:
        warnings.append("dataset manifest has no file inventory")
    label_summary = manifest.get("label_summary") if isinstance(manifest.get("label_summary"), dict) else {}
    malicious = int(label_summary.get("malicious") or 0)
    benign = int(label_summary.get("benign") or 0)
    if args.require_both_labels and (malicious == 0 or benign == 0):
        failures.append("dataset must contain both malicious and benign labels")
    status = "pass" if not failures else "blocked"
    if status == "pass" and warnings:
        status = "warn"
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "dataset_id": manifest.get("dataset_id", ""),
        "dataset_version": dataset_version,
        "record_count": record_count,
        "train_count": train_count,
        "val_count": val_count,
        "test_count": test_count,
        "malicious_count": malicious,
        "benign_count": benign,
        "file_count": len(inventory),
        "failures": failures,
        "warnings": warnings,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Dataset Split Gate",
        "",
        f"- Status: `{report['status']}`",
        f"- Dataset: `{report['dataset_id']}`",
        f"- Version: `{report['dataset_version']}`",
        f"- Records: `{report['record_count']}`",
        f"- Train / Val / Test: `{report['train_count']}` / `{report['val_count']}` / `{report['test_count']}`",
        f"- Malicious / Benign: `{report['malicious_count']}` / `{report['benign_count']}`",
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
    parser = argparse.ArgumentParser(description="Gate dataset versioning, split support, labels, and file inventory evidence.")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--min-records", type=int, default=1)
    parser.add_argument("--min-train", type=int, default=1)
    parser.add_argument("--min-test", type=int, default=1)
    parser.add_argument("--min-val", type=int, default=0)
    parser.add_argument("--require-version", action="store_true")
    parser.add_argument("--require-train", action="store_true")
    parser.add_argument("--require-test", action="store_true")
    parser.add_argument("--require-val", action="store_true")
    parser.add_argument("--require-both-labels", action="store_true")
    parser.add_argument("--require-file-hashes", action="store_true")
    parser.add_argument("--out-json", default="build/evaluation/dataset-split-gate.json")
    parser.add_argument("--out-md", default="build/evaluation/dataset-split-gate.md")
    args = parser.parse_args()
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"dataset split gate: status={report['status']} records={report['record_count']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
