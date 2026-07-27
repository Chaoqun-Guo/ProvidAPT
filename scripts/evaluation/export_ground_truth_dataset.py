#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.evaluation_dataset.v1"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            record.setdefault("source_file", str(path))
            records.append(record)
    return records


def iter_inputs(inputs: list[str]) -> list[Path]:
    paths: list[Path] = []
    for value in inputs:
        path = Path(value)
        if path.is_dir():
            paths.extend(sorted(path.glob("*.jsonl")))
        elif path.is_file():
            paths.append(path)
        else:
            raise SystemExit(f"input not found: {value}")
    if not paths:
        raise SystemExit("no JSONL inputs found")
    return paths


def stable_key(record: dict[str, Any]) -> str:
    parts = [
        str(record.get("run_id", "")),
        str(record.get("step_id", "")),
        str(record.get("step_index", "")),
        str(record.get("command", "")),
    ]
    return "|".join(parts)


def split_name(record: dict[str, Any], train_ratio: float, seed: str) -> str:
    digest = hashlib.sha256((seed + "|" + stable_key(record)).encode("utf-8")).hexdigest()
    bucket = int(digest[:8], 16) / 0xFFFFFFFF
    return "train" if bucket < train_ratio else "test"


def normalize_record(record: dict[str, Any], split: str) -> dict[str, Any]:
    malicious = bool(record.get("malicious"))
    technique_id = str(record.get("technique_id") or "benign")
    tactic_id = str(record.get("tactic_id") or record.get("tactic") or "benign")
    return {
        "schema": SCHEMA,
        "dataset_split": split,
        "label": "malicious" if malicious else "benign",
        "malicious": malicious,
        "run_id": record.get("run_id", ""),
        "source_file": record.get("source_file", ""),
        "category": record.get("category", record.get("phase", "")),
        "phase": record.get("phase", ""),
        "step_index": record.get("step_index", 0),
        "step_id": record.get("step_id", ""),
        "step_name": record.get("step_name", ""),
        "tactic_id": tactic_id,
        "tactic_name": record.get("tactic_name", ""),
        "technique_id": technique_id,
        "technique_name": record.get("technique_name", ""),
        "mitre_url": record.get("mitre_url", ""),
        "expected_event": record.get("expected_event", ""),
        "expected_relation": record.get("expected_relation", ""),
        "actor": record.get("actor", ""),
        "object": record.get("object", ""),
        "command": record.get("command", ""),
    }


def load_correlation(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    records = data.get("records", []) if isinstance(data, dict) else []
    out: dict[str, dict[str, Any]] = {}
    for row in records:
        truth = row.get("ground_truth", {}) if isinstance(row, dict) else {}
        if isinstance(truth, dict):
            out[stable_key(truth)] = row
    return out


def coverage(records: list[dict[str, Any]], correlation: dict[str, dict[str, Any]]) -> dict[str, Any]:
    by_tactic: dict[str, Counter[str]] = defaultdict(Counter)
    by_technique: dict[str, Counter[str]] = defaultdict(Counter)
    by_run: dict[str, Counter[str]] = defaultdict(Counter)
    detected = 0
    malicious = 0

    for record in records:
        normalized = normalize_record(record, split="")
        is_malicious = normalized["malicious"]
        if is_malicious:
            malicious += 1
        row = correlation.get(stable_key(record), {})
        status = str(row.get("status", "not_evaluated"))
        if status == "matched":
            detected += 1
        tactic = normalized["tactic_id"]
        technique = normalized["technique_id"]
        run_id = str(normalized["run_id"] or "unknown")
        bucket = "detected" if status == "matched" else ("missed" if correlation else "simulated")
        by_tactic[tactic][bucket] += 1
        by_tactic[tactic]["total"] += 1
        by_technique[technique][bucket] += 1
        by_technique[technique]["total"] += 1
        by_run[run_id][bucket] += 1
        by_run[run_id]["total"] += 1
        if is_malicious:
            by_tactic[tactic]["malicious"] += 1
            by_technique[technique]["malicious"] += 1
            by_run[run_id]["malicious"] += 1
        else:
            by_tactic[tactic]["benign"] += 1
            by_technique[technique]["benign"] += 1
            by_run[run_id]["benign"] += 1

    return {
        "schema": "providapt.attack_coverage.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(records),
        "malicious": malicious,
        "benign": len(records) - malicious,
        "detected": detected,
        "coverage_percent": round((detected / malicious * 100.0), 2) if malicious else 0.0,
        "correlation_status": "merged" if correlation else "not_provided",
        "by_tactic": {key: dict(value) for key, value in sorted(by_tactic.items())},
        "by_technique": {key: dict(value) for key, value in sorted(by_technique.items())},
        "by_run": {key: dict(value) for key, value in sorted(by_run.items())},
    }


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dataset_id(labels: list[dict[str, Any]], seed: str, train_ratio: float) -> str:
    digest = hashlib.sha256()
    digest.update(SCHEMA.encode("utf-8"))
    digest.update(b"\0")
    digest.update(seed.encode("utf-8"))
    digest.update(b"\0")
    digest.update(str(train_ratio).encode("utf-8"))
    digest.update(b"\0")
    for record in labels:
        digest.update(json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8"))
        digest.update(b"\n")
    return "ds-" + digest.hexdigest()[:16]


def split_summary(labels: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "splits": defaultdict(Counter),
        "by_tactic": defaultdict(Counter),
        "by_technique": defaultdict(Counter),
        "runs": defaultdict(Counter),
    }
    for record in labels:
        split = str(record.get("dataset_split") or "unknown")
        label = str(record.get("label") or "unknown")
        tactic = str(record.get("tactic_id") or "unknown")
        technique = str(record.get("technique_id") or "unknown")
        run_id = str(record.get("run_id") or "unknown")
        summary["splits"][split]["total"] += 1
        summary["splits"][split][label] += 1
        summary["by_tactic"][tactic]["total"] += 1
        summary["by_tactic"][tactic][split] += 1
        summary["by_technique"][technique]["total"] += 1
        summary["by_technique"][technique][split] += 1
        summary["runs"][run_id]["total"] += 1
        summary["runs"][run_id][split] += 1
    return {
        key: {inner_key: dict(counter) for inner_key, counter in sorted(value.items())}
        for key, value in summary.items()
    }


def output_inventory(out_dir: Path, files: dict[str, str]) -> dict[str, dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}
    for key, relative in files.items():
        path = out_dir / relative
        inventory[key] = {
            "path": relative,
            "bytes": path.stat().st_size if path.exists() else 0,
            "sha256": file_sha256(path) if path.exists() else "",
        }
    return inventory

def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# ProvidAPT ATT&CK Coverage Report",
        "",
        f"- Generated at: `{report['generated_at']}`",
        f"- Records: `{report['total']}`",
        f"- Malicious: `{report['malicious']}`",
        f"- Benign: `{report['benign']}`",
        f"- Correlation: `{report['correlation_status']}`",
        f"- Detection coverage: `{report['coverage_percent']}%`",
        "",
        "## By Tactic",
        "",
        "| Tactic | Total | Malicious | Benign | Detected | Missed | Simulated |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for tactic, row in report["by_tactic"].items():
        lines.append(
            f"| `{tactic}` | {row.get('total', 0)} | {row.get('malicious', 0)} | "
            f"{row.get('benign', 0)} | {row.get('detected', 0)} | "
            f"{row.get('missed', 0)} | {row.get('simulated', 0)} |"
        )
    lines.extend([
        "",
        "## By Run",
        "",
        "| Run | Total | Malicious | Benign | Detected | Missed | Simulated |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ])
    for run_id, row in report["by_run"].items():
        lines.append(
            f"| `{run_id}` | {row.get('total', 0)} | {row.get('malicious', 0)} | "
            f"{row.get('benign', 0)} | {row.get('detected', 0)} | "
            f"{row.get('missed', 0)} | {row.get('simulated', 0)} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Export ProvidAPT ground-truth datasets and ATT&CK coverage reports.")
    parser.add_argument("inputs", nargs="+", help="Ground-truth JSONL file or directory")
    parser.add_argument("--out-dir", default="build/evaluation-dataset", help="Output directory")
    parser.add_argument("--train-ratio", type=float, default=0.8, help="Deterministic train split ratio")
    parser.add_argument("--seed", default="providapt", help="Deterministic split seed")
    parser.add_argument("--correlation-json", help="Optional /api/v1/evaluation/correlation JSON export")
    parser.add_argument("--dataset-version", default="", help="Optional external dataset version label")
    args = parser.parse_args()

    if not 0.0 < args.train_ratio < 1.0:
        raise SystemExit("--train-ratio must be between 0 and 1")

    input_paths = iter_inputs(args.inputs)
    records: list[dict[str, Any]] = []
    for path in input_paths:
        records.extend(load_jsonl(path))
    records.sort(key=stable_key)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    correlation = load_correlation(Path(args.correlation_json) if args.correlation_json else None)

    train: list[dict[str, Any]] = []
    test: list[dict[str, Any]] = []
    labels: list[dict[str, Any]] = []
    for record in records:
        split = split_name(record, args.train_ratio, args.seed)
        normalized = normalize_record(record, split)
        labels.append(normalized)
        if split == "train":
            train.append(normalized)
        else:
            test.append(normalized)

    output_files = {
        "labels": "labels.jsonl",
        "train": "train.jsonl",
        "test": "test.jsonl",
        "coverage_json": "coverage.json",
        "coverage_markdown": "coverage.md",
    }

    write_jsonl(out_dir / output_files["labels"], labels)
    write_jsonl(out_dir / output_files["train"], train)
    write_jsonl(out_dir / output_files["test"], test)

    report = coverage(records, correlation)
    (out_dir / output_files["coverage_json"]).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(out_dir / output_files["coverage_markdown"], report)

    manifest = {
        "schema": SCHEMA,
        "dataset_id": dataset_id(labels, args.seed, args.train_ratio),
        "dataset_version": args.dataset_version,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": [str(path) for path in input_paths],
        "record_count": len(labels),
        "train_count": len(train),
        "test_count": len(test),
        "train_ratio": args.train_ratio,
        "seed": args.seed,
        "split_summary": split_summary(labels),
        "files": output_inventory(out_dir, output_files),
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"records={len(labels)} train={len(train)} test={len(test)} out_dir={out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
