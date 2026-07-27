#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REGISTRY_SCHEMA = "providapt.model_registry.v1"
DRIFT_SCHEMA = "providapt.model_drift_report.v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
      raise SystemExit(f"{path}: expected JSON object")
    return data


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_registry(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema": REGISTRY_SCHEMA, "created_at": utc_now(), "models": []}
    registry = load_json(path)
    registry.setdefault("schema", REGISTRY_SCHEMA)
    registry.setdefault("models", [])
    if not isinstance(registry["models"], list):
        raise SystemExit(f"{path}: models must be a list")
    return registry


def register_model(args: argparse.Namespace) -> dict[str, Any]:
    manifest_path = Path(args.manifest)
    registry_path = Path(args.registry)
    manifest = load_json(manifest_path)
    metrics_path = Path(args.metrics) if args.metrics else None
    metrics = load_json(metrics_path) if metrics_path else {}
    record = {
        "model_name": args.model_name,
        "model_version": args.model_version,
        "registered_at": utc_now(),
        "dataset_id": manifest.get("dataset_id", ""),
        "dataset_version": manifest.get("dataset_version", ""),
        "dataset_record_count": manifest.get("record_count", 0),
        "dataset_manifest": {
            "path": str(manifest_path),
            "sha256": sha256_file(manifest_path),
            "size_bytes": manifest_path.stat().st_size,
        },
        "metrics": {
            "path": str(metrics_path) if metrics_path else "",
            "sha256": sha256_file(metrics_path) if metrics_path else "",
            "summary": metrics,
        },
        "commit": args.commit or "",
        "notes": args.notes or "",
    }
    registry = load_registry(registry_path)
    registry["updated_at"] = utc_now()
    registry["models"] = [
        item for item in registry["models"]
        if not (item.get("model_name") == args.model_name and item.get("model_version") == args.model_version)
    ]
    registry["models"].append(record)
    registry["models"].sort(key=lambda item: (item.get("model_name", ""), item.get("model_version", "")))
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return registry


def split_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    value = manifest.get("split_summary")
    if isinstance(value, dict):
        return value
    return {}


def as_counter(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, int] = {}
    for key, item in value.items():
        try:
            result[str(key)] = int(item)
        except (TypeError, ValueError):
            result[str(key)] = 0
    return result


def delta_rows(baseline: dict[str, int], candidate: dict[str, int], threshold: float) -> list[dict[str, Any]]:
    keys = sorted(set(baseline) | set(candidate))
    rows: list[dict[str, Any]] = []
    for key in keys:
        before = baseline.get(key, 0)
        after = candidate.get(key, 0)
        delta = after - before
        delta_percent = round(delta * 100.0 / before, 2) if before else (100.0 if after else 0.0)
        rows.append({
            "key": key,
            "baseline": before,
            "candidate": after,
            "delta": delta,
            "delta_percent": delta_percent,
            "exceeds_threshold": abs(delta_percent) >= threshold and before != after,
        })
    return rows


def build_drift_report(baseline: dict[str, Any], candidate: dict[str, Any], threshold: float) -> dict[str, Any]:
    base_summary = split_summary(baseline)
    cand_summary = split_summary(candidate)
    sections = {
        "by_tactic": delta_rows(as_counter(base_summary.get("by_tactic")), as_counter(cand_summary.get("by_tactic")), threshold),
        "by_technique": delta_rows(as_counter(base_summary.get("by_technique")), as_counter(cand_summary.get("by_technique")), threshold),
        "by_split": delta_rows(as_counter(base_summary.get("splits")), as_counter(cand_summary.get("splits")), threshold),
    }
    record_delta = int(candidate.get("record_count", 0)) - int(baseline.get("record_count", 0))
    warnings = []
    for name, rows in sections.items():
        for row in rows:
            if row["exceeds_threshold"]:
                warnings.append(f"{name}:{row['key']} changed {row['delta_percent']}%")
    if record_delta == 0 and not warnings:
        status = "stable"
    elif warnings:
        status = "review_required"
    else:
        status = "changed"
    return {
        "schema": DRIFT_SCHEMA,
        "generated_at": utc_now(),
        "status": status,
        "threshold_percent": threshold,
        "baseline": {
            "dataset_id": baseline.get("dataset_id", ""),
            "dataset_version": baseline.get("dataset_version", ""),
            "record_count": baseline.get("record_count", 0),
        },
        "candidate": {
            "dataset_id": candidate.get("dataset_id", ""),
            "dataset_version": candidate.get("dataset_version", ""),
            "record_count": candidate.get("record_count", 0),
        },
        "record_delta": record_delta,
        "sections": sections,
        "warnings": warnings,
    }


def render_drift_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Model Drift Report",
        "",
        f"- Status: `{report['status']}`",
        f"- Threshold: {report['threshold_percent']}%",
        f"- Baseline: `{report['baseline']['dataset_id']}` ({report['baseline']['record_count']} records)",
        f"- Candidate: `{report['candidate']['dataset_id']}` ({report['candidate']['record_count']} records)",
        f"- Record delta: {report['record_delta']}",
        "",
    ]
    for section, rows in report["sections"].items():
        lines.extend([f"## {section}", "", "| Key | Baseline | Candidate | Delta | Delta % |", "| --- | ---: | ---: | ---: | ---: |"])
        for row in rows:
            marker = " **review**" if row["exceeds_threshold"] else ""
            lines.append(f"| {row['key']} | {row['baseline']} | {row['candidate']} | {row['delta']} | {row['delta_percent']}%{marker} |")
        lines.append("")
    if report["warnings"]:
        lines.extend(["## Warnings", ""])
        lines.extend(f"- {item}" for item in report["warnings"])
        lines.append("")
    return "\n".join(lines)


def run_drift(args: argparse.Namespace) -> dict[str, Any]:
    report = build_drift_report(load_json(Path(args.baseline)), load_json(Path(args.candidate)), float(args.threshold_percent))
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_drift_markdown(report), encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Register ProvidAPT models and compare dataset drift.")
    sub = parser.add_subparsers(dest="command", required=True)
    reg = sub.add_parser("register", help="append or replace a model registry record")
    reg.add_argument("--manifest", required=True)
    reg.add_argument("--registry", default="build/model-registry.json")
    reg.add_argument("--model-name", required=True)
    reg.add_argument("--model-version", required=True)
    reg.add_argument("--metrics")
    reg.add_argument("--commit")
    reg.add_argument("--notes")
    drift = sub.add_parser("drift", help="compare two exported dataset manifests")
    drift.add_argument("--baseline", required=True)
    drift.add_argument("--candidate", required=True)
    drift.add_argument("--threshold-percent", type=float, default=20.0)
    drift.add_argument("--out-json", default="build/evaluation/model-drift.json")
    drift.add_argument("--out-md", default="build/evaluation/model-drift.md")
    args = parser.parse_args()
    if args.command == "register":
        register_model(args)
    elif args.command == "drift":
        run_drift(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
