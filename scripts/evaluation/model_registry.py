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
FEATURE_SCHEMA = "providapt.model_feature_schema.v1"
DEFAULT_FEATURES = [
    "node_count",
    "edge_count",
    "graph_density",
    "avg_degree",
    "max_degree",
    "stddev_degree",
    "process_ratio",
    "file_ratio",
    "network_ratio",
    "used_edge_ratio",
    "generated_by_ratio",
    "informed_by_ratio",
    "avg_path_length",
    "max_path_length",
    "interaction_entropy",
]


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


def canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def feature_schema_digest(schema: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(schema).encode("utf-8")).hexdigest()


def default_feature_schema(version: str = "1") -> dict[str, Any]:
    schema = {
        "schema": FEATURE_SCHEMA,
        "feature_schema_version": version,
        "vector_length": len(DEFAULT_FEATURES),
        "features": [
            {"index": index, "name": name, "type": "float64"}
            for index, name in enumerate(DEFAULT_FEATURES)
        ],
    }
    schema["sha256"] = feature_schema_digest({k: v for k, v in schema.items() if k != "sha256"})
    return schema


def load_feature_schema(path: str | None) -> dict[str, Any]:
    if not path:
        return default_feature_schema()
    schema = load_json(Path(path))
    validate_feature_schema(schema, default_feature_schema(), strict=True)
    return schema


def schema_feature_names(schema: dict[str, Any]) -> list[str]:
    features = schema.get("features")
    if not isinstance(features, list):
        raise SystemExit("feature schema must contain a features list")
    names: list[str] = []
    for expected_index, feature in enumerate(features):
        if not isinstance(feature, dict):
            raise SystemExit(f"feature {expected_index}: expected object")
        if int(feature.get("index", -1)) != expected_index:
            raise SystemExit(f"feature {expected_index}: index mismatch")
        name = str(feature.get("name", "")).strip()
        if not name:
            raise SystemExit(f"feature {expected_index}: missing name")
        names.append(name)
    return names


def validate_feature_schema(candidate: dict[str, Any], expected: dict[str, Any], strict: bool = False) -> dict[str, Any]:
    candidate_names = schema_feature_names(candidate)
    expected_names = schema_feature_names(expected)
    missing = [name for name in expected_names if name not in candidate_names]
    extra = [name for name in candidate_names if name not in expected_names]
    order_changed = candidate_names != expected_names
    supplied_hash = str(candidate.get("sha256", "")).strip()
    recomputed_hash = feature_schema_digest({k: v for k, v in candidate.items() if k != "sha256"})
    hash_match = not supplied_hash or supplied_hash == recomputed_hash
    status = "pass"
    if missing or extra or order_changed or not hash_match:
        status = "fail" if strict else "warn"
    report = {
        "schema": "providapt.model_feature_schema_validation.v1",
        "generated_at": utc_now(),
        "status": status,
        "expected_vector_length": len(expected_names),
        "candidate_vector_length": len(candidate_names),
        "missing": missing,
        "extra": extra,
        "order_changed": order_changed,
        "hash_match": hash_match,
        "candidate_sha256": supplied_hash or recomputed_hash,
        "recomputed_sha256": recomputed_hash,
    }
    if status == "fail":
        raise SystemExit(json.dumps(report, indent=2, sort_keys=True))
    return report


def register_model(args: argparse.Namespace) -> dict[str, Any]:
    manifest_path = Path(args.manifest)
    registry_path = Path(args.registry)
    manifest = load_json(manifest_path)
    metrics_path = Path(args.metrics) if args.metrics else None
    metrics = load_json(metrics_path) if metrics_path else {}
    feature_schema = load_feature_schema(args.feature_schema)
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
        "feature_schema": {
            "path": args.feature_schema or "builtin:providapt-model-features",
            "sha256": feature_schema.get("sha256") or feature_schema_digest(feature_schema),
            "version": feature_schema.get("feature_schema_version", ""),
            "vector_length": feature_schema.get("vector_length", len(schema_feature_names(feature_schema))),
            "features": schema_feature_names(feature_schema),
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


def export_schema(args: argparse.Namespace) -> dict[str, Any]:
    schema = default_feature_schema(args.version)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return schema


def run_schema_check(args: argparse.Namespace) -> dict[str, Any]:
    report = validate_feature_schema(load_json(Path(args.schema_file)), default_feature_schema(), strict=args.strict)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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
    reg.add_argument("--feature-schema")
    reg.add_argument("--commit")
    reg.add_argument("--notes")
    drift = sub.add_parser("drift", help="compare two exported dataset manifests")
    drift.add_argument("--baseline", required=True)
    drift.add_argument("--candidate", required=True)
    drift.add_argument("--threshold-percent", type=float, default=20.0)
    drift.add_argument("--out-json", default="build/evaluation/model-drift.json")
    drift.add_argument("--out-md", default="build/evaluation/model-drift.md")
    schema = sub.add_parser("export-schema", help="write the built-in model feature schema")
    schema.add_argument("--version", default="1")
    schema.add_argument("--out", default="build/evaluation/model-feature-schema.json")
    check = sub.add_parser("validate-schema", help="validate a model feature schema against the built-in contract")
    check.add_argument("--schema-file", required=True)
    check.add_argument("--out", default="build/evaluation/model-feature-schema-check.json")
    check.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    if args.command == "register":
        register_model(args)
    elif args.command == "drift":
        run_drift(args)
    elif args.command == "export-schema":
        export_schema(args)
    elif args.command == "validate-schema":
        run_schema_check(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
