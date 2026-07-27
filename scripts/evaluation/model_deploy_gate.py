#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.model_deploy_gate.v1"


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected JSON object")
    return data


def find_model(registry: dict[str, Any], name: str, version: str) -> dict[str, Any] | None:
    for record in registry.get("models", []):
        if not isinstance(record, dict):
            continue
        if record.get("model_name") == name and record.get("model_version") == version:
            return record
    return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_gate(args: argparse.Namespace) -> dict[str, Any]:
    registry = load_json(Path(args.registry))
    model = find_model(registry, args.model_name, args.model_version)
    detection = load_json(Path(args.detection_quality)) if args.detection_quality else {}
    drift = load_json(Path(args.drift_report)) if args.drift_report else {}
    schema_check = load_json(Path(args.feature_schema_check)) if args.feature_schema_check else {}
    failures: list[str] = []
    warnings: list[str] = []
    if model is None:
        failures.append("model is not registered")
    else:
        feature_schema = model.get("feature_schema") or {}
        if int(feature_schema.get("vector_length", 0) or 0) <= 0:
            failures.append("registered model does not record feature schema vector length")
        if not feature_schema.get("sha256"):
            failures.append("registered model does not record feature schema hash")
        artifact = model.get("artifact") or {}
        artifact_path = str(artifact.get("path") or "").strip()
        if artifact_path:
            path = Path(artifact_path)
            if not path.exists():
                failures.append(f"registered model artifact is missing: {artifact_path}")
            elif path.stat().st_size <= 0:
                failures.append(f"registered model artifact is empty: {artifact_path}")
            elif artifact.get("sha256") and artifact.get("sha256") != sha256_file(path):
                failures.append(f"registered model artifact sha256 mismatch: {artifact_path}")
        else:
            warnings.append("registered model does not record a deployable artifact path")
    precision = float(detection.get("precision_percent", 0) or 0)
    recall = float(detection.get("recall_percent", 0) or 0)
    if detection:
        if precision < args.min_precision:
            failures.append(f"precision {precision}% is below minimum {args.min_precision}%")
        if recall < args.min_recall:
            failures.append(f"recall {recall}% is below minimum {args.min_recall}%")
    else:
        warnings.append("detection quality report not supplied")
    if drift and drift.get("status") == "review_required":
        failures.append("dataset drift requires review")
    if schema_check and schema_check.get("status") != "pass":
        failures.append("feature schema check did not pass")
    status = "pass" if not failures else "blocked"
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "model_name": args.model_name,
        "model_version": args.model_version,
        "thresholds": {
            "min_precision": args.min_precision,
            "min_recall": args.min_recall,
        },
        "model_registered": model is not None,
        "feature_schema": (model or {}).get("feature_schema", {}),
        "artifact": (model or {}).get("artifact", {}),
        "precision_percent": precision,
        "recall_percent": recall,
        "drift_status": drift.get("status", "not_supplied"),
        "schema_check_status": schema_check.get("status", "not_supplied"),
        "failures": failures,
        "warnings": warnings,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Model Deployment Gate",
        "",
        f"- Status: `{report['status']}`",
        f"- Model: `{report['model_name']}:{report['model_version']}`",
        f"- Precision: `{report['precision_percent']}%`",
        f"- Recall: `{report['recall_percent']}%`",
        f"- Drift: `{report['drift_status']}`",
        f"- Feature schema check: `{report['schema_check_status']}`",
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
    parser = argparse.ArgumentParser(description="Gate model deployment on registry, feature schema, detection quality, and drift evidence.")
    parser.add_argument("--registry", required=True)
    parser.add_argument("--model-name", required=True)
    parser.add_argument("--model-version", required=True)
    parser.add_argument("--detection-quality")
    parser.add_argument("--drift-report")
    parser.add_argument("--feature-schema-check")
    parser.add_argument("--min-precision", type=float, default=70.0)
    parser.add_argument("--min-recall", type=float, default=80.0)
    parser.add_argument("--out-json", default="build/evaluation/model-deploy-gate.json")
    parser.add_argument("--out-md", default="build/evaluation/model-deploy-gate.md")
    args = parser.parse_args()
    report = build_gate(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} model={report['model_name']}:{report['model_version']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
