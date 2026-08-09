#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.model_closed_loop.v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_json(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    target = Path(path)
    if not target.exists():
        return {}
    data = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"{target}: expected JSON object")
    return data


def metric(metrics: dict[str, Any], name: str) -> float:
    for key in (name, name.lower(), name.upper()):
        value = metrics.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    summary = metrics.get("summary")
    if isinstance(summary, dict):
        return metric(summary, name)
    return 0.0


def as_percent(value: float) -> float:
    return value * 100.0 if 0.0 <= value <= 1.0 else value


def latest_model(registry: dict[str, Any], model_name: str, model_version: str) -> dict[str, Any]:
    models = registry.get("models")
    if not isinstance(models, list):
        return {}
    for record in reversed(models):
        if model_name and record.get("model_name") != model_name:
            continue
        if model_version and record.get("model_version") != model_version:
            continue
        return record if isinstance(record, dict) else {}
    return {}


def feedback_summary(path: str | None, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    if not path:
        manifest_feedback = (manifest or {}).get("alert_feedback")
        if isinstance(manifest_feedback, dict):
            return {
                "path": "",
                "records": int(manifest_feedback.get("feedback_entry_count") or 0),
                "labels": manifest_feedback.get("feedback_by_classification", {}),
                "alert_count": int(manifest_feedback.get("feedback_alert_count") or 0),
                "reviewed": int(manifest_feedback.get("feedback_reviewed_count") or 0),
                "needs_review": int(manifest_feedback.get("feedback_needs_review_count") or 0),
                "source": "dataset_manifest",
            }
        return {"path": "", "records": 0, "labels": {}, "alert_count": 0, "reviewed": 0, "needs_review": 0, "source": "none"}
    target = Path(path)
    if not target.exists():
        return {"path": str(target), "records": 0, "labels": {}, "alert_count": 0, "reviewed": 0, "needs_review": 0, "missing": True}
    labels: dict[str, int] = {}
    actions: dict[str, int] = {}
    alert_ids: set[str] = set()
    records = 0
    invalid_json = 0
    with target.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records += 1
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                invalid_json += 1
                continue
            label = normalize_feedback_label(item.get("classification") or item.get("label") or item.get("verdict") or item.get("status"))
            labels[label] = labels.get(label, 0) + 1
            action = str(item.get("action") or "unknown").lower().strip() or "unknown"
            actions[action] = actions.get(action, 0) + 1
            alert_id = str(item.get("alert_id") or "").strip()
            if alert_id:
                alert_ids.add(alert_id)
    reviewed = sum(labels.get(key, 0) for key in ("true_positive", "false_positive", "benign", "duplicate"))
    return {
        "path": str(target),
        "records": records,
        "labels": dict(sorted(labels.items())),
        "actions": dict(sorted(actions.items())),
        "alert_count": len(alert_ids),
        "reviewed": reviewed,
        "needs_review": labels.get("needs_review", 0),
        "invalid_json": invalid_json,
        "source": "feedback_file",
    }


def normalize_feedback_label(value: Any) -> str:
    normalized = str(value or "").lower().strip().replace("-", "_").replace(" ", "_")
    if normalized == "tp":
        return "true_positive"
    if normalized == "fp":
        return "false_positive"
    if normalized in {"true_positive", "false_positive", "benign", "duplicate", "needs_review"}:
        return normalized
    return "needs_review"


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    manifest = load_json(args.dataset_manifest)
    metrics = load_json(args.metrics)
    registry = load_json(args.registry)
    drift = load_json(args.drift_report)
    model = latest_model(registry, args.model_name, args.model_version)
    feedback = feedback_summary(args.feedback, manifest)
    precision = as_percent(metric(metrics, "precision"))
    recall = as_percent(metric(metrics, "recall"))
    accuracy = as_percent(metric(metrics, "accuracy"))
    f1 = as_percent(metric(metrics, "f1"))
    gates = [
        gate("dataset_manifest", bool(manifest), "dataset manifest is present"),
        gate("model_metrics", bool(metrics), "model metrics are present"),
        gate("precision", precision >= args.min_precision, f"precision {precision:.2f}% >= {args.min_precision:.2f}%"),
        gate("recall", recall >= args.min_recall, f"recall {recall:.2f}% >= {args.min_recall:.2f}%"),
        gate("f1", f1 >= args.min_f1, f"f1 {f1:.2f}% >= {args.min_f1:.2f}%"),
        gate("registered_model", bool(model), "model registry contains this model version"),
    ]
    if drift:
        drift_ok = str(drift.get("status", "")).lower() in {"stable", "pass", "changed"}
        gates.append(gate("drift", drift_ok, f"drift status is {drift.get('status', 'unknown')}"))
    if args.require_feedback:
        gates.append(gate("operator_feedback", feedback["records"] > 0, "operator feedback is attached"))
        gates.append(gate("reviewed_feedback_labels", feedback.get("reviewed", 0) > 0, "operator feedback includes reviewed TP/FP/benign/duplicate labels"))
    failed = [item for item in gates if item["status"] == "fail"]
    recommendations = []
    if precision < args.min_precision:
        recommendations.append("Review false positives, hard negatives, and alert feedback before promotion.")
    if recall < args.min_recall:
        recommendations.append("Collect additional attack-path examples and retrain with higher malicious support.")
    if f1 < args.min_f1:
        recommendations.append("Tune threshold or rebalance training windows before production rollout.")
    if not model:
        recommendations.append("Register the trained model artifact before deployment.")
    if feedback["records"] == 0:
        recommendations.append("Attach operator feedback to close the detection-improvement loop.")
    status = "ready" if not failed else "review_required"
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "status": status,
        "model_name": args.model_name,
        "model_version": args.model_version,
        "dataset": dataset_summary(manifest),
        "metrics": {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "auc": metric(metrics, "auc"),
        },
        "registry_model": model,
        "drift": drift,
        "feedback": feedback,
        "gates": gates,
        "recommendations": recommendations,
    }


def gate(name: str, passed: bool, message: str) -> dict[str, str]:
    return {"name": name, "status": "pass" if passed else "fail", "message": message}


def dataset_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "dataset_id": manifest.get("dataset_id", ""),
        "dataset_version": manifest.get("dataset_version", ""),
        "record_count": manifest.get("record_count", 0),
        "split_summary": manifest.get("split_summary", {}),
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Model Closed Loop Report",
        "",
        f"- Status: `{report['status']}`",
        f"- Model: `{report['model_name']}` `{report['model_version']}`",
        f"- Dataset: `{report['dataset']['dataset_id']}` ({report['dataset']['record_count']} records)",
        f"- Precision: {report['metrics']['precision']}%",
        f"- Recall: {report['metrics']['recall']}%",
        f"- F1: {report['metrics']['f1']}%",
        "",
        "## Gates",
        "",
        "| Gate | Status | Message |",
        "| --- | --- | --- |",
    ]
    for item in report["gates"]:
        lines.append(f"| {item['name']} | {item['status']} | {item['message']} |")
    lines.extend(["", "## Feedback", "", f"- Records: {report['feedback']['records']}", f"- Labels: `{json.dumps(report['feedback']['labels'], sort_keys=True)}`", ""])
    if report["recommendations"]:
        lines.extend(["## Recommendations", ""])
        lines.extend(f"- {item}" for item in report["recommendations"])
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a closed-loop model promotion report from dataset, metrics, registry, drift, and operator feedback.")
    parser.add_argument("--dataset-manifest", required=True)
    parser.add_argument("--metrics", required=True)
    parser.add_argument("--registry", default="build/model-registry.json")
    parser.add_argument("--model-name", default="graph-detector")
    parser.add_argument("--model-version", default="")
    parser.add_argument("--drift-report", default="")
    parser.add_argument("--feedback", default="")
    parser.add_argument("--require-feedback", action="store_true")
    parser.add_argument("--min-precision", type=float, default=70.0)
    parser.add_argument("--min-recall", type=float, default=80.0)
    parser.add_argument("--min-f1", type=float, default=70.0)
    parser.add_argument("--out-json", default="build/evaluation/model-closed-loop.json")
    parser.add_argument("--out-md", default="build/evaluation/model-closed-loop.md")
    args = parser.parse_args()
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({"status": report["status"], "out_json": str(out_json), "out_md": str(out_md)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
