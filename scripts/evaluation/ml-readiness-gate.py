#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.evaluation import build_graph_training_dataset as graph_dataset


SCHEMA = "providapt.ml_readiness.v1"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"missing JSON file: {path}")
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected JSON object")
    return data


def compute_quality_from_inputs(args: argparse.Namespace) -> dict[str, Any]:
    if not args.events or not args.ground_truth:
        return {}
    event_files = graph_dataset.iter_files(args.events, (".ndjson", ".jsonl"))
    normal_files = graph_dataset.iter_files(args.normal_events or [], (".ndjson", ".jsonl")) if args.normal_events else []
    truth_files = graph_dataset.iter_files(args.ground_truth, (".jsonl", ".ndjson"))
    attack_events = [event for path in event_files for event in graph_dataset.load_jsonl(path)]
    normal_events = [event for path in normal_files for event in graph_dataset.load_jsonl(path)]
    truths = [truth for path in truth_files for truth in graph_dataset.load_jsonl(path)]
    window_ns = int(args.window_seconds * 1_000_000_000)
    matched_truth_count = 0
    fallback_truth_count = 0
    for truth in truths:
        if any(graph_dataset.matches_truth(event, truth, window_ns) for event in attack_events):
            matched_truth_count += 1
        else:
            fallback_truth_count += 1
    return graph_dataset.quality_summary(attack_events + normal_events, truths, matched_truth_count, fallback_truth_count)


def check_dataset(manifest: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    quality = manifest.get("quality") or compute_quality_from_inputs(args)
    labels = manifest.get("label_summary") or {}
    failures: list[str] = []
    warnings: list[str] = []
    records = int(manifest.get("record_count") or 0)
    source_events = int(manifest.get("event_source_count") or 0)
    malicious = int(labels.get("malicious") or labels.get("1") or 0)
    benign = int(labels.get("benign") or labels.get("0") or 0)
    truth_match_rate = float(quality.get("truth_match_rate_percent") or 0.0)
    cmdline_rate = float(quality.get("cmdline_present_percent") or 0.0)
    path_rate = float(quality.get("path_present_percent") or 0.0)
    if records < args.min_graphs:
        failures.append(f"dataset has {records} graphs, expected at least {args.min_graphs}")
    if source_events < args.min_source_events:
        failures.append(f"dataset has {source_events} source events, expected at least {args.min_source_events}")
    if malicious < args.min_malicious_graphs:
        failures.append(f"dataset has {malicious} malicious graphs, expected at least {args.min_malicious_graphs}")
    if benign < args.min_benign_graphs:
        failures.append(f"dataset has {benign} benign graphs, expected at least {args.min_benign_graphs}")
    if truth_match_rate < args.min_truth_match_rate:
        failures.append(f"truth match rate {truth_match_rate}% below {args.min_truth_match_rate}%")
    if cmdline_rate < args.min_cmdline_rate:
        warnings.append(f"cmdline presence {cmdline_rate}% below target {args.min_cmdline_rate}%")
    if path_rate < args.min_path_rate:
        warnings.append(f"path presence {path_rate}% below target {args.min_path_rate}%")
    if manifest.get("synthetic"):
        warnings.append("dataset is synthetic; keep separate from VM-captured evaluation evidence")
    return {
        "status": "pass" if not failures else "blocked",
        "dataset_id": manifest.get("dataset_id", ""),
        "dataset_version": manifest.get("dataset_version", ""),
        "records": records,
        "source_events": source_events,
        "malicious_graphs": malicious,
        "benign_graphs": benign,
        "ground_truth_count": int(quality.get("ground_truth_count") or manifest.get("ground_truth_count") or 0),
        "truth_matched_count": int(quality.get("truth_matched_count") or 0),
        "truth_fallback_count": int(quality.get("truth_fallback_count") or 0),
        "truth_match_rate_percent": truth_match_rate,
        "cmdline_present_percent": cmdline_rate,
        "cmdline_procfs_percent": float(quality.get("cmdline_procfs_percent") or 0.0),
        "cwd_present_percent": float(quality.get("cwd_present_percent") or 0.0),
        "exe_path_present_percent": float(quality.get("exe_path_present_percent") or 0.0),
        "path_present_percent": path_rate,
        "absolute_path_percent": float(quality.get("absolute_path_percent") or 0.0),
        "event_type_summary": quality.get("event_type_summary", {}),
        "failures": failures,
        "warnings": warnings,
    }


def check_metrics(metrics: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    failures: list[str] = []
    test_metrics = metrics.get("test_metrics") or metrics
    precision = float(test_metrics.get("precision_percent") or 0.0)
    recall = float(test_metrics.get("recall_percent") or 0.0)
    f1 = float(test_metrics.get("f1_percent") or 0.0)
    roc_auc = float(test_metrics.get("roc_auc_percent") or 0.0)
    pr_auc = float(test_metrics.get("pr_auc_percent") or 0.0)
    support = int(test_metrics.get("support") or metrics.get("support") or 0)
    if precision < args.min_precision:
        failures.append(f"precision {precision}% below {args.min_precision}%")
    if recall < args.min_recall:
        failures.append(f"recall {recall}% below {args.min_recall}%")
    if f1 < args.min_f1:
        failures.append(f"f1 {f1}% below {args.min_f1}%")
    if support < args.min_test_support:
        failures.append(f"test support {support} below {args.min_test_support}")
    return {
        "status": "pass" if not failures else "blocked",
        "architecture": metrics.get("architecture", ""),
        "device": metrics.get("device", ""),
        "dataset_records": metrics.get("dataset_records", 0),
        "test_support": support,
        "precision_percent": precision,
        "recall_percent": recall,
        "f1_percent": f1,
        "roc_auc_percent": roc_auc,
        "pr_auc_percent": pr_auc,
        "confusion": test_metrics.get("confusion", {}),
        "failures": failures,
    }


def check_deploy_gate(gate: dict[str, Any] | None) -> dict[str, Any]:
    if not gate:
        return {"status": "skipped", "warnings": ["model deploy gate not supplied"], "failures": []}
    failures = list(gate.get("failures") or [])
    if gate.get("status") != "pass":
        failures.append(f"model deploy gate status is {gate.get('status')}")
    return {
        "status": "pass" if not failures else "blocked",
        "model_registered": bool(gate.get("model_registered")),
        "drift_status": gate.get("drift_status", ""),
        "schema_check_status": gate.get("schema_check_status", ""),
        "failures": failures,
        "warnings": list(gate.get("warnings") or []),
    }


def overall_status(sections: dict[str, dict[str, Any]]) -> str:
    blocking = [section for section in sections.values() if section.get("status") == "blocked"]
    return "pass" if not blocking else "blocked"


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT ML Readiness",
        "",
        f"- Status: `{report['status']}`",
        f"- Generated at: `{report['generated_at']}`",
        "",
    ]
    for name, section in report["sections"].items():
        lines.extend([f"## {name.replace('_', ' ').title()}", "", f"- Status: `{section.get('status')}`"])
        for key, value in section.items():
            if key in {"status", "failures", "warnings"}:
                continue
            lines.append(f"- {key}: `{value}`")
        if section.get("failures"):
            lines.append("- Failures: " + "; ".join(section["failures"]))
        if section.get("warnings"):
            lines.append("- Warnings: " + "; ".join(section["warnings"]))
        lines.append("")
    return "\n".join(lines)


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    sections = {
        "dataset_quality": check_dataset(load_json(Path(args.dataset_manifest)), args),
        "model_metrics": check_metrics(load_json(Path(args.metrics)), args),
    }
    gate = load_json(Path(args.model_gate)) if args.model_gate else None
    sections["model_deploy_gate"] = check_deploy_gate(gate)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": overall_status(sections),
        "sections": sections,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Gate graph ML readiness on dataset quality and model metrics.")
    parser.add_argument("--dataset-manifest", required=True)
    parser.add_argument("--metrics", required=True)
    parser.add_argument("--model-gate", default="")
    parser.add_argument("--events", action="append", default=[], help="Optional attack event NDJSON path or directory used to compute quality for legacy manifests")
    parser.add_argument("--normal-events", action="append", default=[], help="Optional normal event NDJSON path or directory used to compute quality for legacy manifests")
    parser.add_argument("--ground-truth", action="append", default=[], help="Optional ground-truth JSONL path or directory used to compute quality for legacy manifests")
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("--min-graphs", type=int, default=1000)
    parser.add_argument("--min-source-events", type=int, default=10000)
    parser.add_argument("--min-malicious-graphs", type=int, default=100)
    parser.add_argument("--min-benign-graphs", type=int, default=100)
    parser.add_argument("--min-truth-match-rate", type=float, default=80.0)
    parser.add_argument("--min-cmdline-rate", type=float, default=10.0)
    parser.add_argument("--min-path-rate", type=float, default=10.0)
    parser.add_argument("--min-precision", type=float, default=70.0)
    parser.add_argument("--min-recall", type=float, default=80.0)
    parser.add_argument("--min-f1", type=float, default=70.0)
    parser.add_argument("--min-test-support", type=int, default=100)
    parser.add_argument("--out-json", default="build/ml-readiness/ml-readiness-gate.json")
    parser.add_argument("--out-md", default="build/ml-readiness/ml-readiness-gate.md")
    args = parser.parse_args()
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} sections={','.join(report['sections'])}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
