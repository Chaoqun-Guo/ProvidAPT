#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.model_lifecycle_gate.v1"
APPROVAL_ROLES = ("model_owner", "security", "soc_lead")


def load_json(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    target = Path(path)
    if not target.exists():
        return {}
    data = json.loads(target.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise SystemExit(f"{target}: expected JSON object")
    return data


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def feedback_counts(closed_loop: dict[str, Any]) -> tuple[int, int]:
    feedback = closed_loop.get("feedback")
    if not isinstance(feedback, dict):
        return 0, 0
    return int(feedback.get("records") or 0), int(feedback.get("reviewed") or 0)


def baseline_days(closed_loop: dict[str, Any]) -> float:
    dataset = closed_loop.get("dataset")
    if not isinstance(dataset, dict):
        return 0.0
    for key in ("baseline_days", "observation_days", "collection_days"):
        value = dataset.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    split = dataset.get("split_summary")
    if isinstance(split, dict):
        value = split.get("baseline_days") or split.get("observation_days")
        if isinstance(value, (int, float)):
            return float(value)
    return 0.0


def approval_failures(approval: dict[str, Any], require_approval: bool) -> list[str]:
    if not approval:
        return ["model promotion approval is missing"] if require_approval else []
    failures: list[str] = []
    for role in APPROVAL_ROLES:
        entry = approval.get(role)
        if not isinstance(entry, dict):
            failures.append(f"{role} approval missing")
            continue
        decision = str(entry.get("decision") or entry.get("status") or "").lower()
        approver = str(entry.get("approved_by") or entry.get("owner") or "").strip()
        if decision not in {"approved", "pass"}:
            failures.append(f"{role} approval is not approved")
        if not approver or "delegate" in approver.lower() or "placeholder" in approver.lower():
            failures.append(f"{role} approval requires a named owner")
    return failures


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    closed_loop = load_json(args.closed_loop)
    deploy_gate = load_json(args.deploy_gate)
    drift = load_json(args.drift_report)
    approval = load_json(args.approval)
    failures: list[str] = []
    warnings: list[str] = []
    if closed_loop.get("status") != "ready":
        failures.append("model closed-loop report is not ready")
    if deploy_gate.get("status") != "pass":
        failures.append("model deploy gate did not pass")
    drift_status = str((drift or closed_loop.get("drift") or {}).get("status") or "not_supplied")
    if drift_status in {"review_required", "blocked", "fail"}:
        failures.append(f"dataset drift requires review: {drift_status}")
    if drift_status == "not_supplied":
        warnings.append("drift report not supplied")
    feedback_records, reviewed_labels = feedback_counts(closed_loop)
    if feedback_records < args.min_feedback_records:
        failures.append(f"feedback records {feedback_records} below {args.min_feedback_records}")
    if reviewed_labels < args.min_reviewed_labels:
        failures.append(f"reviewed feedback labels {reviewed_labels} below {args.min_reviewed_labels}")
    days = baseline_days(closed_loop)
    if days < args.min_baseline_days:
        failures.append(f"baseline days {days} below {args.min_baseline_days}")
    failures.extend(approval_failures(approval, args.require_approval))
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "status": "blocked" if failures else "pass",
        "thresholds": {
            "min_feedback_records": args.min_feedback_records,
            "min_reviewed_labels": args.min_reviewed_labels,
            "min_baseline_days": args.min_baseline_days,
            "require_approval": args.require_approval,
        },
        "model": {
            "name": closed_loop.get("model_name", deploy_gate.get("model_name", "")),
            "version": closed_loop.get("model_version", deploy_gate.get("model_version", "")),
        },
        "closed_loop_status": closed_loop.get("status", "missing"),
        "deploy_gate_status": deploy_gate.get("status", "missing"),
        "drift_status": drift_status,
        "feedback_records": feedback_records,
        "reviewed_labels": reviewed_labels,
        "baseline_days": days,
        "approval_roles": list(APPROVAL_ROLES),
        "failures": failures,
        "warnings": warnings,
    }


def render_markdown(report: dict[str, Any]) -> str:
    model = report["model"]
    lines = [
        "# ProvidAPT Model Lifecycle Gate",
        "",
        f"- Status: `{report['status']}`",
        f"- Model: `{model['name']}:{model['version']}`",
        f"- Closed loop: `{report['closed_loop_status']}`",
        f"- Deploy gate: `{report['deploy_gate_status']}`",
        f"- Drift: `{report['drift_status']}`",
        f"- Feedback records: `{report['feedback_records']}`",
        f"- Reviewed labels: `{report['reviewed_labels']}`",
        f"- Baseline days: `{report['baseline_days']}`",
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


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Gate model promotion on feedback volume, drift, baseline age, deploy readiness, and approvals.")
    parser.add_argument("--closed-loop", required=True)
    parser.add_argument("--deploy-gate", required=True)
    parser.add_argument("--drift-report", default="")
    parser.add_argument("--approval", default="")
    parser.add_argument("--require-approval", action="store_true")
    parser.add_argument("--min-feedback-records", type=int, default=25)
    parser.add_argument("--min-reviewed-labels", type=int, default=10)
    parser.add_argument("--min-baseline-days", type=float, default=7.0)
    parser.add_argument("--out-json", default="build/evaluation/model-lifecycle-gate.json")
    parser.add_argument("--out-md", default="build/evaluation/model-lifecycle-gate.md")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"model lifecycle gate: status={report['status']} model={report['model']['name']}:{report['model']['version']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
