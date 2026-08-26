#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.model_lifecycle_gate.v1"
APPROVAL_ROLES = ("model_owner", "security", "soc_lead")
REVIEWED_FEEDBACK_LABELS = ("true_positive", "false_positive", "benign", "duplicate")


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


def sha256_file(path: str | None) -> str:
    if not path:
        return ""
    target = Path(path)
    if not target.exists() or not target.is_file():
        return ""
    digest = hashlib.sha256()
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_ref(path: str | None, kind: str) -> dict[str, Any]:
    target = Path(path) if path else None
    return {
        "kind": kind,
        "path": str(target) if target else "",
        "present": bool(target and target.exists() and target.is_file() and target.stat().st_size > 0),
        "sha256": sha256_file(path),
    }


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def feedback_counts(closed_loop: dict[str, Any]) -> tuple[int, int]:
    feedback = closed_loop.get("feedback")
    if not isinstance(feedback, dict):
        return 0, 0
    return int(feedback.get("records") or 0), int(feedback.get("reviewed") or 0)


def normalize_feedback_label(value: Any) -> str:
    normalized = str(value or "").lower().strip().replace("-", "_").replace(" ", "_")
    if normalized == "tp":
        return "true_positive"
    if normalized == "fp":
        return "false_positive"
    if normalized in REVIEWED_FEEDBACK_LABELS or normalized == "needs_review":
        return normalized
    return normalized


def feedback_labels(closed_loop: dict[str, Any]) -> dict[str, int]:
    feedback = closed_loop.get("feedback")
    if not isinstance(feedback, dict):
        return {}
    raw = feedback.get("labels") or feedback.get("label_counts") or feedback.get("feedback_by_classification")
    if not isinstance(raw, dict):
        return {}
    labels: dict[str, int] = {}
    for label, value in raw.items():
        normalized = normalize_feedback_label(label)
        if not normalized:
            continue
        try:
            count = int(value or 0)
        except (TypeError, ValueError):
            count = 0
        labels[normalized] = labels.get(normalized, 0) + count
    return dict(sorted(labels.items()))


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


def baseline_report_summary(report: dict[str, Any]) -> dict[str, Any]:
    if not report:
        return {
            "status": "not_supplied",
            "windows": 0,
            "observation_days": 0.0,
            "max_drift_percent": 0.0,
        }
    windows = report.get("windows") if isinstance(report.get("windows"), list) else []
    observation_days = report.get("observation_days")
    if not isinstance(observation_days, (int, float)):
        observation_days = report.get("baseline_days") if isinstance(report.get("baseline_days"), (int, float)) else 0.0
    max_drift = report.get("max_observed_drift_percent")
    if not isinstance(max_drift, (int, float)):
        observed = [
            float(item.get("drift_percent") or item.get("max_observed_drift_percent") or 0)
            for item in windows
            if isinstance(item, dict)
        ]
        max_drift = max(observed) if observed else 0.0
    return {
        "status": str(report.get("status") or "unknown").lower(),
        "windows": len(windows),
        "observation_days": float(observation_days),
        "max_drift_percent": float(max_drift),
    }


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


def approval_summary(approval: dict[str, Any]) -> dict[str, dict[str, str]]:
    summary: dict[str, dict[str, str]] = {}
    for role in APPROVAL_ROLES:
        entry = approval.get(role) if isinstance(approval, dict) else {}
        if not isinstance(entry, dict):
            entry = {}
        summary[role] = {
            "decision": str(entry.get("decision") or entry.get("status") or "missing").lower(),
            "owner": str(entry.get("approved_by") or entry.get("owner") or "").strip(),
        }
    return summary


def model_identity(report: dict[str, Any]) -> dict[str, str]:
    feature_schema = report.get("feature_schema") if isinstance(report.get("feature_schema"), dict) else {}
    return {
        "name": str(report.get("model_name") or report.get("name") or "").strip(),
        "version": str(report.get("model_version") or report.get("version") or "").strip(),
        "feature_schema_sha256": str(
            report.get("feature_schema_sha256")
            or report.get("feature_schema_hash")
            or feature_schema.get("sha256")
            or ""
        ).strip(),
    }


def identity_failures(closed_loop: dict[str, Any], deploy_gate: dict[str, Any]) -> list[str]:
    closed = model_identity(closed_loop)
    deploy = model_identity(deploy_gate)
    failures: list[str] = []
    for field in ("name", "version"):
        if not closed[field]:
            failures.append(f"closed-loop model {field} is missing")
        if not deploy[field]:
            failures.append(f"deploy-gate model {field} is missing")
        if closed[field] and deploy[field] and closed[field] != deploy[field]:
            failures.append(f"model {field} mismatch: closed-loop={closed[field]} deploy-gate={deploy[field]}")
    if closed["feature_schema_sha256"] and deploy["feature_schema_sha256"] and closed["feature_schema_sha256"] != deploy["feature_schema_sha256"]:
        failures.append("feature schema hash mismatch between closed-loop and deploy-gate evidence")
    return failures


def next_actions(failures: list[str], warnings: list[str]) -> list[str]:
    actions: list[str] = []
    text = "\n".join(failures + warnings).lower()
    if "closed-loop" in text or "feedback" in text or "reviewed feedback" in text or "feedback label" in text:
        actions.append("collect additional analyst TP/FP/benign/duplicate feedback and rerun make model-closed-loop")
    if "deploy gate" in text or "model name mismatch" in text or "model version mismatch" in text or "feature schema" in text:
        actions.append("rerun model registration, feature-schema check, and make model-deploy-gate for the same model identity")
    if "drift" in text:
        actions.append("review dataset drift, update baseline evidence, or retrain before promotion")
    if "baseline days" in text or "long-term baseline" in text:
        actions.append("extend the baseline observation window before promotion")
    if "approval" in text or "named owner" in text:
        actions.append("attach named model_owner, security, and soc_lead approval evidence")
    if not actions and warnings:
        actions.append("attach optional drift evidence for a more complete model promotion packet")
    return sorted(dict.fromkeys(actions))


def readiness_summary(
    status: str,
    model: dict[str, str],
    closed_loop_status: str,
    deploy_gate_status: str,
    drift_status: str,
    feedback_records: int,
    reviewed_labels: int,
    feedback_label_counts: dict[str, int],
    baseline: float,
    approval_roles: dict[str, dict[str, str]],
    evidence: list[dict[str, Any]],
    failures: list[str],
    warnings: list[str],
) -> dict[str, Any]:
    return {
        "status": status,
        "decision": "approved_for_promotion" if status == "pass" else "promotion_blocked",
        "model": model,
        "closed_loop_status": closed_loop_status,
        "deploy_gate_status": deploy_gate_status,
        "drift_status": drift_status,
        "feedback": {
            "records": feedback_records,
            "reviewed": reviewed_labels,
            "labels": feedback_label_counts,
        },
        "baseline_days": baseline,
        "approvals": approval_roles,
        "evidence": {
            "present": [item["kind"] for item in evidence if item["present"]],
            "missing": [item["kind"] for item in evidence if not item["present"]],
            "sha256": {
                item["kind"]: item["sha256"]
                for item in evidence
                if item["present"] and item["sha256"]
            },
        },
        "blocker_count": len(failures),
        "warning_count": len(warnings),
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    closed_loop = load_json(args.closed_loop)
    deploy_gate = load_json(args.deploy_gate)
    drift = load_json(args.drift_report)
    baseline_report = load_json(args.baseline_report)
    approval = load_json(args.approval)
    failures: list[str] = []
    warnings: list[str] = []
    if closed_loop.get("status") != "ready":
        failures.append("model closed-loop report is not ready")
    if deploy_gate.get("status") != "pass":
        failures.append("model deploy gate did not pass")
    failures.extend(identity_failures(closed_loop, deploy_gate))
    drift_status = str((drift or closed_loop.get("drift") or {}).get("status") or "not_supplied")
    if drift_status in {"review_required", "blocked", "fail"}:
        failures.append(f"dataset drift requires review: {drift_status}")
    if drift_status == "not_supplied":
        warnings.append("drift report not supplied")
    feedback_records, reviewed_labels = feedback_counts(closed_loop)
    labels = feedback_labels(closed_loop)
    if feedback_records < args.min_feedback_records:
        failures.append(f"feedback records {feedback_records} below {args.min_feedback_records}")
    if reviewed_labels < args.min_reviewed_labels:
        failures.append(f"reviewed feedback labels {reviewed_labels} below {args.min_reviewed_labels}")
    required_feedback_labels = list(dict.fromkeys(
        normalize_feedback_label(item) for item in (args.required_feedback_label or []) if normalize_feedback_label(item)
    ))
    for label in required_feedback_labels:
        observed = labels.get(label, 0)
        if observed < args.min_feedback_per_label:
            failures.append(f"feedback label {label} count {observed} below {args.min_feedback_per_label}")
    days = baseline_days(closed_loop)
    if days < args.min_baseline_days:
        failures.append(f"baseline days {days} below {args.min_baseline_days}")
    baseline_summary = baseline_report_summary(baseline_report)
    if args.require_baseline_report and not baseline_report:
        failures.append("long-term baseline report is missing")
    if baseline_report:
        if baseline_summary["status"] not in {"pass", "ready", "stable"}:
            failures.append(f"long-term baseline report status is {baseline_summary['status']}")
        if baseline_summary["windows"] < args.min_baseline_windows:
            failures.append(f"long-term baseline windows {baseline_summary['windows']} below {args.min_baseline_windows}")
        if baseline_summary["observation_days"] < args.min_baseline_days:
            failures.append(f"long-term baseline observation days {baseline_summary['observation_days']} below {args.min_baseline_days}")
    failures.extend(approval_failures(approval, args.require_approval))
    closed_identity = model_identity(closed_loop)
    deploy_identity = model_identity(deploy_gate)
    model = {
        "name": closed_identity["name"] or deploy_identity["name"],
        "version": closed_identity["version"] or deploy_identity["version"],
        "feature_schema_sha256": closed_identity["feature_schema_sha256"] or deploy_identity["feature_schema_sha256"],
    }
    evidence = [
        evidence_ref(args.closed_loop, "closed_loop"),
        evidence_ref(args.deploy_gate, "deploy_gate"),
        evidence_ref(args.drift_report, "drift_report"),
        evidence_ref(args.baseline_report, "baseline_report"),
        evidence_ref(args.approval, "approval"),
    ]
    status = "blocked" if failures else "pass"
    approvals = approval_summary(approval)
    summary = readiness_summary(
        status,
        model,
        str(closed_loop.get("status", "missing")),
        str(deploy_gate.get("status", "missing")),
        drift_status,
        feedback_records,
        reviewed_labels,
        labels,
        days,
        approvals,
        evidence,
        failures,
        warnings,
    )
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "status": status,
        "promotion_decision": "approved_for_promotion" if status == "pass" else "promotion_blocked",
        "thresholds": {
            "min_feedback_records": args.min_feedback_records,
            "min_reviewed_labels": args.min_reviewed_labels,
            "required_feedback_labels": required_feedback_labels,
            "min_feedback_per_label": args.min_feedback_per_label,
            "min_baseline_days": args.min_baseline_days,
            "require_approval": args.require_approval,
        },
        "model": model,
        "closed_loop_model": closed_identity,
        "deploy_gate_model": deploy_identity,
        "closed_loop_status": closed_loop.get("status", "missing"),
        "deploy_gate_status": deploy_gate.get("status", "missing"),
        "drift_status": drift_status,
        "feedback_records": feedback_records,
        "reviewed_labels": reviewed_labels,
        "feedback_labels": labels,
        "baseline_days": days,
        "baseline_report": baseline_summary,
        "approval_roles": list(APPROVAL_ROLES),
        "approval_summary": approvals,
        "evidence": evidence,
        "promotion_packet": {
            "decision": "approved_for_promotion" if status == "pass" else "promotion_blocked",
            "model": model,
            "readiness_summary": summary,
            "evidence_count": sum(1 for item in evidence if item["present"]),
            "evidence_sha256": {
                item["kind"]: item["sha256"]
                for item in evidence
                if item["present"] and item["sha256"]
            },
            "next_actions": next_actions(failures, warnings),
        },
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
        f"- Required feedback labels: `{', '.join(report['thresholds']['required_feedback_labels']) or 'none'}`",
        f"- Baseline days: `{report['baseline_days']}`",
        f"- Long-term baseline: `{json.dumps(report['baseline_report'], sort_keys=True)}`",
        f"- Promotion decision: `{report['promotion_decision']}`",
        f"- Evidence files: `{report['promotion_packet']['evidence_count']}`",
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
    if report["promotion_packet"]["next_actions"]:
        lines.extend(["## Next Actions", ""])
        lines.extend(f"- {item}" for item in report["promotion_packet"]["next_actions"])
        lines.append("")
    summary = report["promotion_packet"]["readiness_summary"]
    lines.extend([
        "## Readiness Summary",
        "",
        "| Area | Value |",
        "| --- | --- |",
        f"| Decision | {summary['decision']} |",
        f"| Blockers | {summary['blocker_count']} |",
        f"| Warnings | {summary['warning_count']} |",
        f"| Evidence present | {', '.join(summary['evidence']['present']) or 'none'} |",
        f"| Evidence missing | {', '.join(summary['evidence']['missing']) or 'none'} |",
        "",
        "## Approvals",
        "",
        "| Role | Decision | Owner |",
        "| --- | --- | --- |",
    ])
    for role, item in report["approval_summary"].items():
        lines.append(f"| {role} | {item['decision']} | {item['owner'] or 'n/a'} |")
    lines.append("")
    lines.extend(["## Feedback Labels", "", "| Label | Count |", "| --- | ---: |"])
    for label, count in report["feedback_labels"].items():
        lines.append(f"| {label} | {count} |")
    lines.append("")
    lines.extend(["## Evidence", ""])
    lines.extend(
        f"- `{item['kind']}`: `{item['path'] or 'not supplied'}` sha256=`{item['sha256'] or 'n/a'}`"
        for item in report["evidence"]
    )
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Gate model promotion on feedback volume, drift, baseline age, deploy readiness, and approvals.")
    parser.add_argument("--closed-loop", required=True)
    parser.add_argument("--deploy-gate", required=True)
    parser.add_argument("--drift-report", default="")
    parser.add_argument("--baseline-report", default="")
    parser.add_argument("--approval", default="")
    parser.add_argument("--require-approval", action="store_true")
    parser.add_argument("--require-baseline-report", action="store_true")
    parser.add_argument("--min-feedback-records", type=int, default=25)
    parser.add_argument("--min-reviewed-labels", type=int, default=10)
    parser.add_argument("--required-feedback-label", action="append", default=[])
    parser.add_argument("--min-feedback-per-label", type=int, default=1)
    parser.add_argument("--min-baseline-days", type=float, default=7.0)
    parser.add_argument("--min-baseline-windows", type=int, default=1)
    parser.add_argument("--out-json", default="build/evaluation/model-lifecycle-gate.json")
    parser.add_argument("--out-md", default="build/evaluation/model-lifecycle-gate.md")
    args = parser.parse_args(argv)
    if not args.required_feedback_label:
        args.required_feedback_label = ["true_positive", "false_positive"]
    return args


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
