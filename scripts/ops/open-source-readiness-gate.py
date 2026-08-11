#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.open_source_readiness.v1"
DEFAULT_REQUIRED_DOCS = [
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "docs/project/final-release-runbook.md",
    "docs/project/production-readiness.md",
    "docs/project/third-party-notices.md",
    "docs/getting-started/evaluation.md",
    "docs/developer/release-readiness.md",
    "PRIVACY.md",
]


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    return data if isinstance(data, dict) else {}


def status_value(report: dict[str, Any], pass_values: set[str] | None = None) -> str:
    if not report:
        return "blocked"
    status = str(report.get("status", "")).lower()
    allowed = pass_values or {"pass"}
    if status in allowed:
        return "pass"
    if status in {"warn", "warning"}:
        return "warn"
    return "blocked"


def validate_docs(paths: list[str]) -> dict[str, Any]:
    missing: list[str] = []
    empty: list[str] = []
    for value in paths:
        path = Path(value)
        if not path.exists():
            missing.append(value)
        elif path.stat().st_size == 0:
            empty.append(value)
    failures = []
    if missing:
        failures.append("missing required docs: " + ", ".join(missing))
    if empty:
        failures.append("empty required docs: " + ", ".join(empty))
    return {
        "status": "pass" if not failures else "blocked",
        "required_count": len(paths),
        "missing_count": len(missing),
        "empty_count": len(empty),
        "failures": failures,
    }


def onboarding_detail(report: dict[str, Any]) -> dict[str, Any]:
    outputs = report.get("outputs") if isinstance(report.get("outputs"), dict) else {}
    missing_outputs = [name for name in ("config", "checklist") if not outputs.get(name)]
    return {
        "status": "pass" if report and not missing_outputs else "blocked",
        "mode": report.get("mode", ""),
        "postgres": bool(report.get("postgres")),
        "outputs": ",".join(sorted(outputs)),
        "failures": ["missing onboarding outputs: " + ", ".join(missing_outputs)] if missing_outputs else [],
    }


def plugin_detail(reports: list[dict[str, Any]]) -> dict[str, Any]:
    if not reports:
        return {"status": "warn", "plugin_count": 0, "warnings": ["no plugin release gate evidence supplied"]}
    blocked = [report.get("plugin", {}).get("name", "plugin") for report in reports if status_value(report) != "pass"]
    return {
        "status": "pass" if not blocked else "blocked",
        "plugin_count": len(reports),
        "blocked_plugins": blocked,
        "signed_plugins": sum(1 for report in reports if report.get("signature_present")),
    }


def release_gate_detail(report: dict[str, Any]) -> dict[str, Any]:
    gates = report.get("gates") if isinstance(report.get("gates"), list) else []
    if not gates:
        return {"status": "warn", "gate_count": 0, "warnings": ["release gate status evidence was not supplied"]}
    failures: list[str] = []
    warnings: list[str] = []
    for gate in gates:
        if not isinstance(gate, dict):
            continue
        name = str(gate.get("name") or "gate")
        status = str(gate.get("status") or "").lower()
        if status in {"pass", "available", "waived"}:
            continue
        if status in {"warn", "warning", "skipped", "planned"}:
            warnings.append(f"{name}: {gate.get('message', status)}")
        else:
            failures.append(f"{name}: {gate.get('message', status or 'missing status')}")
    return {
        "status": "blocked" if failures else ("warn" if warnings else "pass"),
        "gate_count": len(gates),
        "commit": report.get("full_commit") or report.get("commit", ""),
        "version": report.get("version", ""),
        "failures": failures,
        "warnings": warnings,
    }


def model_lifecycle_detail(report: dict[str, Any]) -> dict[str, Any]:
    if not report:
        return {"status": "warn", "warnings": ["model lifecycle promotion packet was not supplied"]}
    packet = report.get("promotion_packet") if isinstance(report.get("promotion_packet"), dict) else {}
    model = packet.get("model") if isinstance(packet.get("model"), dict) else report.get("model", {})
    failures = list(report.get("failures") or [])
    warnings = list(report.get("warnings") or [])
    status = status_value(report)
    return {
        "status": status,
        "decision": packet.get("decision", report.get("promotion_decision", "")),
        "model": f"{model.get('name', '')}:{model.get('version', '')}",
        "evidence_count": packet.get("evidence_count", 0),
        "next_actions": len(packet.get("next_actions", [])) if isinstance(packet.get("next_actions"), list) else 0,
        "failures": failures if status == "blocked" else [],
        "warnings": warnings,
    }


def visual_baseline_detail(report: dict[str, Any]) -> dict[str, Any]:
    if not report:
        return {"status": "warn", "warnings": ["visual browser baseline evidence was not supplied"]}
    coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else {}
    source_status = str(report.get("status") or "").lower()
    complete = bool(coverage.get("complete_default_matrix"))
    missing_viewports = list(coverage.get("missing_default_viewports") or [])
    missing_pages = list(coverage.get("missing_pages") or [])
    failures: list[str] = []
    warnings: list[str] = []
    if not complete:
        detail = ", ".join(missing_pages + missing_viewports)
        if source_status == "planned":
            warnings.append("visual baseline matrix is planned but not fully captured" + (f": {detail}" if detail else ""))
        else:
            failures.append("visual baseline matrix is incomplete" + (f": {detail}" if detail else ""))
    status = status_value(report, {"pass", "planned"})
    if status == "pass" and source_status == "planned":
        status = "warn"
    if failures:
        status = "blocked"
    return {
        "status": status,
        "source_status": report.get("status", "missing"),
        "screenshots": coverage.get("covered_count", report.get("screenshot_count", 0)),
        "viewport_classes": ",".join(coverage.get("viewport_classes", [])),
        "complete_default_matrix": complete,
        "failures": failures,
        "warnings": warnings,
    }


def approval_detail(path_value: str) -> dict[str, Any]:
    path = Path(path_value)
    if not path.exists() or path.stat().st_size == 0:
        return {"status": "blocked", "path": path_value, "failures": ["approval evidence is missing"]}
    text = path.read_text(encoding="utf-8-sig").lower()
    approved = "approve" in text or "accepted" in text
    return {
        "status": "pass" if approved else "warn",
        "path": path_value,
        "warnings": [] if approved else ["approval document exists but explicit approval wording was not found"],
    }


def overall_status(sections: dict[str, dict[str, Any]]) -> str:
    statuses = [section.get("status") for section in sections.values()]
    if any(status == "blocked" for status in statuses):
        return "blocked"
    if any(status == "warn" for status in statuses):
        return "warn"
    return "pass"


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    docs = args.required_doc or DEFAULT_REQUIRED_DOCS
    plugin_reports = [load_json(Path(path)) for path in args.plugin_gate]
    sections = {
        "release_gate_status": release_gate_detail(load_json(Path(args.release_gates))),
        "operations_readiness": {"status": status_value(load_json(Path(args.operations_readiness_gate)), {"pass", "warn"})},
        "enterprise_readiness": {"status": status_value(load_json(Path(args.enterprise_readiness)), {"pass", "warn"})},
        "model_lifecycle": model_lifecycle_detail(load_json(Path(args.model_lifecycle_gate))),
        "visual_baselines": visual_baseline_detail(load_json(Path(args.visual_regression_snapshots))),
        "onboarding_bundle": onboarding_detail(load_json(Path(args.onboarding_manifest))),
        "plugin_release_gates": plugin_detail(plugin_reports),
        "open_source_documentation": validate_docs(docs),
        "external_approval": approval_detail(args.external_approval),
    }
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": overall_status(sections),
        "sections": sections,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Open Source Readiness",
        "",
        f"- Status: `{report['status']}`",
        f"- Generated at: `{report['generated_at']}`",
        "",
        "| Section | Status | Detail |",
        "| --- | --- | --- |",
    ]
    for name, section in report["sections"].items():
        detail = ", ".join(
            f"{key}={value}"
            for key, value in section.items()
            if key not in {"status", "failures", "warnings"}
        )
        lines.append(f"| {name} | {section['status']} | {detail} |")
    failures = [
        f"{name}: {item}"
        for name, section in report["sections"].items()
        for item in section.get("failures", [])
    ]
    warnings = [
        f"{name}: {item}"
        for name, section in report["sections"].items()
        for item in section.get("warnings", [])
    ]
    if failures:
        lines.extend(["", "## Failures", ""])
        lines.extend(f"- {item}" for item in failures)
    if warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {item}" for item in warnings)
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate open-source release, documentation, onboarding, and plugin readiness evidence.")
    parser.add_argument("--release-gates", default="build/release-gate-status.json")
    parser.add_argument("--operations-readiness-gate", default="build/operations-readiness/operations-readiness-gate.json")
    parser.add_argument("--enterprise-readiness", default="build/enterprise-readiness.json")
    parser.add_argument("--model-lifecycle-gate", default="build/evaluation/model-lifecycle-gate.json")
    parser.add_argument("--visual-regression-snapshots", default="build/visual-regression/visual-regression-snapshots.json")
    parser.add_argument("--onboarding-manifest", default="build/onboarding/onboarding-manifest.json")
    parser.add_argument("--plugin-gate", action="append", default=[])
    parser.add_argument("--required-doc", action="append", default=[])
    parser.add_argument("--external-approval", default="docs/project/external-approval-request-v1.2.3-rc.1.md")
    parser.add_argument("--out-json", default="build/open-source-readiness/open-source-readiness-gate.json")
    parser.add_argument("--out-md", default="build/open-source-readiness/open-source-readiness-gate.md")
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
