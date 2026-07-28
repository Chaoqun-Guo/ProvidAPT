#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.commercialization_readiness.v1"
DEFAULT_REQUIRED_DOCS = [
    "docs/project/commercial-release-checklist.md",
    "docs/project/customer-handoff.md",
    "docs/project/final-release-runbook.md",
    "docs/project/production-readiness.md",
    "docs/project/support-sla.md",
    "docs/project/third-party-notices.md",
    "docs/getting-started/commercial-install.md",
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
        "operations_readiness": {"status": status_value(load_json(Path(args.operations_readiness_gate)), {"pass", "warn"})},
        "enterprise_readiness": {"status": status_value(load_json(Path(args.enterprise_readiness)), {"pass", "warn"})},
        "onboarding_bundle": onboarding_detail(load_json(Path(args.onboarding_manifest))),
        "plugin_release_gates": plugin_detail(plugin_reports),
        "commercial_documentation": validate_docs(docs),
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
        "# ProvidAPT Commercialization Readiness",
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
    parser = argparse.ArgumentParser(description="Aggregate commercialization, documentation, onboarding, and plugin readiness evidence.")
    parser.add_argument("--operations-readiness-gate", default="build/operations-readiness/operations-readiness-gate.json")
    parser.add_argument("--enterprise-readiness", default="build/enterprise-readiness.json")
    parser.add_argument("--onboarding-manifest", default="build/onboarding/onboarding-manifest.json")
    parser.add_argument("--plugin-gate", action="append", default=[])
    parser.add_argument("--required-doc", action="append", default=[])
    parser.add_argument("--external-approval", default="docs/project/external-approval-request-v1.2.3-rc.1.md")
    parser.add_argument("--out-json", default="build/commercialization-readiness/commercialization-readiness-gate.json")
    parser.add_argument("--out-md", default="build/commercialization-readiness/commercialization-readiness-gate.md")
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
