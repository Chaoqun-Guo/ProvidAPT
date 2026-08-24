#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.open_source_release_gate.v1"
PASS_STATUSES = {"pass", "waived", "available", "planned"}
WARN_STATUSES = {"warn", "warning", "skipped"}
REQUIRED_LEGAL_DOCS = [
    "LICENSE",
    "PRIVACY.md",
    "SECURITY.md",
    "CLA.md",
    "docs/compliance/security-privacy.md",
    "docs/compliance/privacy-impact.md",
]
REQUIRED_DELIVERY_DOCS = [
    "docs/project/release-artifact-matrix.md",
    "docs/project/operator-handoff.md",
    "docs/user-guide/upgrade-rollback.md",
    "docs/getting-started/install.md",
    "docs/getting-started/docker-compose.md",
]


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    return data if isinstance(data, dict) else {}


def status_of(report: dict[str, Any], pass_values: set[str] | None = None) -> str:
    if not report:
        return "blocked"
    status = str(report.get("status", "")).lower()
    if status in (pass_values or PASS_STATUSES):
        return "pass"
    if status in WARN_STATUSES:
        return "warn"
    return "blocked"


def release_gate_detail(report: dict[str, Any], allow_skipped_ci: bool) -> dict[str, Any]:
    gates = report.get("gates") if isinstance(report.get("gates"), list) else []
    failures: list[str] = []
    warnings: list[str] = []
    summary: dict[str, str] = {}
    for gate in gates:
        if not isinstance(gate, dict):
            continue
        name = str(gate.get("name") or "gate")
        status = str(gate.get("status") or "").lower()
        summary[name] = status
        if status in PASS_STATUSES:
            continue
        if status == "skipped" and name == "github_actions":
            if allow_skipped_ci:
                warnings.append("GitHub Actions evidence was skipped for a controlled local handoff")
            else:
                failures.append("github_actions: GitHub Actions evidence is skipped")
            continue
        if status in WARN_STATUSES:
            warnings.append(f"{name}: {gate.get('message', status)}")
            continue
        failures.append(f"{name}: {gate.get('message', status or 'missing status')}")
    if not gates:
        failures.append("release gate status evidence is missing")
    return {
        "status": "blocked" if failures else ("warn" if warnings else "pass"),
        "gate_count": len(gates),
        "summary": summary,
        "failures": failures,
        "warnings": warnings,
    }


def package_smoke_detail(path: Path) -> dict[str, Any]:
    expected_any = [
        ["deb-config-check.txt"],
        ["rpm-config-check.txt", "rpm-info.txt"],
        ["tar-providaptctl-path.txt"],
    ]
    missing_groups: list[str] = []
    present: list[str] = []
    if not path.exists():
        return {"status": "blocked", "path": str(path), "present": [], "failures": ["package smoke evidence directory is missing"]}
    for group in expected_any:
        found = [name for name in group if (path / name).exists() and (path / name).stat().st_size > 0]
        if found:
            present.extend(found)
        else:
            missing_groups.append(" or ".join(group))
    return {
        "status": "pass" if not missing_groups else "blocked",
        "path": str(path),
        "present": sorted(present),
        "failures": ["missing package smoke evidence: " + ", ".join(missing_groups)] if missing_groups else [],
    }


def dist_artifact_detail(path: Path) -> dict[str, Any]:
    required_patterns = {
        "archive": ["*.tar.gz"],
        "deb": ["*.deb"],
        "rpm": ["*.rpm"],
        "helm": ["*helm*.tgz", "*chart*.tgz"],
        "spdx_sbom": ["*.spdx.json"],
        "cyclonedx_sbom": ["*.cdx.json"],
        "checksums": ["checksums.txt"],
        "checksum_signature": ["checksums.txt.sig"],
        "readiness_report": ["release-readiness.md"],
    }
    missing: list[str] = []
    found: dict[str, list[str]] = {}
    for name, patterns in required_patterns.items():
        matches = []
        if path.exists():
            for pattern in patterns:
                matches.extend(str(item) for item in sorted(path.glob(pattern)) if item.is_file() and item.stat().st_size > 0)
        found[name] = matches
        if not matches:
            missing.append(name)
    return {
        "status": "pass" if not missing else "blocked",
        "path": str(path),
        "found": found,
        "failures": ["missing release artifacts: " + ", ".join(missing)] if missing else [],
    }


def artifact_signing_detail(report: dict[str, Any]) -> dict[str, Any]:
    if not report:
        return {
            "status": "blocked",
            "failures": ["artifact signing gate evidence is missing; run make artifact-signing-gate"],
        }
    status = status_of(report)
    signature = report.get("signature") if isinstance(report.get("signature"), dict) else {}
    return {
        "status": status,
        "source_status": report.get("status", "missing"),
        "artifact_count": report.get("artifact_count", 0),
        "signature_format": signature.get("format", ""),
        "signature_verification": signature.get("verification", ""),
        "failures": list(report.get("failures") or []) if status == "blocked" else [],
        "warnings": list(report.get("warnings") or []) if status == "warn" else [],
    }


def release_evidence_consistency_detail(report: dict[str, Any]) -> dict[str, Any]:
    if not report:
        return {
            "status": "blocked",
            "failures": ["release evidence consistency gate is missing; run make release-evidence-consistency-gate"],
        }
    status = status_of(report)
    return {
        "status": status,
        "source_status": report.get("status", "missing"),
        "version": report.get("version", ""),
        "commit": report.get("full_commit") or report.get("commit", ""),
        "failures": list(report.get("failures") or []) if status == "blocked" else [],
        "warnings": list(report.get("warnings") or []) if status == "warn" else [],
    }


def docs_detail(paths: list[str]) -> dict[str, Any]:
    missing: list[str] = []
    empty: list[str] = []
    placeholders: list[str] = []
    markers = ["todo", "tbd", "pending", "requires owner", "external owner required", "not signed"]
    for value in paths:
        path = Path(value)
        if not path.exists():
            missing.append(value)
            continue
        if path.stat().st_size == 0:
            empty.append(value)
            continue
        text = path.read_text(encoding="utf-8-sig", errors="replace").lower()
        if any(marker in text for marker in markers):
            placeholders.append(value)
    failures = []
    if missing:
        failures.append("missing documents: " + ", ".join(missing))
    if empty:
        failures.append("empty documents: " + ", ".join(empty))
    warnings = ["documents contain unresolved placeholders: " + ", ".join(placeholders)] if placeholders else []
    return {
        "status": "blocked" if failures else ("warn" if warnings else "pass"),
        "document_count": len(paths),
        "missing_count": len(missing),
        "placeholder_count": len(placeholders),
        "failures": failures,
        "warnings": warnings,
    }


def readiness_detail(report: dict[str, Any], name: str, allow_warn: bool = False) -> dict[str, Any]:
    status = status_of(report, {"pass", "warn"} if allow_warn else {"pass"})
    if status == "warn" and not allow_warn:
        status = "blocked"
    return {
        "status": status,
        "source_status": report.get("status", "missing") if report else "missing",
        "failures": [] if status != "blocked" else [f"{name} evidence is missing or not passing"],
    }


def overall_status(sections: dict[str, dict[str, Any]]) -> str:
    statuses = [section.get("status") for section in sections.values()]
    if any(status == "blocked" for status in statuses):
        return "blocked"
    if any(status == "warn" for status in statuses):
        return "warn"
    return "pass"


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    sections = {
        "release_gates": release_gate_detail(load_json(Path(args.release_gates)), args.allow_skipped_ci),
        "dist_artifacts": dist_artifact_detail(Path(args.dist_dir)),
        "artifact_signing": artifact_signing_detail(load_json(Path(args.artifact_signing_gate))),
        "release_evidence_consistency": release_evidence_consistency_detail(load_json(Path(args.release_evidence_consistency_gate))),
        "package_smoke": package_smoke_detail(Path(args.package_smoke_dir)),
        "production_readiness": readiness_detail(load_json(Path(args.production_readiness_gate)), "production readiness"),
        "ml_readiness": readiness_detail(load_json(Path(args.ml_readiness_gate)), "ML readiness"),
        "operations_readiness": readiness_detail(load_json(Path(args.operations_readiness_gate)), "operations readiness", allow_warn=True),
        "open_source_readiness": readiness_detail(load_json(Path(args.open_source_readiness_gate)), "open source readiness", allow_warn=True),
        "legal_documents": docs_detail(args.legal_doc or REQUIRED_LEGAL_DOCS),
        "delivery_documents": docs_detail(args.delivery_doc or REQUIRED_DELIVERY_DOCS),
    }
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": overall_status(sections),
        "sections": sections,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Open Source Release Gate",
        "",
        f"- Status: `{report['status']}`",
        f"- Generated at: `{report['generated_at']}`",
        "",
        "| Section | Status | Detail |",
        "| --- | --- | --- |",
    ]
    failures: list[str] = []
    warnings: list[str] = []
    for name, section in report["sections"].items():
        detail = ", ".join(
            f"{key}={value}"
            for key, value in section.items()
            if key not in {"status", "failures", "warnings", "found", "summary"}
        )
        lines.append(f"| {name} | {section['status']} | {detail} |")
        failures.extend(f"{name}: {item}" for item in section.get("failures", []))
        warnings.extend(f"{name}: {item}" for item in section.get("warnings", []))
    if failures:
        lines.extend(["", "## Failures", ""])
        lines.extend(f"- {item}" for item in failures)
    if warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {item}" for item in warnings)
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate release evidence for open-source delivery.")
    parser.add_argument("--release-gates", default="build/release-gate-status.json")
    parser.add_argument("--dist-dir", default="dist")
    parser.add_argument("--artifact-signing-gate", default="build/artifact-signing/artifact-signing-gate.json")
    parser.add_argument("--release-evidence-consistency-gate", default="build/release-evidence/release-evidence-consistency-gate.json")
    parser.add_argument("--package-smoke-dir", default="build/package-smoke")
    parser.add_argument("--production-readiness-gate", default="build/production-readiness/production-readiness-gate.json")
    parser.add_argument("--ml-readiness-gate", default="build/ml-readiness/ml-readiness-gate.json")
    parser.add_argument("--operations-readiness-gate", default="build/operations-readiness/operations-readiness-gate.json")
    parser.add_argument("--open-source-readiness-gate", default="build/open-source-readiness/open-source-readiness-gate.json")
    parser.add_argument("--legal-doc", action="append", default=[])
    parser.add_argument("--delivery-doc", action="append", default=[])
    parser.add_argument("--allow-skipped-ci", action="store_true")
    parser.add_argument("--out-json", default="build/operator-release/operator-release-gate.json")
    parser.add_argument("--out-md", default="build/operator-release/operator-release-gate.md")
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
