#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.release_evidence_consistency.v1"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        return {}
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    return data if isinstance(data, dict) else {}


def run_git(args: list[str]) -> str:
    proc = subprocess.run(["git", *args], text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else ""


def text_contains_commit(text: str, short_commit: str, full_commit: str) -> bool:
    if full_commit and full_commit in text:
        return True
    return bool(short_commit and short_commit in text)


def sbom_detail(dist_dir: Path, version: str) -> tuple[dict[str, Any], list[str], list[str]]:
    failures: list[str] = []
    warnings: list[str] = []
    spdx = sorted(dist_dir.glob("*.spdx.json"))
    cdx = sorted(dist_dir.glob("*.cdx.json"))
    if not spdx:
        failures.append("SPDX SBOM is missing")
    if not cdx:
        failures.append("CycloneDX SBOM is missing")
    found_versions: list[str] = []
    for path in spdx + cdx:
        data = load_json(path)
        text = json.dumps(data, sort_keys=True)
        if version and version not in text:
            warnings.append(f"{path.name} does not mention release version {version}")
        found_versions.append(path.name)
    return {
        "spdx_count": len(spdx),
        "cyclonedx_count": len(cdx),
        "files": found_versions,
    }, failures, warnings


def readiness_detail(path: Path, short_commit: str, full_commit: str, version: str) -> tuple[dict[str, Any], list[str], list[str]]:
    failures: list[str] = []
    warnings: list[str] = []
    if not path.exists() or path.stat().st_size == 0:
        return {"path": str(path), "present": False}, ["release readiness report is missing"], []
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text_contains_commit(text, short_commit, full_commit):
        failures.append("release readiness report does not reference current commit")
    if version and version not in text:
        failures.append("release readiness report does not reference current version")
    status_match = re.search(r"status[:\s`-]+([A-Za-z_ -]+)", text, flags=re.IGNORECASE)
    return {
        "path": str(path),
        "present": True,
        "mentions_commit": text_contains_commit(text, short_commit, full_commit),
        "mentions_version": bool(version and version in text),
        "status_hint": status_match.group(1).strip()[:40] if status_match else "",
    }, failures, warnings


def scan_manifest_detail(path: Path, full_commit: str, version: str) -> tuple[dict[str, Any], list[str], list[str]]:
    failures: list[str] = []
    warnings: list[str] = []
    manifest = load_json(path)
    if not manifest:
        return {"path": str(path), "present": False}, ["scan manifest is missing"], []
    if manifest.get("schema") != "providapt.security_scan_manifest.v1":
        failures.append("scan manifest schema is invalid")
    manifest_commit = str(manifest.get("full_commit") or manifest.get("commit") or "")
    if full_commit and manifest_commit != full_commit:
        failures.append(f"scan manifest commit mismatch: {manifest_commit or 'missing'}")
    manifest_version = str(manifest.get("version") or "")
    if version and manifest_version and manifest_version != version:
        warnings.append(f"scan manifest version differs from current version: {manifest_version}")
    reports = manifest.get("reports") if isinstance(manifest.get("reports"), dict) else {}
    missing_reports = sorted(key for key, value in reports.items() if str(value).lower() != "present")
    if missing_reports:
        failures.append("scan manifest marks reports missing: " + ", ".join(missing_reports))
    return {
        "path": str(path),
        "present": True,
        "commit": manifest_commit,
        "version": manifest_version,
        "missing_reports": missing_reports,
    }, failures, warnings


def artifact_signing_detail(report: dict[str, Any]) -> tuple[dict[str, Any], list[str], list[str]]:
    if not report:
        return {"present": False}, ["artifact signing gate evidence is missing"], []
    failures = list(report.get("failures") or []) if report.get("status") != "pass" else []
    warnings = list(report.get("warnings") or [])
    return {
        "present": True,
        "status": report.get("status", ""),
        "artifact_count": report.get("artifact_count", 0),
        "signature_format": (report.get("signature") or {}).get("format", "") if isinstance(report.get("signature"), dict) else "",
    }, failures, warnings


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    dist_dir = Path(args.dist_dir)
    full_commit = args.full_commit or run_git(["rev-parse", "HEAD"])
    short_commit = args.commit or run_git(["rev-parse", "--short", "HEAD"])
    version = args.version or run_git(["describe", "--tags", "--always"])
    failures: list[str] = []
    warnings: list[str] = []
    readiness, readiness_failures, readiness_warnings = readiness_detail(Path(args.release_readiness), short_commit, full_commit, version)
    scan, scan_failures, scan_warnings = scan_manifest_detail(Path(args.scan_manifest), full_commit, version)
    signing, signing_failures, signing_warnings = artifact_signing_detail(load_json(Path(args.artifact_signing_gate)))
    sbom, sbom_failures, sbom_warnings = sbom_detail(dist_dir, version)
    for items in (readiness_failures, scan_failures, signing_failures, sbom_failures):
        failures.extend(items)
    for items in (readiness_warnings, scan_warnings, signing_warnings, sbom_warnings):
        warnings.extend(items)
    status = "blocked" if failures else "warn" if warnings else "pass"
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "version": version,
        "commit": short_commit,
        "full_commit": full_commit,
        "dist_dir": str(dist_dir),
        "release_readiness": readiness,
        "scan_manifest": scan,
        "artifact_signing": signing,
        "sbom": sbom,
        "failures": failures,
        "warnings": warnings,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Release Evidence Consistency Gate",
        "",
        f"- Status: `{report['status']}`",
        f"- Version: `{report['version']}`",
        f"- Commit: `{report['full_commit']}`",
        f"- Dist: `{report['dist_dir']}`",
        "",
        "| Evidence | Detail |",
        "| --- | --- |",
        f"| Release readiness | present={report['release_readiness'].get('present')} mentions_commit={report['release_readiness'].get('mentions_commit')} mentions_version={report['release_readiness'].get('mentions_version')} |",
        f"| Scan manifest | present={report['scan_manifest'].get('present')} commit={report['scan_manifest'].get('commit', '')} |",
        f"| Artifact signing | present={report['artifact_signing'].get('present')} status={report['artifact_signing'].get('status', '')} artifacts={report['artifact_signing'].get('artifact_count', 0)} |",
        f"| SBOM | spdx={report['sbom'].get('spdx_count', 0)} cyclonedx={report['sbom'].get('cyclonedx_count', 0)} |",
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
    parser = argparse.ArgumentParser(description="Check release evidence consistency across dist, SBOM, scans, signing, version, and commit.")
    parser.add_argument("--dist-dir", default="dist")
    parser.add_argument("--release-readiness", default="dist/release-readiness.md")
    parser.add_argument("--scan-manifest", default="build/security/scan-manifest.json")
    parser.add_argument("--artifact-signing-gate", default="build/artifact-signing/artifact-signing-gate.json")
    parser.add_argument("--version", default="")
    parser.add_argument("--commit", default="")
    parser.add_argument("--full-commit", default="")
    parser.add_argument("--out-json", default="build/release-evidence/release-evidence-consistency-gate.json")
    parser.add_argument("--out-md", default="build/release-evidence/release-evidence-consistency-gate.md")
    args = parser.parse_args()
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} version={report['version']} commit={report['commit']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
