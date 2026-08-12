#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.plugin_release_gate.v1"
SEMVER_RE = re.compile(r"^v?\d+\.\d+\.\d+([-.+][A-Za-z0-9.-]+)?$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
PERMISSION_RE = re.compile(r"^[a-z][a-z0-9_-]*:(read|write|execute|subscribe|publish)$")
SIGNATURE_ALGORITHMS = {"ed25519", "cosign", "minisign"}


def parse_semver(value: Any) -> tuple[int, int, int] | None:
    text = str(value or "").strip()
    if not SEMVER_RE.match(text):
        return None
    core = text.lstrip("v").split("-", 1)[0].split("+", 1)[0]
    major, minor, patch = core.split(".")
    return int(major), int(minor), int(patch)


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
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


def safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def validate_manifest(manifest: dict[str, Any], manifest_path: Path, signature_path: Path | None, allow_unsigned: bool) -> dict[str, Any]:
    required = ["name", "version", "type", "providapt_min_version"]
    missing = [key for key in required if not str(manifest.get(key, "")).strip()]
    warnings: list[str] = []
    failures: list[str] = []
    if missing:
        failures.append("missing required fields: " + ", ".join(missing))
    if manifest.get("version") and not SEMVER_RE.match(str(manifest["version"])):
        failures.append("version must be semantic version compatible")
    if manifest.get("providapt_min_version") and not SEMVER_RE.match(str(manifest["providapt_min_version"])):
        failures.append("providapt_min_version must be semantic version compatible")
    if manifest.get("providapt_max_version") and not SEMVER_RE.match(str(manifest["providapt_max_version"])):
        failures.append("providapt_max_version must be semantic version compatible")
    min_version = parse_semver(manifest.get("providapt_min_version"))
    max_version = parse_semver(manifest.get("providapt_max_version"))
    if min_version and max_version and min_version > max_version:
        failures.append("providapt_min_version must not be greater than providapt_max_version")
    plugin_type = str(manifest.get("type", "")).lower()
    if plugin_type not in {"detection", "scoring", "threatintel", "enrichment"}:
        failures.append("type must be detection, scoring, threatintel, or enrichment")
    entrypoint = str(manifest.get("entrypoint") or manifest.get("import_path") or "").strip()
    if not entrypoint:
        warnings.append("entrypoint/import_path is not set; compile-time registration must be documented")
    permissions = manifest.get("permissions")
    if permissions is None:
        failures.append("permissions are required for plugin distribution")
        permissions = []
    elif not isinstance(permissions, list):
        failures.append("permissions must be a list")
        permissions = []
    else:
        for permission in permissions:
            text = str(permission).strip()
            if text in {"*", "*:*", "admin", "root"}:
                failures.append(f"unsafe plugin permission: {text}")
            elif not text:
                failures.append("plugin permission entries must not be empty")
    distribution = manifest.get("distribution")
    if not isinstance(distribution, dict):
        failures.append("distribution policy is required")
        distribution = {}
    if distribution and not str(distribution.get("channel") or "").strip():
        failures.append("distribution.channel is required when distribution policy is declared")
    if distribution and not str(distribution.get("artifact") or "").strip():
        failures.append("distribution.artifact is required when distribution policy is declared")
    signature_algorithm = str(distribution.get("signature_algorithm") or "").strip().lower() if distribution else ""
    if distribution and not signature_algorithm:
        failures.append("distribution.signature_algorithm is required")
    elif signature_algorithm and signature_algorithm not in SIGNATURE_ALGORITHMS:
        failures.append("distribution.signature_algorithm must be ed25519, cosign, or minisign")
    artifact_sha256 = str(distribution.get("artifact_sha256") or "").strip() if distribution else ""
    if distribution and not artifact_sha256:
        failures.append("distribution.artifact_sha256 is required")
    elif artifact_sha256 and not SHA256_RE.match(artifact_sha256):
        failures.append("distribution.artifact_sha256 must be a SHA-256 hex digest")
    artifact_value = str(distribution.get("artifact") or "").strip() if distribution else ""
    artifact_path = (manifest_path.parent / artifact_value).resolve() if artifact_value and not Path(artifact_value).is_absolute() else Path(artifact_value)
    artifact_present = bool(artifact_value and artifact_path.exists() and artifact_path.is_file())
    artifact_hash_matches = False
    if artifact_present and artifact_sha256:
        artifact_hash_matches = sha256_file(artifact_path).lower() == artifact_sha256.lower()
        if not artifact_hash_matches:
            failures.append("distribution.artifact_sha256 does not match artifact file")
    elif artifact_value:
        warnings.append("distribution artifact file was not found next to the manifest; recorded hash could not be verified locally")
    for permission in permissions:
        text = str(permission).strip()
        if text and not PERMISSION_RE.match(text):
            failures.append(f"plugin permission must use scope:action with a least-privilege action: {text}")
    compatibility_tests = manifest.get("compatibility_tests")
    if not isinstance(compatibility_tests, list) or not compatibility_tests:
        failures.append("compatibility_tests with at least one passing ProvidAPT version are required")
        compatibility_passes: list[dict[str, Any]] = []
    else:
        compatibility_passes = []
        for index, item in enumerate(compatibility_tests, 1):
            row = item if isinstance(item, dict) else {}
            version = str(row.get("providapt_version") or "").strip()
            status_value = str(row.get("status") or "").strip().lower()
            if not version or not SEMVER_RE.match(version):
                failures.append(f"compatibility_tests[{index}].providapt_version must be semantic version compatible")
            if status_value != "pass":
                failures.append(f"compatibility_tests[{index}].status must be pass")
            if version and status_value == "pass":
                compatibility_passes.append(row)
    rollback = manifest.get("rollback")
    if not isinstance(rollback, list) or not rollback:
        failures.append("rollback instructions are required")
        rollback_steps: list[str] = []
    else:
        rollback_steps = []
        for step in rollback:
            text = str(step).strip()
            if not text:
                failures.append("rollback steps must not be empty")
            else:
                rollback_steps.append(text)
    rollback_drill = manifest.get("rollback_drill")
    if not isinstance(rollback_drill, dict):
        failures.append("rollback_drill evidence is required")
        rollback_drill_summary: dict[str, Any] = {}
    else:
        rollback_drill_summary = {
            "status": str(rollback_drill.get("status") or "").strip().lower(),
            "tested_at": str(rollback_drill.get("tested_at") or "").strip(),
            "tested_by": str(rollback_drill.get("tested_by") or "").strip(),
            "steps_verified": safe_int(rollback_drill.get("steps_verified")),
        }
        if rollback_drill_summary["status"] != "pass":
            failures.append("rollback_drill.status must be pass")
        if not rollback_drill_summary["tested_at"]:
            failures.append("rollback_drill.tested_at is required")
        if not rollback_drill_summary["tested_by"]:
            failures.append("rollback_drill.tested_by is required")
        if rollback_drill_summary["steps_verified"] < len(rollback_steps):
            failures.append("rollback_drill.steps_verified must cover all rollback steps")
    signature_present = bool(signature_path and signature_path.exists() and signature_path.stat().st_size > 0)
    if not signature_present and not allow_unsigned:
        failures.append("plugin signature evidence is required")
    status = "pass" if not failures else "blocked"
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "manifest_path": str(manifest_path),
        "manifest_sha256": sha256_file(manifest_path),
        "signature_path": str(signature_path) if signature_path else "",
        "signature_present": signature_present,
        "plugin": {
            "name": manifest.get("name", ""),
            "version": manifest.get("version", ""),
            "type": manifest.get("type", ""),
            "compatibility": {
                "providapt_min_version": manifest.get("providapt_min_version", ""),
                "providapt_max_version": manifest.get("providapt_max_version", ""),
            },
            "entrypoint": entrypoint,
            "permissions": permissions,
            "distribution": distribution,
            "artifact": {
                "path": str(artifact_path) if artifact_value else "",
                "present": artifact_present,
                "hash_matches": artifact_hash_matches,
            },
            "compatibility_tests": compatibility_tests if isinstance(compatibility_tests, list) else [],
            "compatibility_pass_count": len(compatibility_passes),
        },
        "failures": failures,
        "warnings": warnings,
        "rollback": rollback_steps,
        "rollback_drill": rollback_drill_summary,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Plugin Release Gate",
        "",
        f"- Status: `{report['status']}`",
        f"- Plugin: `{report['plugin']['name']}`",
        f"- Version: `{report['plugin']['version']}`",
        f"- ProvidAPT min version: `{report['plugin']['compatibility']['providapt_min_version']}`",
        f"- ProvidAPT max version: `{report['plugin']['compatibility']['providapt_max_version'] or 'unbounded'}`",
        f"- Manifest SHA-256: `{report['manifest_sha256']}`",
        f"- Signature present: `{report['signature_present']}`",
        f"- Permissions: `{json.dumps(report['plugin'].get('permissions', []), sort_keys=True)}`",
        f"- Distribution: `{json.dumps(report['plugin'].get('distribution', {}), sort_keys=True)}`",
        f"- Artifact present: `{report['plugin']['artifact']['present']}`",
        f"- Artifact hash matches: `{report['plugin']['artifact']['hash_matches']}`",
        f"- Compatibility tests passed: `{report['plugin']['compatibility_pass_count']}`",
        f"- Rollback drill: `{json.dumps(report.get('rollback_drill', {}), sort_keys=True)}`",
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
    lines.extend(["## Rollback", ""])
    lines.extend(f"- {item}" for item in report["rollback"])
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate plugin release manifest, signature evidence, compatibility, and rollback notes.")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--signature")
    parser.add_argument("--allow-unsigned", action="store_true")
    parser.add_argument("--out-json", default="build/plugins/plugin-release-gate.json")
    parser.add_argument("--out-md", default="build/plugins/plugin-release-gate.md")
    args = parser.parse_args()
    manifest_path = Path(args.manifest)
    signature_path = Path(args.signature) if args.signature else None
    report = validate_manifest(load_json(manifest_path), manifest_path, signature_path, args.allow_unsigned)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} plugin={report['plugin']['name']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
