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
    plugin_type = str(manifest.get("type", "")).lower()
    if plugin_type not in {"detection", "scoring", "threatintel", "enrichment"}:
        failures.append("type must be detection, scoring, threatintel, or enrichment")
    entrypoint = str(manifest.get("entrypoint") or manifest.get("import_path") or "").strip()
    if not entrypoint:
        warnings.append("entrypoint/import_path is not set; compile-time registration must be documented")
    permissions = manifest.get("permissions")
    if permissions is None:
        warnings.append("permissions are not declared; plugin permission model should be explicit before production distribution")
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
        warnings.append("distribution policy is not declared")
        distribution = {}
    if distribution and not str(distribution.get("channel") or "").strip():
        failures.append("distribution.channel is required when distribution policy is declared")
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
            "providapt_min_version": manifest.get("providapt_min_version", ""),
            "providapt_max_version": manifest.get("providapt_max_version", ""),
            "entrypoint": entrypoint,
            "permissions": permissions,
            "distribution": distribution,
        },
        "failures": failures,
        "warnings": warnings,
        "rollback": [
            "disable the plugin in providapt.toml",
            "restore the previous signed plugin manifest",
            "restart affected agents or wait for next policy poll",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Plugin Release Gate",
        "",
        f"- Status: `{report['status']}`",
        f"- Plugin: `{report['plugin']['name']}`",
        f"- Version: `{report['plugin']['version']}`",
        f"- Manifest SHA-256: `{report['manifest_sha256']}`",
        f"- Signature present: `{report['signature_present']}`",
        f"- Permissions: `{json.dumps(report['plugin'].get('permissions', []), sort_keys=True)}`",
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
