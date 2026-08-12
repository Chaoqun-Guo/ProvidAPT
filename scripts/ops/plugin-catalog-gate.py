#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.plugin_catalog_gate.v1"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        raise SystemExit(f"missing JSON file: {path}")
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected JSON object")
    return data


def plugin_identity(report: dict[str, Any]) -> tuple[str, str]:
    plugin = report.get("plugin") if isinstance(report.get("plugin"), dict) else {}
    return str(plugin.get("name") or "").strip(), str(plugin.get("version") or "").strip()


def plugin_summary(path: Path, report: dict[str, Any]) -> dict[str, Any]:
    plugin = report.get("plugin") if isinstance(report.get("plugin"), dict) else {}
    distribution = plugin.get("distribution") if isinstance(plugin.get("distribution"), dict) else {}
    compatibility = plugin.get("compatibility") if isinstance(plugin.get("compatibility"), dict) else {}
    artifact = plugin.get("artifact") if isinstance(plugin.get("artifact"), dict) else {}
    rollback_drill = report.get("rollback_drill") if isinstance(report.get("rollback_drill"), dict) else {}
    permissions = plugin.get("permissions") if isinstance(plugin.get("permissions"), list) else []
    return {
        "path": str(path),
        "status": str(report.get("status") or "missing"),
        "name": str(plugin.get("name") or ""),
        "version": str(plugin.get("version") or ""),
        "type": str(plugin.get("type") or ""),
        "signature_present": bool(report.get("signature_present")),
        "permissions": permissions,
        "permission_count": len(permissions),
        "channel": str(distribution.get("channel") or ""),
        "artifact": str(distribution.get("artifact") or ""),
        "artifact_sha256_present": bool(str(distribution.get("artifact_sha256") or "").strip()),
        "artifact_present": bool(artifact.get("present")),
        "artifact_hash_matches": bool(artifact.get("hash_matches")),
        "providapt_min_version": str(compatibility.get("providapt_min_version") or ""),
        "providapt_max_version": str(compatibility.get("providapt_max_version") or ""),
        "compatibility_pass_count": int(plugin.get("compatibility_pass_count") or 0),
        "rollback_steps": len(report.get("rollback") or []) if isinstance(report.get("rollback"), list) else 0,
        "rollback_drill_status": str(rollback_drill.get("status") or ""),
        "rollback_drill_steps_verified": int(rollback_drill.get("steps_verified") or 0),
        "failures": list(report.get("failures") or []),
        "warnings": list(report.get("warnings") or []),
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    failures: list[str] = []
    warnings: list[str] = []
    plugins: list[dict[str, Any]] = []
    seen: dict[tuple[str, str], str] = {}
    for path_value in args.plugin_gate:
        path = Path(path_value)
        report = load_json(path)
        item = plugin_summary(path, report)
        plugins.append(item)
        identity = (item["name"], item["version"])
        if not item["name"] or not item["version"]:
            failures.append(f"{path}: plugin name/version is missing")
        elif identity in seen:
            failures.append(f"duplicate plugin identity {item['name']}:{item['version']} in {seen[identity]} and {path}")
        else:
            seen[identity] = str(path)
        if item["status"] != "pass":
            failures.append(f"{item['name'] or path}: plugin release gate is {item['status']}")
        if args.require_signatures and not item["signature_present"]:
            failures.append(f"{item['name'] or path}: signature is missing")
        if args.require_permissions and item["permission_count"] <= 0:
            failures.append(f"{item['name'] or path}: permissions are missing")
        if not item["channel"] or not item["artifact"]:
            failures.append(f"{item['name'] or path}: distribution channel/artifact is missing")
        if not item["artifact_sha256_present"]:
            failures.append(f"{item['name'] or path}: artifact SHA-256 evidence is missing")
        if item["compatibility_pass_count"] <= 0:
            failures.append(f"{item['name'] or path}: compatibility pass evidence is missing")
        if item["rollback_steps"] <= 0:
            failures.append(f"{item['name'] or path}: rollback steps are missing")
        if item["rollback_drill_status"] != "pass":
            failures.append(f"{item['name'] or path}: rollback drill did not pass")
        if item["rollback_drill_steps_verified"] < item["rollback_steps"]:
            failures.append(f"{item['name'] or path}: rollback drill does not cover all steps")
        warnings.extend(f"{item['name'] or path}: {warning}" for warning in item["warnings"])
    if not plugins and args.require_plugins:
        failures.append("plugin catalog is empty")
    status = "blocked" if failures else "warn" if warnings else "pass"
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "plugin_count": len(plugins),
        "require_plugins": args.require_plugins,
        "require_signatures": args.require_signatures,
        "require_permissions": args.require_permissions,
        "plugins": plugins,
        "failures": failures,
        "warnings": warnings,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Plugin Catalog Gate",
        "",
        f"- Status: `{report['status']}`",
        f"- Plugins: `{report['plugin_count']}`",
        "",
        "| Plugin | Version | Type | Status | Signed | Permissions | Compatibility Passes | Channel | Artifact Hash | Rollback Drill |",
        "| --- | --- | --- | --- | --- | ---: | ---: | --- | --- | --- |",
    ]
    for item in report["plugins"]:
        lines.append(
            "| {name} | {version} | {type} | {status} | {signed} | {permission_count} | {compatibility_pass_count} | {channel} | {artifact_hash} | {rollback_drill} |".format(
                name=escape_cell(item["name"]),
                version=escape_cell(item["version"]),
                type=escape_cell(item["type"]),
                status=escape_cell(item["status"]),
                signed=str(item["signature_present"]).lower(),
                permission_count=item["permission_count"],
                compatibility_pass_count=item["compatibility_pass_count"],
                channel=escape_cell(item["channel"]),
                artifact_hash="present" if item["artifact_sha256_present"] else "missing",
                rollback_drill=escape_cell(item["rollback_drill_status"] or "missing"),
            )
        )
    if report["failures"]:
        lines.extend(["", "## Failures", ""])
        lines.extend(f"- {item}" for item in report["failures"])
    if report["warnings"]:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {item}" for item in report["warnings"])
    lines.append("")
    return "\n".join(lines)


def escape_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate signed plugin release gates into a distributable catalog decision.")
    parser.add_argument("--plugin-gate", action="append", default=[], help="plugin-release-gate JSON output")
    parser.add_argument("--require-plugins", action="store_true")
    parser.add_argument("--require-signatures", action="store_true")
    parser.add_argument("--require-permissions", action="store_true")
    parser.add_argument("--out-json", default="build/plugins/plugin-catalog-gate.json")
    parser.add_argument("--out-md", default="build/plugins/plugin-catalog-gate.md")
    args = parser.parse_args()
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} plugins={report['plugin_count']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
