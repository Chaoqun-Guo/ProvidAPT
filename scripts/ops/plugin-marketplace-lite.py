#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.plugin_marketplace_lite.v1"


def load_json(path_value: str) -> dict[str, Any]:
    path = Path(path_value)
    if not path.exists() or path.stat().st_size == 0:
        return {}
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    return data if isinstance(data, dict) else {}


def marketplace_entry(item: dict[str, Any]) -> dict[str, Any]:
    name = str(item.get("name") or "")
    version = str(item.get("version") or "")
    signed = bool(item.get("signed"))
    sig_match = bool(item.get("signature_hash_matches"))
    return {
        "manifest": f"{name}:{version}",
        "name": name,
        "version": version,
        "artifact": str(item.get("artifact") or ""),
        "permissions": item.get("permissions") if isinstance(item.get("permissions"), list) else [],
        "signature_status": "verified" if signed and sig_match else "missing",
        "compatible_from": str(item.get("providapt_min_version") or ""),
        "compatible_until": str(item.get("providapt_max_version") or ""),
        "rollback": str(item.get("rollback_drill_status") or "missing"),
        "test_evidence": {
            "compatibility_pass_count": int(item.get("compatibility_pass_count") or 0),
            "signature_hash_matches": sig_match,
        },
    }


def build_marketplace(args: argparse.Namespace) -> dict[str, Any]:
    catalog = load_json(args.plugin_catalog)
    entries = [marketplace_entry(item) for item in catalog.get("distribution_catalog", []) if isinstance(item, dict)]
    status = "blocked" if str(catalog.get("status") or "missing") == "blocked" else "pass" if entries else "warn"
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "source_catalog": args.plugin_catalog,
        "plugin_count": len(entries),
        "plugins": entries,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Plugin Marketplace Lite",
        "",
        f"- Status: `{report['status']}`",
        f"- Plugins: `{report['plugin_count']}`",
        "",
        "| Plugin | Signature | Compatibility | Permissions | Rollback | Artifact |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in report["plugins"]:
        compatibility = item["compatible_from"] or "unbounded"
        if item["compatible_until"]:
            compatibility += "..." + item["compatible_until"]
        lines.append(
            "| {manifest} | {signature} | {compatibility} | {permissions} | {rollback} | {artifact} |".format(
                manifest=item["manifest"],
                signature=item["signature_status"],
                compatibility=compatibility,
                permissions=", ".join(item["permissions"]),
                rollback=item["rollback"],
                artifact=item["artifact"],
            )
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Render a lightweight open-source plugin marketplace catalog.")
    parser.add_argument("--plugin-catalog", default="build/plugins/plugin-catalog-gate.json")
    parser.add_argument("--out-json", default="build/plugins/plugin-marketplace-lite.json")
    parser.add_argument("--out-md", default="build/plugins/plugin-marketplace-lite.md")
    args = parser.parse_args()
    report = build_marketplace(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"plugin marketplace lite: status={report['status']} plugins={report['plugin_count']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
