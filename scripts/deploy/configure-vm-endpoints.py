#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = "providapt.vm_endpoint_config.v1"


def update_endpoints(text: str, telemetry_endpoint: str, policy_endpoint: str) -> tuple[str, dict[str, bool]]:
    section = ""
    seen = {"telemetry": False, "policy": False}
    changed = {"telemetry": False, "policy": False}
    lines: list[str] = []
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped and not line.startswith((" ", "\t")) and stripped.endswith(":"):
            section = stripped[:-1]
        if section in ("telemetry", "policy") and stripped.startswith("endpoint:"):
            newline = "\n" if line.endswith("\n") else ""
            indent = line[: len(line) - len(line.lstrip())]
            value = telemetry_endpoint if section == "telemetry" else policy_endpoint
            replacement = f'{indent}endpoint: "{value}"{newline}'
            lines.append(replacement)
            seen[section] = True
            changed[section] = replacement != line
            continue
        lines.append(line)
    missing = [key for key, ok in seen.items() if not ok]
    if missing:
        raise ValueError("missing endpoint field(s): " + ", ".join(missing))
    return "".join(lines), changed


def legacy_hits(text: str, markers: list[str]) -> list[str]:
    return [marker for marker in markers if marker and marker in text]


def main() -> int:
    parser = argparse.ArgumentParser(description="Update or validate ProvidAPT VM agent control-plane endpoints.")
    parser.add_argument("config", help="Path to /etc/providapt/providapt.toml or a copied config file")
    parser.add_argument("--control-host", required=True, help="Control-plane DNS name, for example vm-ubuntu-master.<TAILSCALE_DOMAIN>")
    parser.add_argument("--grpc-port", default="50051")
    parser.add_argument("--rest-port", default="18080")
    parser.add_argument("--in-place", action="store_true", help="Rewrite the config file")
    parser.add_argument("--backup", action="store_true", help="Create a timestamped backup before --in-place rewrite")
    parser.add_argument("--reject-marker", action="append", default=["192.168.150."], help="Fail when a marker remains after rendering")
    args = parser.parse_args()

    config = Path(args.config)
    if not config.exists():
        raise SystemExit(f"config not found: {config}")
    original = config.read_text(encoding="utf-8")
    telemetry_endpoint = f"{args.control_host}:{args.grpc_port}"
    policy_endpoint = f"http://{args.control_host}:{args.rest_port}"
    rendered, changed = update_endpoints(original, telemetry_endpoint, policy_endpoint)
    hits = legacy_hits(rendered, args.reject_marker)
    report = {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "config": str(config),
        "telemetry_endpoint": telemetry_endpoint,
        "policy_endpoint": policy_endpoint,
        "changed": changed,
        "legacy_markers": hits,
        "status": "pass" if not hits else "blocked",
    }
    if hits:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1
    if args.in_place and rendered != original:
        if args.backup:
            backup = config.with_name(config.name + ".bak-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
            backup.write_text(original, encoding="utf-8")
            report["backup"] = str(backup)
        config.write_text(rendered, encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
