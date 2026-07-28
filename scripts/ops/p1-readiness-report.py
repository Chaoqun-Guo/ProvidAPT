#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.p1_readiness.v1"
REQUIRED_SECRET_OUTPUTS = {
    "systemd_dropin",
    "docker_compose",
    "kubernetes_secret",
    "vault_policy",
    "vault_loader",
    "vault_config",
}


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"missing required JSON file: {path}")
    data = json.loads(path.read_text(encoding="utf-8").lstrip("\ufeff"))
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected JSON object")
    return data


def fetch_json(base_url: str, path: str, api_key: str = "", timeout: float = 10.0) -> dict[str, Any]:
    request = urllib.request.Request(base_url.rstrip("/") + path)
    if api_key:
        request.add_header("X-API-Key", api_key)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
    except urllib.error.URLError as exc:
        raise SystemExit(f"fetch failed for {path}: {exc}") from exc
    data = json.loads(body.decode("utf-8").lstrip("\ufeff"))
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected JSON object")
    return data


def check_secret_backends(manifest: dict[str, Any]) -> dict[str, Any]:
    outputs = manifest.get("outputs") or {}
    present = {key for key, value in outputs.items() if value}
    missing = sorted(REQUIRED_SECRET_OUTPUTS - present)
    variables = manifest.get("variable_count", 0)
    vault = manifest.get("vault") or {}
    failures: list[str] = []
    if missing:
        failures.append("missing secret backend outputs: " + ", ".join(missing))
    if not isinstance(variables, int) or variables < 1:
        failures.append("secret backend manifest has no variables")
    if not vault.get("mount") or not vault.get("path_prefix"):
        failures.append("vault backend mount/path_prefix missing")
    return {
        "status": "pass" if not failures else "blocked",
        "variables": variables,
        "outputs": sorted(present),
        "vault": vault,
        "failures": failures,
    }


def check_tls_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    server = manifest.get("server") or {}
    ca = manifest.get("ca") or {}
    agents = manifest.get("agents") or []
    for label, section in [("ca", ca), ("server", server)]:
        if not section.get("cert") or not section.get("key"):
            failures.append(f"{label} cert/key missing")
        if not section.get("fingerprint_sha256"):
            failures.append(f"{label} fingerprint missing")
    if not isinstance(agents, list) or not agents:
        failures.append("no agent certificates listed")
    return {
        "status": "pass" if not failures else "blocked",
        "server_cn": server.get("cn", ""),
        "server_san": server.get("san", ""),
        "agent_count": len(agents) if isinstance(agents, list) else 0,
        "failures": failures,
    }


def check_postgres(report: dict[str, Any]) -> dict[str, Any]:
    backup = report.get("backup") or {}
    schema_check = report.get("schema_check") or {}
    failures: list[str] = []
    if backup.get("status") != "pass":
        failures.append("postgres backup did not pass")
    if int(backup.get("bytes") or 0) <= 0:
        failures.append("postgres backup is empty")
    if schema_check.get("status") not in {"pass", "skipped"}:
        failures.append("postgres schema check failed")
    return {
        "status": "pass" if not failures else "blocked",
        "backup_bytes": backup.get("bytes", 0),
        "restore_status": (report.get("restore") or {}).get("status", ""),
        "schema_status": schema_check.get("status", ""),
        "failures": failures,
    }


def report_age(agent: dict[str, Any], default: int = 999999) -> int:
    try:
        return int(agent.get("last_report_age_seconds", default))
    except (TypeError, ValueError):
        return default


def check_fleet(fleet: dict[str, Any], min_agents: int, min_healthy: int, max_age: int) -> dict[str, Any]:
    agents = fleet.get("agents") or []
    if not isinstance(agents, list):
        agents = []
    healthy = [agent for agent in agents if str(agent.get("status", "")).upper() == "HEALTHY"]
    stale = [
        str(agent.get("agent_id") or agent.get("id") or agent.get("hostname") or "unknown")
        for agent in agents
        if report_age(agent) > max_age
    ]
    failures: list[str] = []
    if len(agents) < min_agents:
        failures.append(f"fleet has {len(agents)} agents, expected {min_agents}")
    if len(healthy) < min_healthy:
        failures.append(f"fleet has {len(healthy)} healthy agents, expected {min_healthy}")
    if stale:
        failures.append("stale agents: " + ", ".join(stale))
    return {
        "status": "pass" if not failures else "blocked",
        "agents": len(agents),
        "healthy_agents": len(healthy),
        "max_report_age_seconds": max([report_age(agent, 0) for agent in agents] or [0]),
        "failures": failures,
    }


def overall_status(sections: dict[str, dict[str, Any]]) -> str:
    return "pass" if all(section.get("status") == "pass" for section in sections.values()) else "blocked"


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT P1 Readiness",
        "",
        f"- Status: `{report['status']}`",
        f"- Generated at: `{report['generated_at']}`",
        "",
    ]
    for name, section in report["sections"].items():
        lines.extend([
            f"## {name.replace('_', ' ').title()}",
            "",
            f"- Status: `{section.get('status', 'unknown')}`",
        ])
        for key, value in section.items():
            if key in {"status", "failures"}:
                continue
            lines.append(f"- {key}: `{value}`")
        if section.get("failures"):
            lines.append("- Failures: " + "; ".join(section["failures"]))
        lines.append("")
    return "\n".join(lines)


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    sections: dict[str, dict[str, Any]] = {}
    sections["secret_backends"] = check_secret_backends(load_json(Path(args.secret_manifest)))
    sections["tls_rotation"] = check_tls_manifest(load_json(Path(args.tls_manifest)))
    if args.postgres_report:
        sections["postgres_state"] = check_postgres(load_json(Path(args.postgres_report)))
    if args.server:
        sections["fleet"] = check_fleet(
            fetch_json(args.server, "/api/v1/control/fleet", args.api_key),
            args.min_agents,
            args.min_healthy,
            args.max_report_age_seconds,
        )
    report = {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": overall_status(sections),
        "sections": sections,
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate P1 production-readiness evidence.")
    parser.add_argument("--secret-manifest", default="build/secrets/secret-backend-manifest.json")
    parser.add_argument("--tls-manifest", default="build/tls/manifest.json")
    parser.add_argument("--postgres-report", default="")
    parser.add_argument("--server", default="")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--min-agents", type=int, default=3)
    parser.add_argument("--min-healthy", type=int, default=3)
    parser.add_argument("--max-report-age-seconds", type=int, default=60)
    parser.add_argument("--out-json", default="build/p1/p1-readiness.json")
    parser.add_argument("--out-md", default="build/p1/p1-readiness.md")
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
