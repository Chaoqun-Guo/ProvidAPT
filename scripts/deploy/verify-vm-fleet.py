#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.vm_fleet_verification.v1"
DEFAULT_MARKERS = [
    "graphSubsetForCluster",
    "exportClusterSubset",
    "openGraphTrace",
    "graph-cluster-actions",
]


def fetch(url: str, api_key: str = "", timeout: float = 10.0) -> tuple[int, bytes, str]:
    request = urllib.request.Request(url)
    if api_key:
        request.add_header("X-API-Key", api_key)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read(), response.headers.get("content-type", "")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.headers.get("content-type", "")
    except urllib.error.URLError as exc:
        raise SystemExit(f"fetch failed for {url}: {exc}") from exc


def load_json_url(base_url: str, path: str, api_key: str = "") -> dict[str, Any]:
    status, body, _ = fetch(base_url.rstrip("/") + path, api_key)
    if status != 200:
        raise SystemExit(f"{path}: HTTP {status}: {body[:200]!r}")
    try:
        data = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected JSON object")
    return data


def report_age(agent: dict[str, Any], default: int = 999999) -> int:
    value = agent.get("last_report_age_seconds")
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def agent_summary(agent: dict[str, Any]) -> dict[str, Any]:
    return {
        "agent_id": str(agent.get("agent_id") or agent.get("hostname") or "unknown"),
        "hostname": str(agent.get("hostname") or ""),
        "status": str(agent.get("status") or ""),
        "status_reason": str(agent.get("status_reason") or ""),
        "last_report_age_seconds": report_age(agent),
        "last_report_at": str(agent.get("last_report_at") or ""),
        "version": str(agent.get("version") or ""),
        "attachment_mode": str(agent.get("attachment_mode") or ""),
        "enrollment_status": str(agent.get("enrollment_status") or ""),
        "graph_nodes": agent.get("graph_nodes", 0),
        "graph_edges": agent.get("graph_edges", 0),
        "alerts": agent.get("alert_count", 0),
    }


def verify(base_url: str, args: argparse.Namespace) -> dict[str, Any]:
    failures: list[str] = []
    warnings: list[str] = []
    status_doc = load_json_url(base_url, "/api/v1/status", args.api_key)
    overview = load_json_url(base_url, "/api/v1/control/overview", args.api_key)
    fleet = load_json_url(base_url, "/api/v1/control/fleet", args.api_key)
    graph = load_json_url(base_url, "/api/v1/graph/export", args.api_key)
    alerts = load_json_url(base_url, "/api/v1/control/alerts", args.api_key)
    html_status, html_body, _ = fetch(base_url.rstrip("/") + "/dashboard", args.api_key)
    if html_status != 200:
        failures.append(f"dashboard returned HTTP {html_status}")
    html = html_body.decode("utf-8", errors="replace")
    missing_markers = [marker for marker in args.dashboard_markers if marker not in html]
    if missing_markers:
        failures.append("dashboard missing markers: " + ", ".join(missing_markers))
    agents = fleet.get("agents", [])
    if not isinstance(agents, list):
        failures.append("fleet agents is not a list")
        agents = []
    agent_summaries = sorted([agent_summary(agent) for agent in agents], key=lambda item: item["agent_id"])
    healthy = [agent for agent in agents if str(agent.get("status", "")).upper() == "HEALTHY"]
    if len(agents) < args.min_agents:
        failures.append(f"fleet has {len(agents)} agents, expected at least {args.min_agents}")
    if len(healthy) < args.min_healthy:
        failures.append(f"fleet has {len(healthy)} healthy agents, expected at least {args.min_healthy}")
    stale = [
        str(agent.get("agent_id") or agent.get("hostname") or "unknown")
        for agent in agents
        if report_age(agent) > args.max_report_age_seconds
    ]
    if stale:
        failures.append("stale agents: " + ", ".join(stale))
    versions = sorted({str(agent.get("version", "")) for agent in agents if agent.get("version")})
    if args.expected_commit and any(args.expected_commit not in version for version in versions):
        failures.append(f"not all agent versions contain commit {args.expected_commit}: {versions}")
    graph_elements = graph.get("elements", [])
    if not isinstance(graph_elements, list) or len(graph_elements) == 0:
        warnings.append("graph export is empty")
    alert_count = len(alerts.get("alerts", [])) if isinstance(alerts.get("alerts"), list) else 0
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": "pass" if not failures else "blocked",
        "base_url": base_url,
        "service_status": status_doc.get("status", ""),
        "health": status_doc.get("health", ""),
        "version": (status_doc.get("diagnostics") or {}).get("version", ""),
        "agents": len(agents),
        "healthy_agents": len(healthy),
        "overview_total_agents": overview.get("total_agents", 0),
        "overview_healthy_agents": overview.get("healthy_agents", 0),
        "max_report_age_seconds": max([report_age(agent, 0) for agent in agents] or [0]),
        "agent_versions": versions,
        "agent_details": agent_summaries,
        "graph_elements": len(graph_elements) if isinstance(graph_elements, list) else 0,
        "alerts": alert_count,
        "dashboard_markers": {marker: marker in html for marker in args.dashboard_markers},
        "failures": failures,
        "warnings": warnings,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT VM Fleet Verification",
        "",
        f"- Status: `{report['status']}`",
        f"- Base URL: `{report['base_url']}`",
        f"- Service: `{report['service_status']}` / `{report['health']}`",
        f"- Version: `{report['version']}`",
        f"- Agents: `{report['agents']}` total / `{report['healthy_agents']}` healthy",
        f"- Max report age: `{report['max_report_age_seconds']}s`",
        f"- Graph elements: `{report['graph_elements']}`",
        f"- Alerts: `{report['alerts']}`",
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
    lines.extend(["## Agents", ""])
    lines.append("| Agent | Hostname | Status | Age | Attachment | Enrollment | Alerts |")
    lines.append("| --- | --- | --- | ---: | --- | --- | ---: |")
    for agent in report.get("agent_details", []):
        reason = f" ({agent['status_reason']})" if agent.get("status_reason") else ""
        lines.append(
            f"| `{agent['agent_id']}` | `{agent['hostname']}` | `{agent['status']}{reason}` | "
            f"`{agent['last_report_age_seconds']}s` | `{agent['attachment_mode']}` | "
            f"`{agent['enrollment_status']}` | `{agent['alerts']}` |"
        )
    lines.append("")
    lines.extend(["## Dashboard Markers", ""])
    lines.extend(f"- `{key}`: {value}" for key, value in report["dashboard_markers"].items())
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a deployed ProvidAPT control plane and reporting VM fleet.")
    parser.add_argument("--server", required=True, help="Control-plane base URL, for example http://vm-ubuntu-master.<TAILSCALE_DOMAIN>:18080")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--min-agents", type=int, default=3)
    parser.add_argument("--min-healthy", type=int, default=3)
    parser.add_argument("--max-report-age-seconds", type=int, default=30)
    parser.add_argument("--expected-commit", default="")
    parser.add_argument("--dashboard-marker", action="append", dest="dashboard_markers", default=[])
    parser.add_argument("--out-json", default="build/deploy/vm-fleet-verification.json")
    parser.add_argument("--out-md", default="build/deploy/vm-fleet-verification.md")
    args = parser.parse_args()
    if not args.dashboard_markers:
        args.dashboard_markers = DEFAULT_MARKERS
    report = verify(args.server, args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} agents={report['agents']} healthy={report['healthy_agents']} graph_elements={report['graph_elements']}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
