#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.observability_pack_check.v1"
REQUIRED_ALERTS = ["ProvidaptNoEvents", "ProvidaptBackpressure", "ProvidaptCriticalAlert"]
REQUIRED_METRICS = ["providapt_events_ingested_total", "providapt_graph_nodes", "providapt_alerts_triggered_total"]
MOJIBAKE_MARKERS = ("\u95c1", "\u95b3", "\u9225", "\u951f", "\ufffd")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8-sig", errors="replace")


def has_mojibake(data: str) -> bool:
    return any(marker in data for marker in MOJIBAKE_MARKERS)


def check_prometheus(path: Path) -> dict[str, Any]:
    data = text(path)
    failures: list[str] = []
    if not data:
        failures.append("prometheus scrape config is missing")
    if "job_name:" not in data or "providapt" not in data:
        failures.append("providapt scrape job missing")
    if "metrics_path: /metrics" not in data:
        failures.append("/metrics scrape path missing")
    return {"status": "pass" if not failures else "blocked", "path": str(path), "failures": failures}


def check_alerts(path: Path) -> dict[str, Any]:
    data = text(path)
    failures: list[str] = []
    warnings: list[str] = []
    for alert in REQUIRED_ALERTS:
        if alert not in data:
            failures.append(f"required alert rule missing: {alert}")
    if has_mojibake(data):
        warnings.append("alert rule file contains mojibake characters")
    if "severity: critical" not in data:
        warnings.append("no critical severity alert rule found")
    return {"status": "blocked" if failures else ("warn" if warnings else "pass"), "path": str(path), "failures": failures, "warnings": warnings}


def check_dashboard(path: Path) -> dict[str, Any]:
    data = text(path)
    failures: list[str] = []
    warnings: list[str] = []
    panels = 0
    if not data:
        failures.append("Grafana dashboard JSON is missing")
    else:
        try:
            doc = json.loads(data)
            dashboard = doc.get("dashboard", doc)
            panels = len(dashboard.get("panels") or [])
            title = str(dashboard.get("title", ""))
            if not title or "ProvidAPT" not in title:
                failures.append("dashboard title is missing ProvidAPT")
            if panels < 4:
                failures.append("dashboard has fewer than four panels")
            dumped = json.dumps(doc)
            for metric in REQUIRED_METRICS[:2]:
                if metric not in dumped:
                    warnings.append(f"dashboard does not reference metric {metric}")
            if has_mojibake(data):
                warnings.append("dashboard JSON contains mojibake characters")
        except json.JSONDecodeError as exc:
            failures.append(f"dashboard JSON parse failed: {exc}")
    return {"status": "blocked" if failures else ("warn" if warnings else "pass"), "path": str(path), "panel_count": panels, "failures": failures, "warnings": warnings}


def fetch(url: str, api_key: str = "") -> str:
    request = urllib.request.Request(url)
    if api_key:
        request.add_header("X-API-Key", api_key)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        raise SystemExit(f"fetch failed for {url}: {exc}") from exc


def check_live(server: str, api_key: str) -> dict[str, Any]:
    if not server:
        return {"status": "skipped", "message": "server URL not supplied"}
    base = server.rstrip("/")
    metrics = fetch(base + "/metrics", api_key)
    status_text = fetch(base + "/api/v1/status", api_key)
    failures = [f"live metrics missing {metric}" for metric in REQUIRED_METRICS if metric not in metrics]
    try:
        status = json.loads(status_text)
    except json.JSONDecodeError:
        status = {}
        failures.append("status endpoint did not return JSON")
    return {"status": "pass" if not failures else "blocked", "server": server, "version": status.get("version", ""), "failures": failures}


def overall(sections: dict[str, dict[str, Any]]) -> str:
    statuses = [section.get("status") for section in sections.values() if section.get("status") != "skipped"]
    if "blocked" in statuses:
        return "blocked"
    if "warn" in statuses:
        return "warn"
    return "pass"


def render_markdown(report: dict[str, Any]) -> str:
    lines = ["# ProvidAPT Observability Pack Check", "", f"- Status: `{report['status']}`", f"- Generated at: `{report['generated_at']}`", "", "| Section | Status | Detail |", "| --- | --- | --- |"]
    for name, section in report["sections"].items():
        detail = "; ".join(section.get("failures") or section.get("warnings") or [str(section.get("message", ""))])
        lines.append(f"| {name} | {section['status']} | {detail} |")
    lines.append("")
    return "\n".join(lines)


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    sections = {
        "prometheus": check_prometheus(Path(args.prometheus)),
        "alerts": check_alerts(Path(args.alerts)),
        "dashboard": check_dashboard(Path(args.dashboard)),
        "live": check_live(args.server, args.api_key),
    }
    return {"schema": SCHEMA, "generated_at": utc_now(), "status": overall(sections), "sections": sections}


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate production observability assets and optional live metrics.")
    parser.add_argument("--prometheus", default="scripts/docker/prometheus.yml")
    parser.add_argument("--alerts", default="build/prometheus/providapt_alerts.yml")
    parser.add_argument("--dashboard", default="build/prometheus/providapt_dashboard.json")
    parser.add_argument("--server", default="")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--out-json", default="build/observability/observability-pack-check.json")
    parser.add_argument("--out-md", default="build/observability/observability-pack-check.md")
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
