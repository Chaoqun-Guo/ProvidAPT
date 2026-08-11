#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import ProxyHandler, Request, build_opener


SCHEMA = "providapt.trace_svg_stress.v1"
LAYOUTS = ("tree", "compact", "timeline", "grouped")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def request_svg(server: str, alert_id: str, layout: str, api_key: str, timeout: float) -> tuple[int, str, float]:
    base = server.rstrip("/")
    encoded = quote(alert_id, safe="")
    query = urlencode({"layout": layout})
    req = Request(f"{base}/api/v1/alerts/{encoded}/svg?{query}")
    if api_key:
        req.add_header("X-API-Key", api_key)
    start = time.perf_counter()
    opener = build_opener(ProxyHandler({}))
    with opener.open(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        elapsed = (time.perf_counter() - start) * 1000.0
        return int(resp.status), body, elapsed


def request_json(server: str, path: str, api_key: str, timeout: float) -> dict[str, Any]:
    base = server.rstrip("/")
    req = Request(f"{base}{path}")
    if api_key:
        req.add_header("X-API-Key", api_key)
    opener = build_opener(ProxyHandler({}))
    with opener.open(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected JSON object")
    return data


def discover_alert_ids(server: str, api_key: str, timeout: float, limit: int) -> list[str]:
    if limit <= 0:
        return []
    data = request_json(server, "/api/v1/control/alerts", api_key, timeout)
    alerts = data.get("alerts") if isinstance(data.get("alerts"), list) else []
    ids: list[str] = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        alert_id = str(alert.get("id") or alert.get("alert_id") or "").strip()
        if alert_id and alert_id not in ids:
            ids.append(alert_id)
        if len(ids) >= limit:
            break
    return ids


def svg_stats(svg: str) -> dict[str, Any]:
    node_count = len(re.findall(r'data-node-id="', svg))
    edge_count = len(re.findall(r'data-source="', svg))
    cluster_count = len(re.findall(r'data-folded-count="', svg))
    width = extract_number(svg, r'<svg[^>]*\swidth="([0-9.]+)"')
    height = extract_number(svg, r'<svg[^>]*\sheight="([0-9.]+)"')
    return {
        "bytes": len(svg.encode("utf-8")),
        "node_count": node_count,
        "edge_count": edge_count,
        "cluster_count": cluster_count,
        "width": width,
        "height": height,
        "has_svg": "<svg" in svg and "</svg>" in svg,
    }


def extract_number(text: str, pattern: str) -> float:
    match = re.search(pattern, text)
    if not match:
        return 0.0
    try:
        return float(match.group(1))
    except ValueError:
        return 0.0


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    failures: list[str] = []
    discovered = False
    alert_ids = list(args.alert_id or [])
    if not alert_ids:
        discovered = True
        try:
            alert_ids = discover_alert_ids(args.server, args.api_key, args.timeout_seconds, args.discover_limit)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
            failures.append(f"alert discovery failed: {exc}")
    if not alert_ids:
        failures.append("no alert IDs supplied or discovered")
    results: list[dict[str, Any]] = []
    for alert_id in alert_ids:
        for layout in args.layout:
            result: dict[str, Any] = {"alert_id": alert_id, "layout": layout}
            try:
                status, body, elapsed_ms = request_svg(args.server, alert_id, layout, args.api_key, args.timeout_seconds)
                result.update({"http_status": status, "latency_ms": round(elapsed_ms, 2)})
                result.update(svg_stats(body))
                if status != 200:
                    failures.append(f"{alert_id}/{layout}: HTTP {status}")
                if not result["has_svg"]:
                    failures.append(f"{alert_id}/{layout}: response is not SVG")
                if result["latency_ms"] > args.max_latency_ms:
                    failures.append(f"{alert_id}/{layout}: latency {result['latency_ms']}ms above {args.max_latency_ms}ms")
                if int(result["node_count"]) < args.min_node_count:
                    failures.append(f"{alert_id}/{layout}: node count {result['node_count']} below {args.min_node_count}")
                if result["width"] <= 0 or result["height"] <= 0:
                    failures.append(f"{alert_id}/{layout}: SVG dimensions missing")
            except HTTPError as exc:
                elapsed_ms = 0.0
                try:
                    body = exc.read().decode("utf-8", errors="replace")
                except OSError:
                    body = ""
                result.update({"http_status": exc.code, "latency_ms": elapsed_ms, "error": body[:500] or str(exc)})
                failures.append(f"{alert_id}/{layout}: HTTP {exc.code}")
            except (URLError, TimeoutError, OSError) as exc:
                result.update({"http_status": 0, "latency_ms": 0.0, "error": str(exc)})
                failures.append(f"{alert_id}/{layout}: request failed: {exc}")
            results.append(result)
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "status": "blocked" if failures else "pass",
        "server": args.server,
        "alert_source": "discovered" if discovered else "provided",
        "alert_ids": alert_ids,
        "thresholds": {
            "max_latency_ms": args.max_latency_ms,
            "min_node_count": args.min_node_count,
            "timeout_seconds": args.timeout_seconds,
        },
        "layouts": list(args.layout),
        "results": results,
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Trace SVG Stress Evidence",
        "",
        f"- Status: `{report['status']}`",
        f"- Server: `{report['server']}`",
        f"- Alert source: `{report.get('alert_source', 'provided')}`",
        f"- Alert IDs: `{', '.join(report.get('alert_ids', [])) or 'none'}`",
        "",
        "| Alert | Layout | HTTP | Latency ms | Nodes | Edges | Clusters | Bytes | Dimensions |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for item in report["results"]:
        dims = f"{item.get('width', 0)}x{item.get('height', 0)}"
        lines.append(
            f"| {item.get('alert_id', '')} | {item.get('layout', '')} | {item.get('http_status', 0)} | "
            f"{item.get('latency_ms', 0)} | {item.get('node_count', 0)} | {item.get('edge_count', 0)} | "
            f"{item.get('cluster_count', 0)} | {item.get('bytes', 0)} | {dims} |"
        )
    if report["failures"]:
        lines.extend(["", "## Failures", ""])
        lines.extend(f"- {item}" for item in report["failures"])
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect real API stress evidence for Trace SVG layouts.")
    parser.add_argument("--server", required=True)
    parser.add_argument("--alert-id", action="append", default=[])
    parser.add_argument("--discover-limit", type=int, default=3, help="Discover up to N alert IDs from /api/v1/control/alerts when --alert-id is omitted")
    parser.add_argument("--layout", action="append", choices=LAYOUTS, default=list(LAYOUTS))
    parser.add_argument("--api-key", default=os.environ.get("PROVIDAPT_API_KEY", ""))
    parser.add_argument("--max-latency-ms", type=float, default=1500.0)
    parser.add_argument("--min-node-count", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    parser.add_argument("--out-json", default="build/trace-stress/trace-svg-stress.json")
    parser.add_argument("--out-md", default="build/trace-stress/trace-svg-stress.md")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = build_report(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"trace svg stress: status={report['status']} results={len(report['results'])}")
    return 1 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
