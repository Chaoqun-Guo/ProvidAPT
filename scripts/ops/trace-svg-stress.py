#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
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


def request_svg(server: str, alert_id: str, layout: str, timeout: float) -> tuple[int, str, float]:
    base = server.rstrip("/")
    encoded = quote(alert_id, safe="")
    query = urlencode({"layout": layout})
    req = Request(f"{base}/api/v1/alerts/{encoded}/svg?{query}")
    start = time.perf_counter()
    opener = build_opener(ProxyHandler({}))
    with opener.open(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        elapsed = (time.perf_counter() - start) * 1000.0
        return int(resp.status), body, elapsed


def request_json(server: str, path: str, timeout: float) -> dict[str, Any]:
    base = server.rstrip("/")
    req = Request(f"{base}{path}")
    opener = build_opener(ProxyHandler({}))
    with opener.open(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected JSON object")
    return data


def discover_alert_ids(server: str, timeout: float, limit: int) -> list[str]:
    if limit <= 0:
        return []
    data = request_json(server, "/api/v1/control/alerts", timeout)
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


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 2)
    rank = (len(ordered) - 1) * pct
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return round(ordered[lower] * (1 - weight) + ordered[upper] * weight, 2)


def result_passed(item: dict[str, Any], max_latency_ms: float, min_node_count: int) -> bool:
    return (
        int(item.get("http_status") or 0) == 200
        and not item.get("error")
        and bool(item.get("has_svg"))
        and float(item.get("latency_ms") or 0) <= max_latency_ms
        and int(item.get("node_count") or 0) >= min_node_count
        and float(item.get("width") or 0) > 0
        and float(item.get("height") or 0) > 0
    )


def evidence_summary(
    results: list[dict[str, Any]],
    alert_ids: list[str],
    layouts: list[str],
    max_latency_ms: float,
    min_node_count: int,
    failures: list[str],
) -> dict[str, Any]:
    expected = {(alert_id, layout) for alert_id in alert_ids for layout in layouts}
    seen = {(str(item.get("alert_id") or ""), str(item.get("layout") or "")) for item in results}
    matrix = []
    for alert_id in alert_ids:
        for layout in layouts:
            item = next(
                (
                    candidate
                    for candidate in results
                    if str(candidate.get("alert_id") or "") == alert_id and str(candidate.get("layout") or "") == layout
                ),
                {},
            )
            status = "pass" if item and result_passed(item, max_latency_ms, min_node_count) else ("blocked" if item else "missing")
            matrix.append(
                {
                    "alert_id": alert_id,
                    "layout": layout,
                    "status": status,
                    "latency_ms": item.get("latency_ms", 0),
                    "node_count": item.get("node_count", 0),
                    "http_status": item.get("http_status", 0),
                }
            )
    layout_summary: dict[str, dict[str, Any]] = {}
    for layout in layouts:
        items = [item for item in results if str(item.get("layout") or "") == layout]
        latencies = [float(item.get("latency_ms") or 0) for item in items if item.get("latency_ms") is not None]
        nodes = [int(item.get("node_count") or 0) for item in items if item.get("node_count") is not None]
        layout_summary[layout] = {
            "result_count": len(items),
            "pass_count": sum(1 for item in items if result_passed(item, max_latency_ms, min_node_count)),
            "blocked_count": sum(1 for item in items if item and not result_passed(item, max_latency_ms, min_node_count)),
            "latency_p50_ms": percentile(latencies, 0.50),
            "latency_p95_ms": percentile(latencies, 0.95),
            "latency_max_ms": round(max(latencies), 2) if latencies else 0.0,
            "min_node_count": min(nodes) if nodes else 0,
            "max_node_count": max(nodes) if nodes else 0,
        }
    return {
        "expected_result_count": len(expected),
        "result_count": len(results),
        "complete_matrix": bool(expected) and expected == seen and all(item["status"] == "pass" for item in matrix),
        "missing_pairs": [
            {"alert_id": alert_id, "layout": layout}
            for alert_id, layout in sorted(expected - seen)
        ],
        "matrix": matrix,
        "by_layout": layout_summary,
        "latency": {
            "p50_ms": percentile([float(item.get("latency_ms") or 0) for item in results], 0.50),
            "p95_ms": percentile([float(item.get("latency_ms") or 0) for item in results], 0.95),
            "max_ms": round(max([float(item.get("latency_ms") or 0) for item in results] or [0.0]), 2),
        },
        "failure_count": len(failures),
    }


def synthetic_svg(alert_id: str, layout: str, node_count: int) -> str:
    node_count = max(1, node_count)
    columns = max(1, min(16, int(node_count ** 0.5)))
    spacing_x = 140 if layout in {"tree", "timeline"} else 96
    spacing_y = 86 if layout != "compact" else 58
    width = max(800, columns * spacing_x + 180)
    rows = (node_count + columns - 1) // columns
    height = max(420, rows * spacing_y + 180)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" data-layout="{layout}">',
        f'<title>Synthetic Trace SVG stress fixture for {alert_id}</title>',
    ]
    for i in range(node_count):
        x = 70 + (i % columns) * spacing_x
        y = 70 + (i // columns) * spacing_y
        node_type = "process" if i % 3 == 0 else ("file" if i % 3 == 1 else "network")
        parts.append(
            f'<g data-node-id="{alert_id}:n{i}" data-type="{node_type}">'
            f'<circle cx="{x}" cy="{y}" r="12"></circle><text x="{x + 16}" y="{y + 4}">n{i}</text></g>'
        )
        if i > 0:
            source = f"{alert_id}:n{i - 1}"
            target = f"{alert_id}:n{i}"
            parts.append(f'<path data-source="{source}" data-target="{target}" d="M{x - spacing_x},{y} L{x},{y}"></path>')
    cluster_count = max(1, node_count // 25) if layout == "grouped" else max(0, node_count // 50)
    for i in range(cluster_count):
        folded = min(25, max(2, node_count - i * 25))
        parts.append(f'<g data-folded-count="{folded}" data-cluster-id="{alert_id}:c{i}"></g>')
    parts.append("</svg>")
    return "".join(parts)


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
    synthetic = bool(getattr(args, "synthetic_alerts", 0))
    alert_ids = list(args.alert_id or [])
    if synthetic and not alert_ids:
        alert_ids = [f"synthetic:{i + 1}" for i in range(int(args.synthetic_alerts))]
    if not alert_ids and not synthetic:
        discovered = True
        try:
            alert_ids = discover_alert_ids(args.server, args.timeout_seconds, args.discover_limit)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
            failures.append(f"alert discovery failed: {exc}")
    if not alert_ids:
        failures.append("no alert IDs supplied or discovered")
    results: list[dict[str, Any]] = []
    for alert_id in alert_ids:
        for layout in args.layout:
            result: dict[str, Any] = {"alert_id": alert_id, "layout": layout}
            try:
                if synthetic:
                    start = time.perf_counter()
                    body = synthetic_svg(alert_id, layout, int(args.synthetic_nodes))
                    elapsed_ms = (time.perf_counter() - start) * 1000.0
                    status = 200
                else:
                    status, body, elapsed_ms = request_svg(args.server, alert_id, layout, args.timeout_seconds)
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
                finally:
                    close = getattr(exc, "close", None)
                    if callable(close):
                        close()
                    elif getattr(exc, "fp", None):
                        fp = getattr(exc, "fp")
                        fp.close()
                result.update({"http_status": exc.code, "latency_ms": elapsed_ms, "error": body[:500] or str(exc)})
                failures.append(f"{alert_id}/{layout}: HTTP {exc.code}")
            except (URLError, TimeoutError, OSError) as exc:
                result.update({"http_status": 0, "latency_ms": 0.0, "error": str(exc)})
                failures.append(f"{alert_id}/{layout}: request failed: {exc}")
            results.append(result)
    summary = evidence_summary(results, alert_ids, list(args.layout), args.max_latency_ms, args.min_node_count, failures)
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "status": "blocked" if failures else "pass",
        "server": args.server,
        "alert_source": "synthetic" if synthetic else ("discovered" if discovered else "provided"),
        "alert_ids": alert_ids,
        "thresholds": {
            "max_latency_ms": args.max_latency_ms,
            "min_node_count": args.min_node_count,
            "timeout_seconds": args.timeout_seconds,
            "synthetic_nodes": int(getattr(args, "synthetic_nodes", 0) or 0),
        },
        "layouts": list(args.layout),
        "results": results,
        "evidence_summary": summary,
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
        f"- Complete matrix: `{str((report.get('evidence_summary') or {}).get('complete_matrix', False)).lower()}`",
        f"- Latency p95 ms: `{((report.get('evidence_summary') or {}).get('latency') or {}).get('p95_ms', 0)}`",
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
    summary = report.get("evidence_summary") if isinstance(report.get("evidence_summary"), dict) else {}
    if summary.get("by_layout"):
        lines.extend(["", "## Layout Summary", "", "| Layout | Results | Pass | Blocked | p50 ms | p95 ms | Max ms | Nodes |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |"])
        for layout, item in sorted(summary["by_layout"].items()):
            lines.append(
                f"| {layout} | {item.get('result_count', 0)} | {item.get('pass_count', 0)} | "
                f"{item.get('blocked_count', 0)} | {item.get('latency_p50_ms', 0)} | "
                f"{item.get('latency_p95_ms', 0)} | {item.get('latency_max_ms', 0)} | "
                f"{item.get('min_node_count', 0)}-{item.get('max_node_count', 0)} |"
            )
    if summary.get("matrix"):
        lines.extend(["", "## Coverage Matrix", "", "| Alert | Layout | Status | HTTP | Latency ms | Nodes |", "| --- | --- | --- | ---: | ---: | ---: |"])
        for item in summary["matrix"]:
            lines.append(
                f"| {item.get('alert_id', '')} | {item.get('layout', '')} | {item.get('status', '')} | "
                f"{item.get('http_status', 0)} | {item.get('latency_ms', 0)} | {item.get('node_count', 0)} |"
            )
    if report["failures"]:
        lines.extend(["", "## Failures", ""])
        lines.extend(f"- {item}" for item in report["failures"])
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect real API stress evidence for Trace SVG layouts.")
    parser.add_argument("--server", default="")
    parser.add_argument("--alert-id", action="append", default=[])
    parser.add_argument("--discover-limit", type=int, default=3, help="Discover up to N alert IDs from /api/v1/control/alerts when --alert-id is omitted")
    parser.add_argument("--layout", action="append", choices=LAYOUTS, default=[])
    parser.add_argument("--max-latency-ms", type=float, default=1500.0)
    parser.add_argument("--min-node-count", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    parser.add_argument("--synthetic-alerts", type=int, default=0, help="Generate N synthetic alert SVGs locally instead of contacting the API")
    parser.add_argument("--synthetic-nodes", type=int, default=250, help="Node count per synthetic alert")
    parser.add_argument("--out-json", default="build/trace-stress/trace-svg-stress.json")
    parser.add_argument("--out-md", default="build/trace-stress/trace-svg-stress.md")
    args = parser.parse_args(argv)
    if not args.layout:
        args.layout = list(LAYOUTS)
    if not args.server and not args.synthetic_alerts:
        parser.error("--server is required unless --synthetic-alerts is set")
    if args.synthetic_alerts and not args.server:
        args.server = "synthetic://local"
    return args


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
