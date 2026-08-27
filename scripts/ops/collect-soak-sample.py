#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.soak_samples.v1"


def load_status_from_url(url: str, timeout: float = 5.0) -> dict[str, Any]:
    request = urllib.request.Request(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise SystemExit(f"failed to fetch {url}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"{url}: expected JSON object")
    return data


def load_existing(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        return {"schema": SCHEMA, "started_at": utc_now(), "samples": []}
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(data, list):
        return {"schema": SCHEMA, "started_at": utc_now(), "samples": data}
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected JSON object or list")
    data.setdefault("schema", SCHEMA)
    data.setdefault("samples", [])
    if not isinstance(data["samples"], list):
        raise SystemExit(f"{path}: samples must be a list")
    return data


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def number(data: dict[str, Any], *names: str) -> float:
    for name in names:
        value = data
        for part in name.split("."):
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return 0.0


def build_sample(status: dict[str, Any], started_at: float, host: str = "") -> dict[str, Any]:
    metrics = status.get("metrics") if isinstance(status.get("metrics"), dict) else status
    runtime = status.get("runtime") if isinstance(status.get("runtime"), dict) else status
    uptime_seconds = number(status, "uptime_seconds", "runtime.uptime_seconds", "metrics.uptime_seconds")
    duration_hours = max(time.time() - started_at, 0) / 3600 if started_at else uptime_seconds / 3600
    sample = {
        "timestamp": utc_now(),
        "host": host or str(status.get("hostname") or status.get("agent_id") or ""),
        "duration_hours": round(duration_hours, 4),
        "cpu_percent": number(metrics, "cpu_percent", "providapt_cpu_percent"),
        "memory_mb": round(number(metrics, "memory_bytes", "memory_rss_bytes", "providapt_memory_rss_bytes") / (1024 * 1024), 3),
        "disk_mb": round(number(metrics, "disk_bytes", "log_disk_bytes", "providapt_log_disk_bytes") / (1024 * 1024), 3),
        "events_ingested": int(number(metrics, "events_ingested", "events_total", "providapt_events_total")),
        "events_dropped": int(number(metrics, "events_dropped", "dropped_events", "providapt_events_dropped")),
        "graph_nodes": int(number(metrics, "graph_nodes", "providapt_graph_nodes")),
        "graph_edges": int(number(metrics, "graph_edges", "providapt_graph_edges")),
        "queue_depth": int(number(runtime, "queue_depth", "pipeline_queue_depth")),
    }
    return sample


def host_from_status_url(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except ValueError:
        return ""


def append_sample(path: Path, sample: dict[str, Any]) -> dict[str, Any]:
    report = load_existing(path)
    report["samples"].append(sample)
    report["updated_at"] = utc_now()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def collect_samples(
    *,
    status_url: str,
    status_json: str,
    host: str,
    started_at_epoch: float,
    out: Path,
    count: int,
    interval_seconds: float,
) -> dict[str, Any]:
    if count < 1:
        raise SystemExit("--count must be >= 1")
    if interval_seconds < 0:
        raise SystemExit("--interval-seconds must be >= 0")
    report: dict[str, Any] = {}
    for index in range(count):
        status = load_status_from_url(status_url) if status_url else json.loads(Path(status_json).read_text(encoding="utf-8-sig"))
        if not isinstance(status, dict):
            raise SystemExit("status input must be a JSON object")
        sample_host = host or host_from_status_url(status_url)
        report = append_sample(out, build_sample(status, started_at_epoch, sample_host))
        if index < count - 1 and interval_seconds > 0:
            time.sleep(interval_seconds)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Append ProvidAPT runtime samples for accelerated soak readiness.")
    parser.add_argument("--status-url", help="Status or metrics JSON endpoint, for example http://localhost:18080/api/v1/status")
    parser.add_argument("--status-json", help="Read a captured status JSON file instead of fetching an endpoint")
    parser.add_argument("--host", default="")
    parser.add_argument("--started-at-epoch", type=float, default=0)
    parser.add_argument("--count", type=int, default=1, help="Number of samples to append during this run")
    parser.add_argument("--interval-seconds", type=float, default=0, help="Delay between samples when --count is greater than 1")
    parser.add_argument("--out", default="build/performance/soak-samples.json")
    args = parser.parse_args()
    if not args.status_url and not args.status_json:
        raise SystemExit("set --status-url or --status-json")
    report = collect_samples(
        status_url=args.status_url,
        status_json=args.status_json,
        host=args.host,
        started_at_epoch=args.started_at_epoch,
        out=Path(args.out),
        count=args.count,
        interval_seconds=args.interval_seconds,
    )
    print(f"samples={len(report['samples'])} out={args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
