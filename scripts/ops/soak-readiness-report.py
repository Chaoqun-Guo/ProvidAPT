#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.soak_readiness_report.v1"


def load_samples(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    if isinstance(data, dict):
        rows = data.get("samples", [])
    else:
        rows = data
    if not isinstance(rows, list):
        raise SystemExit(f"{path}: expected samples list")
    return [row for row in rows if isinstance(row, dict)]


def max_number(rows: list[dict[str, Any]], *names: str) -> float:
    values: list[float] = []
    for row in rows:
        for name in names:
            try:
                values.append(float(row.get(name)))
                break
            except (TypeError, ValueError):
                continue
    return max(values) if values else 0.0


def build_report(rows: list[dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    duration_hours = max_number(rows, "duration_hours", "elapsed_hours")
    max_cpu = max_number(rows, "cpu_percent", "max_cpu_percent")
    max_memory = max_number(rows, "memory_mb", "rss_mb", "max_memory_mb")
    max_disk = max_number(rows, "disk_mb", "log_disk_mb", "max_disk_mb")
    drops = max_number(rows, "events_dropped", "dropped_events")
    hosts = sorted({str(row.get("host") or "").strip() for row in rows if str(row.get("host") or "").strip()})
    checks = {
        "samples": {"status": "pass" if len(rows) >= args.min_samples else "blocked", "observed": len(rows), "budget": args.min_samples},
        "hosts": {"status": "pass" if len(hosts) >= args.min_hosts else "blocked", "observed": len(hosts), "budget": args.min_hosts},
        "duration": {"status": "pass" if duration_hours >= args.min_hours else "blocked", "observed": duration_hours, "budget": args.min_hours},
        "cpu": {"status": "pass" if max_cpu <= args.max_cpu_percent else "blocked", "observed": max_cpu, "budget": args.max_cpu_percent},
        "memory": {"status": "pass" if max_memory <= args.max_memory_mb else "blocked", "observed": max_memory, "budget": args.max_memory_mb},
        "disk": {"status": "pass" if max_disk <= args.max_disk_mb else "blocked", "observed": max_disk, "budget": args.max_disk_mb},
        "drops": {"status": "pass" if drops <= args.max_dropped_events else "blocked", "observed": drops, "budget": args.max_dropped_events},
    }
    status = "pass" if all(item["status"] == "pass" for item in checks.values()) else "blocked"
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": status,
        "sample_count": len(rows),
        "hosts": hosts,
        "checks": checks,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Soak Readiness Report",
        "",
        f"- Status: `{report['status']}`",
        f"- Samples: `{report['sample_count']}`",
        f"- Hosts: `{', '.join(report.get('hosts', [])) or 'none'}`",
        "",
        "| Check | Status | Observed | Budget |",
        "| --- | --- | ---: | ---: |",
    ]
    for name, row in report["checks"].items():
        lines.append(f"| {name} | {row['status']} | {row['observed']} | {row['budget']} |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate accelerated soak evidence against performance budgets.")
    parser.add_argument("--samples", required=True)
    parser.add_argument("--min-samples", type=int, default=1)
    parser.add_argument("--min-hosts", type=int, default=1)
    parser.add_argument("--min-hours", type=float, default=0.05)
    parser.add_argument("--max-cpu-percent", type=float, default=25.0)
    parser.add_argument("--max-memory-mb", type=float, default=512.0)
    parser.add_argument("--max-disk-mb", type=float, default=4096.0)
    parser.add_argument("--max-dropped-events", type=float, default=0.0)
    parser.add_argument("--out-json", default="build/performance/soak-readiness.json")
    parser.add_argument("--out-md", default="build/performance/soak-readiness.md")
    args = parser.parse_args()
    report = build_report(load_samples(Path(args.samples)), args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(f"status={report['status']} samples={report['sample_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
