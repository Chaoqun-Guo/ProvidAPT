#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "providapt.upgrade_rollout_plan.v1"


def load_fleet(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(data, dict):
        agents = data.get("agents", [])
    else:
        agents = data
    if not isinstance(agents, list):
        raise SystemExit(f"{path}: expected fleet object with agents list")
    return [agent for agent in agents if isinstance(agent, dict)]


def agent_id(agent: dict[str, Any]) -> str:
    return str(agent.get("agent_id") or agent.get("id") or agent.get("hostname") or "unknown")


def healthy(agent: dict[str, Any]) -> bool:
    return str(agent.get("status", "")).lower() in {"healthy", "online"}


def build_batches(agents: list[dict[str, Any]], canary_percent: int, max_batch_size: int) -> list[dict[str, Any]]:
    eligible = [agent for agent in agents if healthy(agent) and str(agent.get("enrollment_status", "approved")).lower() != "revoked"]
    eligible.sort(key=lambda item: (str(item.get("group", "")), str(item.get("hostname", "")), agent_id(item)))
    if not eligible:
        return []
    canary_size = max(1, math.ceil(len(eligible) * max(1, canary_percent) / 100.0))
    canary = eligible[:canary_size]
    remaining = eligible[canary_size:]
    batches = [{
        "name": "canary",
        "action": "upgrade.apply",
        "agents": [agent_id(agent) for agent in canary],
        "pause_after": True,
        "success_gate": "all canary agents healthy, telemetry age below threshold, no critical alerts",
    }]
    index = 1
    while remaining:
        chunk = remaining[:max_batch_size]
        remaining = remaining[max_batch_size:]
        batches.append({
            "name": f"wave-{index}",
            "action": "upgrade.apply",
            "agents": [agent_id(agent) for agent in chunk],
            "pause_after": bool(remaining),
            "success_gate": "batch agents healthy and no upgrade rollback alerts",
        })
        index += 1
    return batches


def build_plan(args: argparse.Namespace) -> dict[str, Any]:
    agents = load_fleet(Path(args.fleet))
    batches = build_batches(agents, args.canary_percent, args.max_batch_size)
    rollback_batches = list(reversed([
        {"name": batch["name"], "action": "upgrade.rollback", "agents": batch["agents"]}
        for batch in batches
    ]))
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "target_version": args.target_version,
        "package": {
            "path": args.package_path,
            "sha256": args.expected_sha256,
            "signature_path": args.signature_path,
        },
        "fleet_size": len(agents),
        "eligible_agents": sum(1 for agent in agents if healthy(agent)),
        "canary_percent": args.canary_percent,
        "max_batch_size": args.max_batch_size,
        "status": "planned" if batches else "blocked",
        "preflight": [
            "verify package checksum and signature",
            "verify backup and rollback plan",
            "verify control-plane telemetry is fresh",
        ],
        "batches": batches,
        "pause_resume_controls": {
            "pause": "stop before the next batch if health, alert, or delivery gates fail",
            "resume": "continue with the next pending batch after gates pass",
        },
        "rollback": {
            "trigger": "critical health regression, failed preflight, or operator decision",
            "batches": rollback_batches,
        },
    }


def render_markdown(plan: dict[str, Any]) -> str:
    lines = [
        "# ProvidAPT Upgrade Rollout Plan",
        "",
        f"- Status: `{plan['status']}`",
        f"- Target version: `{plan['target_version']}`",
        f"- Fleet size: `{plan['fleet_size']}`",
        f"- Eligible agents: `{plan['eligible_agents']}`",
        "",
        "## Apply Batches",
        "",
        "| Batch | Agents | Pause After | Success Gate |",
        "| --- | ---: | --- | --- |",
    ]
    for batch in plan["batches"]:
        lines.append(f"| {batch['name']} | {len(batch['agents'])} | {batch['pause_after']} | {batch['success_gate']} |")
    lines.extend(["", "## Rollback Order", "", "| Batch | Agents |", "| --- | ---: |"])
    for batch in plan["rollback"]["batches"]:
        lines.append(f"| {batch['name']} | {len(batch['agents'])} |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build staged upgrade canary/wave/rollback plan from fleet JSON.")
    parser.add_argument("--fleet", required=True)
    parser.add_argument("--target-version", required=True)
    parser.add_argument("--package-path", default="")
    parser.add_argument("--expected-sha256", default="")
    parser.add_argument("--signature-path", default="")
    parser.add_argument("--canary-percent", type=int, default=10)
    parser.add_argument("--max-batch-size", type=int, default=25)
    parser.add_argument("--out-json", default="build/upgrade/rollout-plan.json")
    parser.add_argument("--out-md", default="build/upgrade/rollout-plan.md")
    args = parser.parse_args()
    plan = build_plan(args)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(plan), encoding="utf-8")
    print(f"status={plan['status']} batches={len(plan['batches'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
