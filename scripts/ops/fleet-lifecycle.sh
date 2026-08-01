#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  fleet-lifecycle.sh --server URL list [--group GROUP] [--tag TAG]
  fleet-lifecycle.sh --server URL action --agent AGENT_ID[,AGENT_ID] --state approved|quarantined|revoked [--note NOTE] [--out-json path] [--out-md path]
  fleet-lifecycle.sh --server URL plan --operation cert-rotation|decommission|quarantine [--agent AGENT_ID[,AGENT_ID]] [--group GROUP] [--tag TAG] [--out-json path] [--out-md path] [--from-file fleet.json]

Wrap common fleet lifecycle operations with safe defaults.
EOF
}

server="${PROVIDAPT_SERVER_URL:-}"
cmd=""
group=""
tag=""
agents=""
state=""
note=""
operation=""
out_json=""
out_md=""
from_file=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --server)
      server="${2:-}"
      shift 2
      ;;
    list|action|plan)
      cmd="$1"
      shift
      ;;
    --group)
      group="${2:-}"
      shift 2
      ;;
    --tag)
      tag="${2:-}"
      shift 2
      ;;
    --agent|--agents)
      agents="${2:-}"
      shift 2
      ;;
    --state)
      state="${2:-}"
      shift 2
      ;;
    --note)
      note="${2:-}"
      shift 2
      ;;
    --operation)
      operation="${2:-}"
      shift 2
      ;;
    --out-json)
      out_json="${2:-}"
      shift 2
      ;;
    --out-md)
      out_md="${2:-}"
      shift 2
      ;;
    --from-file)
      from_file="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ -z "$server" ] || [ -z "$cmd" ]; then
  usage >&2
  exit 2
fi

server="${server%/}"

fleet_url() {
  local query url
  query=""
  [ -n "$group" ] && query="${query}${query:+&}group=$group"
  [ -n "$tag" ] && query="${query}${query:+&}tag=$tag"
  url="$server/api/v1/control/fleet"
  [ -n "$query" ] && url="$url?$query"
  printf '%s' "$url"
}

agent_json_array() {
  printf '%s' "$agents" | awk -F, '{
    printf "["
    for (i=1; i<=NF; i++) {
      gsub(/^ +| +$/, "", $i)
      if ($i != "") {
        if (n++) printf ","
        gsub(/"/, "\\\"", $i)
        printf "\"%s\"", $i
      }
    }
    printf "]"
  }'
}

write_action_evidence() {
  local response="$1"
  RESPONSE_JSON="$response" python3 - "$state" "$agents" "$note" "$out_json" "$out_md" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

state, agents, note, out_json, out_md = sys.argv[1:6]
response = json.loads(os.environ.get("RESPONSE_JSON", "{}").lstrip("\ufeff"))
generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
results = response.get("results") or []
failed = int(response.get("failed") or 0)
succeeded = int(response.get("succeeded") or 0)
report = {
    "schema": "providapt.fleet_lifecycle_action.v1",
    "generated_at": generated_at,
    "action": state,
    "requested_agents": [item.strip() for item in agents.split(",") if item.strip()],
    "note": note,
    "status": "pass" if failed == 0 else "blocked",
    "processed": response.get("processed", len(results)),
    "succeeded": succeeded,
    "failed": failed,
    "results": results,
}

if out_json:
    target = Path(out_json)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if out_md:
    target = Path(out_md)
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Fleet Lifecycle Action",
        "",
        f"Generated: {generated_at}",
        f"Action: `{state}`",
        f"Status: `{report['status']}`",
        f"Processed: `{report['processed']}`",
        f"Succeeded: `{succeeded}`",
        f"Failed: `{failed}`",
        "",
        "| Agent | Status | Message |",
        "| --- | --- | --- |",
    ]
    for item in results:
        lines.append("| `{}` | `{}` | {} |".format(
            item.get("agent_id", ""),
            item.get("status", ""),
            item.get("message", ""),
        ))
    if note:
        lines.extend(["", f"Note: {note}"])
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")

print(json.dumps(report, indent=2, sort_keys=True))
raise SystemExit(1 if failed else 0)
PY
}

generate_plan() {
  local fleet_json
  if [ -n "$from_file" ]; then
    if [ ! -f "$from_file" ]; then
      echo "fleet file not found: $from_file" >&2
      exit 1
    fi
    fleet_json="$(cat "$from_file")"
  else
    fleet_json="$(curl -fsS "$(fleet_url)")"
  fi
  FLEET_JSON="$fleet_json" python3 - "$operation" "$(agent_json_array)" "$group" "$tag" "$out_json" "$out_md" "$note" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

operation, selected_raw, group, tag, out_json, out_md, note = sys.argv[1:8]
fleet = json.loads(os.environ.get("FLEET_JSON", "{}").lstrip("\ufeff"))
selected = set(json.loads(selected_raw or "[]"))
agents = fleet.get("agents") or []
if selected:
    agents = [agent for agent in agents if str(agent.get("id") or agent.get("agent_id") or "") in selected]

def agent_id(agent):
    return str(agent.get("id") or agent.get("agent_id") or "")

steps = {
    "cert-rotation": [
        "Generate replacement client certificate from the approved CA",
        "Install certificate and key on the target host",
        "Restart or reload providapt.service during the approved window",
        "Verify the reported cert_fingerprint changed in Agent Overview",
        "Approve the new enrollment fingerprint and archive the old fingerprint",
    ],
    "decommission": [
        "Confirm host owner and data-retention requirements",
        "Create support bundle or investigation export when required",
        "Set fleet state to revoked",
        "Stop providapt.service on the host",
        "Archive or destroy local logs according to the retention decision",
    ],
    "quarantine": [
        "Set fleet state to quarantined",
        "Confirm telemetry continues while policy advancement is withheld",
        "Collect support bundle and relevant provenance traces",
        "Document containment owner, ticket, and next review time",
    ],
}
if operation not in steps:
    raise SystemExit(f"unsupported operation: {operation}")

generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
items = []
for agent in agents:
    aid = agent_id(agent)
    items.append({
        "agent_id": aid,
        "hostname": agent.get("hostname", ""),
        "group": agent.get("group", ""),
        "tags": agent.get("tags") or [],
        "enrollment_status": agent.get("enrollment_status", ""),
        "health": agent.get("health", ""),
        "last_report_at": agent.get("last_report_at", ""),
        "cert_fingerprint": agent.get("cert_fingerprint", ""),
        "steps": steps[operation],
    })

report = {
    "schema": "providapt.fleet_lifecycle_plan.v1",
    "generated_at": generated_at,
    "operation": operation,
    "group_filter": group,
    "tag_filter": tag,
    "note": note,
    "agent_count": len(items),
    "agents": items,
}

def write_json(path):
    if not path:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def write_md(path):
    if not path:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Fleet Lifecycle Plan",
        "",
        f"Generated: {generated_at}",
        f"Operation: `{operation}`",
        f"Agents: {len(items)}",
        f"Group filter: `{group or '-'}`",
        f"Tag filter: `{tag or '-'}`",
        "",
        "| Agent | Hostname | Status | Health | Cert Fingerprint |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in items:
        lines.append("| {agent_id} | {hostname} | {status} | {health} | {cert} |".format(
            agent_id=item["agent_id"] or "-",
            hostname=item["hostname"] or "-",
            status=item["enrollment_status"] or "-",
            health=item["health"] or "-",
            cert=(item["cert_fingerprint"] or "-"),
        ))
    lines.extend(["", "## Runbook Steps", ""])
    for idx, step in enumerate(steps[operation], 1):
        lines.append(f"{idx}. {step}")
    if note:
        lines.extend(["", f"Note: {note}"])
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")

write_json(out_json)
write_md(out_md)
print(json.dumps(report, indent=2, sort_keys=True))
PY
}

case "$cmd" in
  list)
    curl -fsS "$(fleet_url)"
    ;;
  action)
    if [ -z "$agents" ] || [ -z "$state" ]; then
      usage >&2
      exit 2
    fi
    case "$state" in
      approved|quarantined|revoked) ;;
      *)
        echo "state must be approved, quarantined, or revoked" >&2
        exit 2
        ;;
    esac
    agent_json="$(agent_json_array)"
    note_json="$(printf '%s' "$note" | awk '{
      gsub(/\\/,"\\\\")
      gsub(/"/,"\\\"")
      printf "%s", $0
    }')"
    payload="{\"agent_ids\":$agent_json,\"action\":\"$state\",\"note\":\"$note_json\"}"
    response="$(curl -fsS -X POST "$server/api/v1/control/fleet" \
      -H "Content-Type: application/json" \
      -d "$payload")"
    if [ -n "$out_json" ] || [ -n "$out_md" ]; then
      write_action_evidence "$response"
    else
      printf '%s\n' "$response"
      RESPONSE_JSON="$response" python3 - <<'PY'
import json
import os
response = json.loads(os.environ.get("RESPONSE_JSON", "{}").lstrip("\ufeff"))
raise SystemExit(1 if int(response.get("failed") or 0) else 0)
PY
    fi
    ;;
  plan)
    case "$operation" in
      cert-rotation|decommission|quarantine) ;;
      *)
        echo "operation must be cert-rotation, decommission, or quarantine" >&2
        exit 2
        ;;
    esac
    generate_plan
    ;;
esac
