#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  fleet-lifecycle.sh --server URL list [--group GROUP] [--tag TAG]
  fleet-lifecycle.sh --server URL action --agent AGENT_ID[,AGENT_ID] --state approved|quarantined|revoked [--note NOTE]

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

while [ "$#" -gt 0 ]; do
  case "$1" in
    --server)
      server="${2:-}"
      shift 2
      ;;
    list|action)
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

case "$cmd" in
  list)
    query=""
    [ -n "$group" ] && query="${query}${query:+&}group=$group"
    [ -n "$tag" ] && query="${query}${query:+&}tag=$tag"
    url="$server/api/v1/control/fleet"
    [ -n "$query" ] && url="$url?$query"
    curl -fsS "$url"
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
    agent_json="$(printf '%s' "$agents" | awk -F, '{
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
    }')"
    note_json="$(printf '%s' "$note" | awk '{
      gsub(/\\/,"\\\\")
      gsub(/"/,"\\\"")
      printf "%s", $0
    }')"
    payload="{\"agent_ids\":$agent_json,\"action\":\"$state\",\"note\":\"$note_json\"}"
    curl -fsS -X POST "$server/api/v1/control/fleet" \
      -H "Content-Type: application/json" \
      -d "$payload"
    ;;
esac
