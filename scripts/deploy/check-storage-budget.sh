#!/usr/bin/env bash
set -euo pipefail

DIR="${1:-/var/log/providapt}"
MAX_EVENT_BYTES="${PROVIDAPT_MAX_EVENT_BYTES:-16777216}"
MAX_ALERT_BYTES="${PROVIDAPT_MAX_ALERT_BYTES:-8388608}"
MAX_TOTAL_BYTES="${PROVIDAPT_MAX_TOTAL_BYTES:-536870912}"

if [ ! -d "$DIR" ]; then
  echo "status=missing dir=$DIR"
  exit 0
fi

echo "dir=$DIR"
du -sh "$DIR" 2>/dev/null || true

total_bytes="$(du -sb "$DIR" 2>/dev/null | awk '{print $1}')"
echo "total_bytes=${total_bytes:-0} max_total_bytes=$MAX_TOTAL_BYTES"
if [ "${total_bytes:-0}" -gt "$MAX_TOTAL_BYTES" ]; then
  echo "warning=total_usage_exceeds_budget"
fi

check_glob() {
  local label="$1" max_bytes="$2" pattern="$3"
  find "$DIR" -maxdepth 1 -type f -name "$pattern" -printf '%s %p\n' 2>/dev/null | sort -nr | while read -r size path; do
    [ -n "$size" ] || continue
    status=ok
    if [ "$size" -gt "$max_bytes" ]; then status=oversize; fi
    echo "$label size=$size max=$max_bytes status=$status path=$path"
  done
}

check_glob event "$MAX_EVENT_BYTES" 'providapt-*.ndjson'
check_glob alert "$MAX_ALERT_BYTES" 'alerts*.ndjson'

for sub in store support-bundle backups compliance siem-outbox applied-policy-bundles; do
  if [ -e "$DIR/$sub" ]; then
    size="$(du -sb "$DIR/$sub" 2>/dev/null | awk '{print $1}')"
    echo "component=$sub bytes=${size:-0} path=$DIR/$sub"
  fi
done
