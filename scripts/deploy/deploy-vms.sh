#!/usr/bin/env bash
set -euo pipefail

# Minimal VM deployment helper for constrained disks.
# Required environment variables:
#   PROVIDAPT_VM_HOSTS="ubuntu@192.168.150.129 centos@192.168.150.131 ubuntu@192.168.150.132"
# Optional:
#   PROVIDAPT_BIN=build/bin/providaptd
#   PROVIDAPT_SERVICE=providapt.service
#   PROVIDAPT_REMOTE_BIN=/usr/local/sbin/providaptd

BIN="${PROVIDAPT_BIN:-build/bin/providaptd}"
SERVICE="${PROVIDAPT_SERVICE:-providapt.service}"
REMOTE_BIN="${PROVIDAPT_REMOTE_BIN:-/usr/local/sbin/providaptd}"
REMOTE_TMP="/tmp/providaptd.$$"

if [ ! -x "$BIN" ]; then
  echo "binary not found or not executable: $BIN" >&2
  exit 1
fi
if [ -z "${PROVIDAPT_VM_HOSTS:-}" ]; then
  echo "set PROVIDAPT_VM_HOSTS before running" >&2
  exit 1
fi

for host in ${PROVIDAPT_VM_HOSTS}; do
  echo "==> deploying $host"
  scp -o StrictHostKeyChecking=no "$BIN" "$host:$REMOTE_TMP"
  ssh -o StrictHostKeyChecking=no "$host" "set -eu
    sudo systemctl stop '$SERVICE' || true
    sudo install -m 0755 '$REMOTE_TMP' '$REMOTE_BIN'
    rm -f '$REMOTE_TMP'
    sudo find /var/log/providapt -maxdepth 1 -type f -name 'providapt-*.ndjson' -delete 2>/dev/null || true
    sudo find /var/log/providapt -maxdepth 1 -type f -name 'alerts*.ndjson' -delete 2>/dev/null || true
    sudo systemctl start '$SERVICE'
    systemctl is-active '$SERVICE'
    sudo du -sh /var/log/providapt 2>/dev/null || true
  "
done
