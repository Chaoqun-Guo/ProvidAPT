#!/usr/bin/env bash
set -euo pipefail

# Minimal VM deployment helper for constrained disks.
# Required environment variables:
#   PROVIDAPT_VM_HOSTS="ubuntu@vm-ubuntu-slave.<TAILSCALE_DOMAIN> centos@vm-centos-slave.<TAILSCALE_DOMAIN> ubuntu@vm-ubuntu-master.<TAILSCALE_DOMAIN>"
# Optional:
#   PROVIDAPT_BIN=build/bin/providaptd
#   PROVIDAPT_SERVICE=providapt.service
#   PROVIDAPT_REMOTE_BIN=/usr/local/sbin/providaptd
#   PROVIDAPT_WAIT_SECONDS=30
#   PROVIDAPT_ALLOW_BPF_STUB=0
#   PROVIDAPT_ENABLE_SERVICE=1
#   PROVIDAPT_DELETE_LOGS=0

BIN="${PROVIDAPT_BIN:-build/bin/providaptd}"
SERVICE="${PROVIDAPT_SERVICE:-providapt.service}"
REMOTE_BIN="${PROVIDAPT_REMOTE_BIN:-/usr/local/sbin/providaptd}"
REMOTE_TMP="/tmp/providaptd.$$"
WAIT_SECONDS="${PROVIDAPT_WAIT_SECONDS:-30}"
ALLOW_BPF_STUB="${PROVIDAPT_ALLOW_BPF_STUB:-0}"
ENABLE_SERVICE="${PROVIDAPT_ENABLE_SERVICE:-1}"
DELETE_LOGS="${PROVIDAPT_DELETE_LOGS:-0}"

if [ ! -x "$BIN" ]; then
  echo "binary not found or not executable: $BIN" >&2
  exit 1
fi
SHA256="$(sha256sum "$BIN" | awk '{print $1}')"
if ! head -c 4 "$BIN" | grep -q "$(printf '\177ELF')"; then
  echo "binary is not a Linux ELF executable: $BIN" >&2
  exit 1
fi
if [ "$ALLOW_BPF_STUB" != "1" ] && grep -a -q "eBPF stub: no BPF device available" "$BIN"; then
  echo "binary appears to be built without the bpf tag; rebuild with: GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags bpf ..." >&2
  exit 1
fi
if [ -z "${PROVIDAPT_VM_HOSTS:-}" ]; then
  echo "set PROVIDAPT_VM_HOSTS before running" >&2
  exit 1
fi
echo "deploying binary=$BIN sha256=$SHA256 wait=${WAIT_SECONDS}s delete_logs=${DELETE_LOGS}"

for host in ${PROVIDAPT_VM_HOSTS}; do
  echo "==> deploying $host"
  scp -o StrictHostKeyChecking=no "$BIN" "$host:$REMOTE_TMP"
  ssh -o StrictHostKeyChecking=no "$host" "set -eu
    sudo systemctl stop '$SERVICE' || true
    sudo install -m 0755 '$REMOTE_TMP' '$REMOTE_BIN'
    rm -f '$REMOTE_TMP'
    actual_sha=\$(sha256sum '$REMOTE_BIN' | awk '{print \$1}')
    if [ \"\$actual_sha\" != '$SHA256' ]; then echo \"sha mismatch: \$actual_sha != $SHA256\" >&2; exit 1; fi
    if [ '$DELETE_LOGS' = '1' ] || [ '$DELETE_LOGS' = 'true' ]; then
      sudo find /var/log/providapt -maxdepth 1 -type f \\( -name 'providapt-*.ndjson' -o -name 'alerts*.ndjson' \\) -delete 2>/dev/null || true
    fi
    sudo systemctl reset-failed '$SERVICE' || true
    sudo systemctl daemon-reload
    if [ '$ENABLE_SERVICE' = '1' ]; then sudo systemctl enable '$SERVICE' >/dev/null; fi
    sudo systemctl start '$SERVICE'
    end=\$(( \$(date +%s) + $WAIT_SECONDS ))
    while [ \$(date +%s) -lt \$end ]; do
      [ \"\$(systemctl is-active '$SERVICE' || true)\" = active ] && break
      sleep 2
    done
    state=\$(systemctl is-active '$SERVICE' || true)
    if [ \"\$state\" != active ]; then
      systemctl status '$SERVICE' --no-pager -l || true
      sudo journalctl -u '$SERVICE' -n 80 --no-pager || true
      exit 1
    fi
    '$REMOTE_BIN' -version 2>/dev/null || true
    echo \"sha256=\$actual_sha\"
    sudo du -sh /var/log/providapt 2>/dev/null || true
    bash -s /var/log/providapt <<'REMOTE_CHECK'
DIR=\"\${1:-/var/log/providapt}\"
MAX_TOTAL_BYTES=\"\${PROVIDAPT_MAX_TOTAL_BYTES:-536870912}\"
if [ -d \"\$DIR\" ]; then
  total_bytes=\$(du -sb \"\$DIR\" 2>/dev/null | awk '{print \$1}')
  echo \"log_total_bytes=\${total_bytes:-0} max_total_bytes=\$MAX_TOTAL_BYTES\"
  [ \"\${total_bytes:-0}\" -le \"\$MAX_TOTAL_BYTES\" ] || echo \"warning=log_total_exceeds_budget\"
fi
REMOTE_CHECK
  "
done
