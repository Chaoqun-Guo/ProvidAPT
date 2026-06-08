#!/usr/bin/env bash
set -euo pipefail

# loader_smoke.sh — Linux runtime smoke test for the real eBPF loader.
#
# Verifies:
#   1. precompiled lsm_hooks.bpf.o can be built
#   2. the daemon can be built with -tags bpf
#   3. PROVIDAPT_BPF_OBJECT_PATH override is honored
#   4. providaptd reaches loader startup and either:
#        - starts successfully, or
#        - reports a clear fallback/runtime attachment signal
#
# Usage:
#   sudo bash test/integration/loader_smoke.sh

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
LOG_FILE="$TMP_DIR/providaptd.log"
CONFIG_FILE="$TMP_DIR/providapt-loader-smoke.json"
BIN_FILE="$TMP_DIR/providaptd"
trap 'rm -rf "$TMP_DIR"' EXIT

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "loader_smoke: Linux only"
    exit 1
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "loader_smoke: requires root"
    exit 1
fi

for tool in timeout go make; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "loader_smoke: missing required tool: $tool"
        exit 1
    fi
done

cd "$PROJECT_ROOT"

echo "[1/5] Building eBPF objects"
make v1-ebpf >/dev/null

OBJECT_PATH="$PROJECT_ROOT/build/ebpf/lsm_hooks.bpf.o"
if [[ ! -f "$OBJECT_PATH" ]]; then
    echo "loader_smoke: expected object not found: $OBJECT_PATH"
    exit 1
fi

echo "[2/5] Building providaptd with real eBPF loader"
go build -tags bpf -o "$BIN_FILE" ./cmd/agent/daemon

cat >"$CONFIG_FILE" <<EOF
{
  "kernel": {
    "verbose": true,
    "hooks": [
      "task_alloc",
      "task_free",
      "file_open",
      "bprm_check_security",
      "socket_connect"
    ]
  },
  "output": {
    "dir": "$TMP_DIR/output",
    "format": "json"
  },
  "log": {
    "level": "info",
    "format": "text"
  },
  "capture": {
    "enable_net": true,
    "enable_file": true,
    "enable_proc": true,
    "sensitive_dir": false
  },
  "api": {
    "grpc": ":0",
    "rest": ":0"
  },
  "tls": {
    "enable": false
  },
  "storage": {
    "encrypt": false
  }
}
EOF

echo "[3/5] Running daemon with object-path override"
set +e
PROVIDAPT_BPF_OBJECT_PATH="$OBJECT_PATH" \
timeout --signal=INT 12s "$BIN_FILE" -config "$CONFIG_FILE" >"$LOG_FILE" 2>&1
status=$?
set -e

echo "[4/5] Inspecting loader result"
if grep -qi "loader init failed" "$LOG_FILE"; then
    echo "loader_smoke: loader initialization failed"
    cat "$LOG_FILE"
    exit 1
fi

if grep -qi "no precompiled eBPF object found" "$LOG_FILE"; then
    echo "loader_smoke: object override was not honored"
    cat "$LOG_FILE"
    exit 1
fi

if grep -qi "daemon started" "$LOG_FILE"; then
    mode="lsm"
    if grep -qi "kprobe fallback" "$LOG_FILE"; then
        mode="kprobe_fallback"
    fi
    echo "[5/5] Success: daemon reached runtime startup (mode=$mode)"
    exit 0
fi

if grep -qi "kprobe fallback" "$LOG_FILE"; then
    echo "[5/5] Success: loader entered kprobe fallback path"
    exit 0
fi

if [[ "$status" -eq 124 || "$status" -eq 130 ]]; then
    if grep -qi "all sanity checks passed" "$LOG_FILE"; then
        echo "[5/5] Success: daemon stayed alive long enough for smoke validation"
        exit 0
    fi
fi

echo "loader_smoke: daemon did not reach a known-good loader state"
cat "$LOG_FILE"
exit 1
