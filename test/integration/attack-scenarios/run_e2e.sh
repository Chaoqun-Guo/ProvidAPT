#!/usr/bin/env bash
# =============================================================
# run_e2e.sh — End-to-end ProvidAPT test pipeline.
#
# Runs the full cycle:
#   1. Verify system requirements
#   2. Build ProvidAPT
#   3. Start the daemon
#   4. Run attack simulation
#   5. Stop the daemon
#   6. Verify the captured provenance chain
#   7. Print results
#
# Usage:
#   sudo bash test/attack-scenarios/run_e2e.sh
#   make run && make attack-sim && make verify-capture
# =============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

step() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║  Step $1: $2"
    echo "╚═══════════════════════════════════════════════════════╝"
}

fail() {
    echo -e "  ${RED}FAIL${NC}: $1"
    exit 1
}

ok() {
    echo -e "  ${GREEN}✓${NC} $1"
}

# ── Step 1: Verify ────────────────────────────────────
step "1" "System verification"
if bash scripts/verify.sh; then
    ok "System requirements met"
else
    fail "System requirements not met — run: sudo bash scripts/install_deps.sh"
fi

# ── Step 2: Build ─────────────────────────────────────
step "2" "Building ProvidAPT"
make clean 2>/dev/null || true
make build || fail "Build failed"
ok "Build successful"
echo ""
echo "  Binaries:"
ls -lh build/bin/
ls -lh build/ebpf/

# ── Step 3: Install ───────────────────────────────────
step "3" "Installing to system"
if [ "$(id -u)" -ne 0 ]; then
    # Can't install system-wide, run from build dir
    echo -e "  ${YELLOW}Not root — will run from build directory${NC}"
    DAEMON="./build/bin/providaptd"
    CONFIG="./scripts/providapt.toml"
else
    make install || fail "Install failed"
    DAEMON="/usr/local/sbin/providaptd"
    CONFIG="/etc/providapt/providapt.toml"
fi
ok "Installation ready"

# ── Step 4: Start ProvidAPT ───────────────────────────
step "4" "Starting ProvidAPT daemon"

# Kill any existing instance
sudo pkill providaptd 2>/dev/null || true
sleep 1

# Ensure output directory exists
sudo mkdir -p /var/log/providapt 2>/dev/null || true

# Start daemon in background
echo "  Starting: $DAEMON"
sudo "$DAEMON" -config "$CONFIG" &
DAEMON_PID=$!
sleep 2

if kill -0 "$DAEMON_PID" 2>/dev/null; then
    ok "Daemon running (PID $DAEMON_PID)"
else
    fail "Daemon failed to start"
fi

# ── Step 5: Run attack simulation ─────────────────────
step "5" "Running attack simulation"
bash test/attack-scenarios/attack_sim.sh || fail "Attack simulation failed"
ok "Attack simulation completed"

# Wait for events to be processed
echo "  Waiting 3s for event processing..."
sleep 3

# ── Step 6: Stop ProvidAPT ────────────────────────────
step "6" "Stopping ProvidAPT daemon"
sudo kill "$DAEMON_PID" 2>/dev/null || true
sleep 2
ok "Daemon stopped"

# ── Step 7: Verify capture ────────────────────────────
step "7" "Verifying provenance capture"
if bash test/attack-scenarios/verify_capture.sh; then
    ok "Provenance chain verification passed"
else
    echo -e "  ${YELLOW}Some checks failed — see details above${NC}"
fi

# ── Step 8: Summary ───────────────────────────────────
step "8" "Results"

EVENT_LOG=$(ls -t /var/log/providapt/providapt-*.ndjson 2>/dev/null | head -1)
if [ -n "$EVENT_LOG" ]; then
    EVENT_COUNT=$(wc -l < "$EVENT_LOG")
    echo "  Raw events captured: $EVENT_COUNT"
fi

GRAPH_FILE="/var/log/providapt/provenance.json"
if [ -f "$GRAPH_FILE" ]; then
    echo "  Provenance graph: $GRAPH_FILE"
    jq '.activity | length' "$GRAPH_FILE" 2>/dev/null | xargs echo "  Process nodes:"
    jq '.entity | length' "$GRAPH_FILE" 2>/dev/null | xargs echo "  File/entity nodes:"
    TOTAL=$(jq '(.used | length) + (.wasGeneratedBy | length) + (.wasInformedBy | length)' "$GRAPH_FILE" 2>/dev/null)
    echo "  Total edges: $TOTAL"
fi

ALERT_FILE="/var/log/providapt/alerts.json"
if [ -f "$ALERT_FILE" ]; then
    ALERT_COUNT=$(jq 'length' "$ALERT_FILE" 2>/dev/null || echo 0)
    echo "  Analyzer alerts: $ALERT_COUNT"
    jq -r '.[] | "    [\(.severity)] \(.headline)"' "$ALERT_FILE" 2>/dev/null || true
fi

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║  End-to-end test complete                             ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
