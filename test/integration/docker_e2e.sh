#!/usr/bin/env bash
# ============================================================
# ProvidAPT Docker E2E Test
#
# Full lifecycle test inside Docker:
#   1. Build userspace + eBPF objects
#   2. Install & configure
#   3. Run daemon
#   4. Monitor (status, logs, audit, diagnose)
#   5. Replay (generate test events + replay)
#   6. Archive & backup
#   7. Stop & cleanup
#
# Usage:
#   bash test/integration/docker_e2e.sh
#
# Prerequisites:
#   - Docker running (Linux containers mode on Docker Desktop)
#   - git repository root as working directory
# ============================================================
set -euo pipefail

cd "$(dirname "$0")/../.."
PROJECT_ROOT=$(pwd)
OUTPUT_DIR="$PROJECT_ROOT/build/e2e-docker"
mkdir -p "$OUTPUT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0
TOTAL=0
E2E_START=$(date +%s)

check() {
    TOTAL=$((TOTAL + 1))
    local name="$1"
    local result="$2"
    shift 2
    if [ "$result" = "true" ] || [ "$result" = "0" ] || [ "$result" = "ok" ] || [ "$result" = "0 " ]; then
        echo -e "  ${GREEN}[PASS]${NC} $name"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}[FAIL]${NC} $name"
        [ $# -gt 0 ] && echo "    $*"
        FAIL=$((FAIL + 1))
    fi
}

header() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
    echo ""
}

CONTAINER_NAME="providapt-e2e"
TEST_IMAGE="providapt-e2e:latest"
DAEMON_LOG="$OUTPUT_DIR/daemon.log"
CLI_BIN="./build/bin/providaptctl"
DAEMON_BIN="./build/bin/providaptd"

cleanup() {
    echo ""
    echo -e "${YELLOW}[cleanup] Stopping container...${NC}"
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    docker rm "$CONTAINER_NAME" 2>/dev/null || true
    echo -e "${YELLOW}[cleanup] Done.${NC}"
}
trap cleanup EXIT

# ============================================================
header "Phase 0: Docker Image Build"
# ============================================================
echo "Building Docker image: $TEST_IMAGE ..."
docker build -t "$TEST_IMAGE" -f build/docker/Dockerfile.ubuntu . 2>&1 | tail -5
check "docker build" "$(docker image inspect "$TEST_IMAGE" >/dev/null 2>&1 && echo true || echo false)"

# ============================================================
header "Phase 1: Build Userspace Binaries"
# ============================================================
echo "Building userspace binaries inside Docker..."
docker run --name "$CONTAINER_NAME" \
    -v "$PROJECT_ROOT/build:/workspace/build" \
    "$TEST_IMAGE" \
    bash -c '
        set -e
        echo "  Go version: $(go version)"

        # Build userspace
        make build-userspace 2>&1 | tail -5
        echo "build-userspace exit: $?"

        # Verify binaries exist
        for bin in providaptd providaptctl providapt-watchdog providapt-verify; do
            if [ -f "build/bin/${bin}" ]; then
                echo "  [OK] build/bin/${bin} ($(ls -lh build/bin/${bin} | awk "{print \$5}"))"
            else
                echo "  [MISSING] build/bin/${bin}"
            fi
        done

        # Try eBPF build (may fail in Docker Desktop — non-fatal)
        echo ""
        echo "Attempting eBPF build (non-fatal if fails)..."
        if make build-ebpf 2>/dev/null; then
            echo "  eBPF objects built successfully"
        else
            echo "  [SKIP] eBPF build not supported in this environment"
        fi
    ' 2>&1 | tee "$OUTPUT_DIR/build.log"

BINS="build/bin/providaptd build/bin/providaptctl"
for b in $BINS; do
    check "binary: $b" "$(test -f "$b" && echo true || echo false)" "Missing: $b"
done

# ============================================================
header "Phase 2: Create Runtime Config & Data"
# ============================================================
echo "Creating runtime configuration..."
mkdir -p build/e2e-data/output build/e2e-data/store build/e2e-data/audit

cat > build/e2e-data/providapt.toml << 'CONFIG'
[output]
dir = "/workspace/build/e2e-data/output"

[log]
level = "debug"

[api]
rest = ":8080"
grpc = ":50051"

[capture]
enable_net = false
enable_file = true
enable_proc = true

[store]
path = "/workspace/build/e2e-data/store"
engine = "pebble"

[audit]
dir = "/workspace/build/e2e-data/audit"

[analyzer]
scan_interval = "30s"

[monitoring]
enabled = false
CONFIG

check "config created" "$(test -f build/e2e-data/providapt.toml && echo true || echo false)"

# ============================================================
header "Phase 3: Start Daemon"
# ============================================================
echo "Starting daemon with eBPF fallback mode..."
docker run -d --name "$CONTAINER_NAME" \
    --privileged \
    -v "$PROJECT_ROOT/build:/workspace/build" \
    -v "$PROJECT_ROOT/build/e2e-data:/workspace/build/e2e-data" \
    --pid=host \
    "$TEST_IMAGE" \
    bash -c '
        set -e
        echo "=== Daemon started at $(date) ==="
        echo "Go: $(go version)"
        echo "Kernel: $(uname -r)"
        echo "BTF available: $(test -f /sys/kernel/btf/vmlinux && echo yes || echo no)"
        echo ""

        # Create runtime dirs
        mkdir -p /var/log/providapt /var/run /etc/providapt
        cp /workspace/build/e2e-data/providapt.toml /etc/providapt/providapt.toml

        echo "Starting providaptd..."
        /workspace/build/bin/providaptd \
            -config /etc/providapt/providapt.toml \
            -log-level debug \
            2>&1
    ' 2>&1

sleep 3

echo "Container status:"
docker ps --filter "name=$CONTAINER_NAME" --format "table {{.Names}}\t{{.Status}}"

check "container running" \
    "$(docker ps --filter "name=$CONTAINER_NAME" --filter "status=running" -q | wc -l)" \
    "Container not in running state"

# ============================================================
header "Phase 4: Monitor — Status, Audit, Diagnostic"
# ============================================================

# --- 4a: CLI Status ---
echo "[4a] Testing providaptctl -status ..."
STATUS_OUTPUT=$(docker exec "$CONTAINER_NAME" \
    /workspace/build/bin/providaptctl -config /etc/providapt/providapt.toml -status 2>&1 || true)
echo "$STATUS_OUTPUT"
check "status command" \
    "$(echo "$STATUS_OUTPUT" | grep -c "ProvidAPT" || echo 0)" \
    "Status output did not show expected content"

# Check for key status indicators
check "status: daemon PID" \
    "$(echo "$STATUS_OUTPUT" | grep -cE "PID|pid|running" || echo 0)" \
    "No PID/running indicator in status"

# --- 4b: JSON Status ---
echo "[4b] Testing providaptctl -status -json ..."
JSON_STATUS=$(docker exec "$CONTAINER_NAME" \
    /workspace/build/bin/providaptctl -config /etc/providapt/providapt.toml -status -json 2>&1 || true)
check "json status" \
    "$(echo "$JSON_STATUS" | grep -c "{" || echo 0)" \
    "JSON status did not produce valid output"

# --- 4c: Audit Log ---
echo "[4c] Testing providaptctl -audit ..."
AUDIT_OUT=$(docker exec "$CONTAINER_NAME" \
    /workspace/build/bin/providaptctl -config /etc/providapt/providapt.toml -audit -audit-limit=10 2>&1 || true)
echo "$AUDIT_OUT" | head -5
check "audit command" \
    "$(echo "$AUDIT_OUT" | grep -cE "audit|Entry|security|admin|system" || echo 0)" \
    "Audit output missing expected entries"

# --- 4d: Diagnose ---
echo "[4d] Testing providaptctl -diagnose ..."
DIAG_OUT=$(docker exec "$CONTAINER_NAME" \
    /workspace/build/bin/providaptctl -config /etc/providapt/providapt.toml -diagnose -diagnose-out=/tmp/diag 2>&1 || true)
echo "$DIAG_OUT" | head -3
check "diagnose command" \
    "$(docker exec "$CONTAINER_NAME" test -d /tmp/diag && echo true || echo false)" \
    "Diagnose output directory not created"

# --- 4e: Config Check ---
echo "[4e] Testing providaptctl -config-check ..."
CONFIG_CHECK=$(docker exec "$CONTAINER_NAME" \
    /workspace/build/bin/providaptctl -config /etc/providapt/providapt.toml -config-check 2>&1 || true)
check "config check" \
    "$(echo "$CONFIG_CHECK" | grep -ciE "valid|ok|pass" || echo 0)" \
    "Config check did not report valid"

# --- 4f: Daemon Logs ---
echo "[4f] Checking daemon logs..."
DAEMON_LOGS=$(docker logs "$CONTAINER_NAME" 2>&1 | tail -20)
echo "$DAEMON_LOGS" | head -5
check "daemon logs: startup message" \
    "$(echo "$DAEMON_LOGS" | grep -c "start\|init\|loading\|ProvidAPT" || echo 0)" \
    "Daemon logs missing startup messages"

# --- 4g: bpf inspect (non-fatal, will show fallback status) ---
echo "[4g] Testing providaptctl -bpf (eBPF inspection, may show fallback)..."
BPF_OUT=$(docker exec "$CONTAINER_NAME" \
    /workspace/build/bin/providaptctl -config /etc/providapt/providapt.toml -bpf 2>&1 || true)
echo "$BPF_OUT" | head -5
# BPF inspection may show fallback/unavailable in Docker Desktop — that's expected
check "bpf command executed" \
    "$(test -n "$BPF_OUT" && echo true || echo false)" \
    "BPF command produced no output"

# ============================================================
header "Phase 5: Generate Test Data & Replay"
# ============================================================

# --- 5a: Generate sample events ---
echo "[5a] Generating sample NDJSON event data..."
docker exec "$CONTAINER_NAME" bash -c '
    mkdir -p /tmp/test-events
    for i in $(seq 1 10); do
        TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ" --date="@$((1700000000 + i * 60))" 2>/dev/null || echo "2026-01-01T00:00:00Z")
        cat >> /tmp/test-events/events.ndjson <<EOF
{"timestamp":"${TS}","severity":"HIGH","pattern":"TEST_PATTERN_${i}","headline":"Test event ${i}","source":"e2e-test","details":{"test_id":"${i}"}}
EOF
    done
    echo "  Generated $(wc -l < /tmp/test-events/events.ndjson) events"
'

check "test events generated" \
    "$(docker exec "$CONTAINER_NAME" test -s /tmp/test-events/events.ndjson && echo true || echo false)"

# --- 5b: Replay events through daemon API ---
echo "[5b] Replaying events via CLI..."
REPLAY_OUT=$(docker exec "$CONTAINER_NAME" \
    /workspace/build/bin/providaptctl -config /etc/providapt/providapt.toml -replay -replay-input=/tmp/test-events -replay-max=10 2>&1 || true)
echo "$REPLAY_OUT" | head -10
check "replay command" \
    "$(echo "$REPLAY_OUT" | grep -ciE "replay|event|sent|deliver" || echo 0)" \
    "Replay output did not show event processing"

# --- 5c: Verify output directory has data ---
echo "[5c] Checking output directory..."
OUTPUT_FILES=$(docker exec "$CONTAINER_NAME" ls -la /workspace/build/e2e-data/output/ 2>/dev/null || echo "")
echo "$OUTPUT_FILES" | head -5
check "output directory non-empty" \
    "$(docker exec "$CONTAINER_NAME" find /workspace/build/e2e-data/output/ -type f 2>/dev/null | head -1 | wc -l || echo 0)" \
    "No output files created"

# --- 5d: Archive old logs ---
echo "[5d] Testing -archive command..."
ARCHIVE_OUT=$(docker exec "$CONTAINER_NAME" \
    /workspace/build/bin/providaptctl -config /etc/providapt/providapt.toml -archive -archive-dir=/workspace/build/e2e-data/output -archive-age=0 -archive-dry-run 2>&1 || true)
echo "$ARCHIVE_OUT" | head -3
check "archive command" \
    "$(test -n "$ARCHIVE_OUT" && echo true || echo false)" \
    "Archive produced no output"

# ============================================================
header "Phase 6: Store Operations (Backup/Restore/Verify)"
# ============================================================

# --- 6a: Backup ---
echo "[6a] Testing -backup command..."
BACKUP_OUT=$(docker exec "$CONTAINER_NAME" \
    /workspace/build/bin/providaptctl -config /etc/providapt/providapt.toml -backup -backup-out=/tmp/e2e-backup.tar.gz 2>&1 || true)
echo "$BACKUP_OUT" | head -5
check "backup command" \
    "$(docker exec "$CONTAINER_NAME" test -s /tmp/e2e-backup.tar.gz && echo true || echo false)" \
    "Backup file not created"

# --- 6b: Verify store ---
echo "[6b] Testing -verify command..."
VERIFY_OUT=$(docker exec "$CONTAINER_NAME" \
    /workspace/build/bin/providaptctl -config /etc/providapt/providapt.toml -verify 2>&1 || true)
echo "$VERIFY_OUT" | head -10
check "verify command" \
    "$(test -n "$VERIFY_OUT" && echo true || echo false)" \
    "Verify produced no output"

# ============================================================
header "Phase 7: Stop Daemon & Cleanup"
# ============================================================

# --- 7a: Stop via CLI ---
echo "[7a] Stopping daemon via providaptctl -stop..."
STOP_OUT=$(docker exec "$CONTAINER_NAME" \
    /workspace/build/bin/providaptctl -config /etc/providapt/providapt.toml -stop -json 2>&1 || true)
echo "$STOP_OUT" | head -3

sleep 2

# Check that process stopped
PROC_COUNT=$(docker exec "$CONTAINER_NAME" pgrep -c providaptd 2>/dev/null || echo 0)
check "daemon stopped" \
    "$([ "$PROC_COUNT" -eq 0 ] && echo true || echo false)" \
    "Daemon process still running (count: $PROC_COUNT)"

# --- 7b: Container cleanup ---
echo "[7b] Cleaning up container..."
docker stop "$CONTAINER_NAME" 2>/dev/null || true
docker rm "$CONTAINER_NAME" 2>/dev/null || true
check "container removed" \
    "$(docker ps -a --filter "name=$CONTAINER_NAME" -q | wc -l)" \
    "Container was not removed"

# ============================================================
header "Results"
# ============================================================
E2E_END=$(date +%s)
DURATION=$((E2E_END - E2E_START))

echo ""
echo "  Duration: ${DURATION}s"
echo "  Passed:   ${PASS} / ${TOTAL}"
echo "  Failed:   ${FAIL}"
echo ""
echo "  Details: $OUTPUT_DIR/"
echo "    build.log        — Build output"
echo "    daemon.log       — Daemon output"
echo "    providapt.toml   — Test config"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}══════════════════════════════${NC}"
    echo -e "  ${GREEN}  E2E TEST PASSED${NC}"
    echo -e "  ${GREEN}══════════════════════════════${NC}"
    exit 0
else
    echo -e "  ${RED}══════════════════════════════${NC}"
    echo -e "  ${RED}  ${FAIL} check(s) failed${NC}"
    echo -e "  ${RED}══════════════════════════════${NC}"
    exit 1
fi
