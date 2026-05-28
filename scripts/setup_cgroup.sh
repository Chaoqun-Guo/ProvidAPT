#!/usr/bin/env bash
# =============================================================
# setup_cgroup.sh — Configure cgroup v2 resource limits for
# the ProvidAPT agent.
#
# Limits:
#   CPU:  10% max (100ms out of 1000ms)
#   Memory: 512MB hard limit, 480MB soft throttle
#
# These limits prevent the agent from starving other system
# processes while ensuring it can operate under normal load.
#
# Usage:
#   sudo ./scripts/setup_cgroup.sh
#   sudo ./scripts/setup_cgroup.sh --remove   # tear down
# =============================================================
set -euo pipefail

CGROUP_NAME="providapt"
CGROUP_DIR="/sys/fs/cgroup/${CGROUP_NAME}"
AGENT_BIN="providaptd"

# ── Detect cgroup version ───────────────────────────────
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    CGROUP_V="v2"
elif [ -f /sys/fs/cgroup/cpu/cpu.shares ]; then
    CGROUP_V="v1"
else
    CGROUP_V="none"
fi

# ── Remove ──────────────────────────────────────────────
if [ "${1:-}" = "--remove" ]; then
    echo "Removing ProvidAPT cgroup limits..."
    case "$CGROUP_V" in
        v2)
            rmdir "$CGROUP_DIR" 2>/dev/null || true
            ;;
        v1)
            for subsys in cpu memory; do
                rmdir "/sys/fs/cgroup/$subsys/$CGROUP_NAME" 2>/dev/null || true
            done
            ;;
    esac
    echo "  removed."
    exit 0
fi

echo "ProvidAPT Cgroup Setup"
echo "======================"
echo "  Cgroup version: $CGROUP_V"
echo ""

case "$CGROUP_V" in
    v2)
        setup_cgroup_v2
        ;;
    v1)
        setup_cgroup_v1
        ;;
    *)
        echo "WARNING: cgroup not detected. Skipping resource limits."
        echo "  To enable: mount -t cgroup2 none /sys/fs/cgroup"
        exit 0
        ;;
esac

# ── Attach running agent if present ─────────────────────
AGENT_PID=$(pidof "$AGENT_BIN" 2>/dev/null || true)
if [ -n "$AGENT_PID" ]; then
    echo "  Attaching running agent (PID $AGENT_PID)..."
    echo "$AGENT_PID" > "$CGROUP_DIR/cgroup.procs" 2>/dev/null || \
        echo "  WARNING: could not attach PID (agent may need restart)"
fi

echo ""
echo "✓ Cgroup limits active."
echo "  CPU:  10% max"
echo "  Mem:  512MB max, 480MB throttle"
echo ""
echo "  To verify: cat ${CGROUP_DIR}/cpu.max"
echo "  To remove: sudo $0 --remove"
echo ""

# ── Cgroup v2 setup ────────────────────────────────────
setup_cgroup_v2() {
    echo "[v2] Configuring cgroup at $CGROUP_DIR..."

    # Create cgroup
    if [ ! -d "$CGROUP_DIR" ]; then
        mkdir -p "$CGROUP_DIR"
    fi

    # CPU: max 10% (100ms runtime per 1000ms period)
    echo "100000 1000000" > "$CGROUP_DIR/cpu.max" 2>/dev/null || \
        echo "  WARNING: could not set cpu.max (kernel may lack support)"

    # Memory: 512MB hard limit
    echo "536870912" > "$CGROUP_DIR/memory.max" 2>/dev/null || true
    # Memory: 480MB soft throttle
    echo "503316480" > "$CGROUP_DIR/memory.high" 2>/dev/null || true

    echo "[v2] Limits applied."
}

# ── Cgroup v1 setup ────────────────────────────────────
setup_cgroup_v1() {
    echo "[v1] Configuring cgroup..."

    # CPU cgroup
    if [ -d /sys/fs/cgroup/cpu ]; then
        local cpu_dir="/sys/fs/cgroup/cpu/$CGROUP_NAME"
        mkdir -p "$cpu_dir"
        # CPU: 10% = 10000 out of 100000 (CFS quota)
        echo "10000" > "$cpu_dir/cpu.cfs_quota_us" 2>/dev/null || true
        echo "100000" > "$cpu_dir/cpu.cfs_period_us" 2>/dev/null || true
        echo "[v1] CPU limit: 10%"
    fi

    # Memory cgroup
    if [ -d /sys/fs/cgroup/memory ]; then
        local mem_dir="/sys/fs/cgroup/memory/$CGROUP_NAME"
        mkdir -p "$mem_dir"
        echo "536870912" > "$mem_dir/memory.limit_in_bytes" 2>/dev/null || true
        echo "503316480" > "$mem_dir/memory.soft_limit_in_bytes" 2>/dev/null || true
        echo "[v1] Memory limit: 512MB"
    fi
}
