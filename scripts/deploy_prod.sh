#!/usr/bin/env bash
# =============================================================
# deploy_prod.sh — Production deployment with auto-detection.
#
#  1. Probe kernel capabilities
#  2. Install dependencies (if needed)
#  3. Build with optimal mode
#  4. Install to system
#  5. Configure cgroup limits
#  6. Install systemd service
#  7. Start agent
#
# Usage:
#   sudo bash scripts/deploy_prod.sh
# =============================================================
set -euo pipefail

cd "$(dirname "$0")/.."
PROJECT_DIR=$(pwd)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║  ProvidAPT — Production Deployment                    ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: Probe kernel ───────────────────────────────
echo "[1/7] Probing kernel capabilities..."
source scripts/kernel_probe.sh
echo -e "  ${GREEN}✓${NC} Mode: $PROBE_MODE"
echo ""

# ── Step 2: Verify environment ─────────────────────────
echo "[2/7] Verifying environment..."
if [ "$PROBE_MODE" = "none" ]; then
    echo -e "  ${RED}✗${NC} Kernel does not support eBPF. Aborting."
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Kernel $PROBE_KVER_MAJ.$PROBE_KVER_MIN.$PROBE_KVER_PAT"
echo -e "  ${GREEN}✓${NC} BTF: $PROBE_BTF, BPF_LSM: $PROBE_BPF_LSM"
echo ""

# ── Step 3: Build ──────────────────────────────────────
echo "[3/7] Building ProvidAPT..."
make clean 2>/dev/null || true
make build 2>&1 | sed 's/^/  /'
echo -e "  ${GREEN}✓${NC} Build complete"
echo ""

# ── Step 4: Install to system ──────────────────────────
echo "[4/7] Installing to system..."
if [ "$(id -u)" -ne 0 ]; then
    echo -e "  ${YELLOW}Not root — skipping system install.${NC}"
else
    INSTALL_DIR="/usr/local/lib/providapt/ebpf"
    CONFIG_DIR="/etc/providapt"
    BIN_DIR="/usr/local/sbin"
    CTL_DIR="/usr/local/bin"

    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"
    install -m 0755 build/bin/providaptd        "$BIN_DIR/providaptd"
    install -m 0755 build/bin/providaptctl      "$CTL_DIR/providaptctl"
    install -m 0755 build/bin/providapt-watchdog "$BIN_DIR/providapt-watchdog"
    install -m 0644 build/ebpf/*.bpf.o          "$INSTALL_DIR/"
    install -m 0644 scripts/providapt.toml      "$CONFIG_DIR/providapt.toml"
    echo -e "  ${GREEN}✓${NC} Installed to system"
fi
echo ""

# ── Step 5: Cgroup limits ─────────────────────────────
echo "[5/7] Configuring resource limits..."
if [ "$(id -u)" -eq 0 ]; then
    bash scripts/setup_cgroup.sh 2>&1 | sed 's/^/  /'
fi
echo ""

# ── Step 6: Systemd service ───────────────────────────
echo "[6/7] Installing systemd service..."
if [ "$(id -u)" -eq 0 ] && command -v systemctl &>/dev/null; then
    cp scripts/providapt-cgroup.service /etc/systemd/system/providapt.service
    systemctl daemon-reload 2>/dev/null || true
    echo -e "  ${GREEN}✓${NC} Service installed: /etc/systemd/system/providapt.service"
    echo "  Start:  sudo systemctl start providapt"
    echo "  Enable: sudo systemctl enable providapt"
    echo "  Status: sudo systemctl status providapt"
else
    echo -e "  ${YELLOW}~${NC} systemd not available — skipping"
fi
echo ""

# ── Step 7: Summary ────────────────────────────────────
echo "[7/7] Deployment summary"
echo ""
echo "  Mode:       $PROBE_MODE"
echo "  Binaries:   build/bin/"
echo "  eBPF:       build/ebpf/"
echo "  Cgroup:     /sys/fs/cgroup/providapt/"
echo "  Systemd:    providapt.service"
echo ""
echo "  Quick start:"
echo "    sudo systemctl start providapt"
echo "    sudo journalctl -fu providapt"
echo ""

echo "╔═══════════════════════════════════════════════════════╗"
echo "║  Deployment complete.                                 ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
