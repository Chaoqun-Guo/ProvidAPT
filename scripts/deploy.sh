#!/usr/bin/env bash
# =============================================================
# deploy.sh — Full ProvidAPT deployment pipeline.
#
# Steps:
#   1. Verify system requirements (verify.sh)
#   2. Build eBPF + Go binaries (make build)
#   3. Install to system directories
#   4. Create default config
#   5. Print next steps
#
# Usage:
#   ./scripts/deploy.sh
#   sudo ./scripts/deploy.sh
#   make install
# =============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║  ProvidAPT — Deployment                               ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: Verify environment ─────────────────────────
echo "[1/5] Checking system requirements..."
if bash scripts/verify.sh; then
    echo -e "  ${GREEN}✓${NC} System requirements met"
else
    echo ""
    echo -e "  ${YELLOW}Some checks failed. Run install-deps:${NC}"
    echo "    sudo bash scripts/install_deps.sh"
    echo "    or:  make install-deps"
    echo ""
    echo "  Continue anyway? (y/N)"
    read -r CONTINUE
    if [ "$CONTINUE" != "y" ] && [ "$CONTINUE" != "Y" ]; then
        echo "Aborted."
        exit 1
    fi
fi
echo ""

# ── Step 2: Build ──────────────────────────────────────
echo "[2/5] Building ProvidAPT..."
make build
echo -e "  ${GREEN}✓${NC} Build complete"
echo ""

# ── Step 3: Install ────────────────────────────────────
echo "[3/5] Installing to system..."
if [ "$(id -u)" -ne 0 ]; then
    echo -e "  ${YELLOW}Not running as root — skipping system install.${NC}"
    echo "  Binaries remain in: build/"
    INSTALLED=false
else
    INSTALL_DIR="/usr/local/lib/providapt/ebpf"
    BIN_DIR="/usr/local/sbin"
    CTL_DIR="/usr/local/bin"
    CONFIG_DIR="/etc/providapt"

    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"

    install -m 0755 build/bin/providaptd   "$BIN_DIR/providaptd"
    install -m 0755 build/bin/providaptctl "$CTL_DIR/providaptctl"
    install -m 0644 build/ebpf/lsm_hooks.bpf.o "$INSTALL_DIR/"

    if [ ! -f "$CONFIG_DIR/providapt.toml" ]; then
        cp scripts/providapt.toml "$CONFIG_DIR/providapt.toml"
        echo "  Created config: $CONFIG_DIR/providapt.toml"
    fi

    echo -e "  ${GREEN}✓${NC} Installed to system"
    INSTALLED=true
fi
echo ""

# ── Step 4: Create output directory ────────────────────
echo "[4/5] Creating output directory..."
OUTPUT_DIR="/var/log/providapt"
if [ "$(id -u)" -eq 0 ]; then
    mkdir -p "$OUTPUT_DIR"
    echo "  Output: $OUTPUT_DIR"
fi
echo -e "  ${GREEN}✓${NC}"
echo ""

# ── Step 5: Summary ────────────────────────────────────
echo "[5/5] Deployment summary"
echo ""
echo "  Binaries:"
echo "    daemon:    build/bin/providaptd"
echo "    control:   build/bin/providaptctl"
echo "    eBPF obj:  build/ebpf/lsm_hooks.bpf.o"
echo ""

if [ "$INSTALLED" = true ]; then
    echo "  System paths:"
    echo "    daemon:    /usr/local/sbin/providaptd"
    echo "    control:   /usr/local/bin/providaptctl"
    echo "    eBPF:      /usr/local/lib/providapt/ebpf/"
    echo "    config:    /etc/providapt/providapt.toml"
    echo "    logs:      /var/log/providapt/"
fi

echo ""
echo "  Quick start:"
echo "    sudo providaptd                # Start daemon"
echo "    make attack-sim                # Simulate attack"
echo "    sudo pkill providaptd          # Stop daemon"
echo "    make verify-capture            # Verify capture"
echo ""

echo "╔═══════════════════════════════════════════════════════╗"
echo "║  Deployment complete.                                 ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
