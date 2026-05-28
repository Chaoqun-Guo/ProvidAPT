#!/usr/bin/env bash
# =============================================================
# verify.sh — Check that the target system meets ProvidAPT
# kernel requirements.
#
# Usage:
#   ./scripts/verify.sh
#   make verify-env
#
# Exit codes:
#   0  — all checks pass
#   1  — at least one check failed
# =============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Colour

PASS=0
FAIL=0
SKIP=0

check() {
    local name="$1"
    local cmd="$2"
    if eval "$cmd" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} $name"
        ((PASS++))
    else
        echo -e "  ${RED}✗${NC} $name"
        ((FAIL++))
    fi
}

check_warn() {
    local name="$1"
    local cmd="$2"
    if eval "$cmd" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} $name"
        ((PASS++))
    else
        echo -e "  ${YELLOW}~${NC} $name  (optional, skipping)"
        ((SKIP++))
    fi
}

echo ""
echo "ProvidAPT — System requirements check"
echo "====================================="
echo ""

# ── Kernel version ─────────────────────────────────────
echo "[ kernel ]"
check "Linux kernel 5.11+ detected" \
    'uname -r | grep -qE "^([5-9]|6\.)" && test "$(uname -r | cut -d. -f1)" -ge 5 -a "$(uname -r | cut -d. -f2)" -ge 11 2>/dev/null || test "$(uname -r | cut -d. -f1)" -ge 6'

# CO-RE / BTF
check "BTF available (/sys/kernel/btf/vmlinux)" \
    'test -f /sys/kernel/btf/vmlinux'

# ── Kernel config ─────────────────────────────────────
echo ""
echo "[ kernel config ]"

# Try multiple locations for the kernel config
KCONFIG=""
for loc in /proc/config.gz /boot/config-$(uname -r) /lib/modules/$(uname -r)/config; do
    if [ -f "$loc" ] || [ -f "$loc.gz" ]; then
        KCONFIG="$loc"
        break
    fi
done

if [ -n "$KCONFIG" ]; then
    zcat_cmd="cat"
    if echo "$KCONFIG" | grep -q '\.gz$'; then
        zcat_cmd="zcat"
    fi

    check "CONFIG_BPF=y"       '$zcat_cmd "$KCONFIG" 2>/dev/null | grep -q "CONFIG_BPF=y"'
    check "CONFIG_BPF_SYSCALL=y" '$zcat_cmd "$KCONFIG" 2>/dev/null | grep -q "CONFIG_BPF_SYSCALL=y"'
    check "CONFIG_BPF_LSM=y"   '$zcat_cmd "$KCONFIG" 2>/dev/null | grep -q "CONFIG_BPF_LSM=y"'
    check "CONFIG_DEBUG_INFO_BTF=y" '$zcat_cmd "$KCONFIG" 2>/dev/null | grep -q "CONFIG_DEBUG_INFO_BTF=y"'
else
    echo -e "  ${YELLOW}~${NC} kernel config not found at /proc/config.gz or /boot"
    ((SKIP+=4))
fi

# ── Tools ──────────────────────────────────────────────
echo ""
echo "[ toolchain ]"
check "clang available"    'command -v clang && clang --version | grep -qi "clang"'
check "llvm-strip available" 'command -v llvm-strip'
check "bpftool available"  'command -v bpftool'
check "Go available"       'command -v go'
check "make available"     'command -v make'

# ── Libraries ──────────────────────────────────────────
echo ""
echo "[ libraries ]"
check_warn "libbpf (pkg-config)"    'pkg-config --cflags libbpf 2>/dev/null || test -f /usr/include/bpf/bpf.h'
check_warn "kernel headers"         'test -d /usr/include/linux || test -d /lib/modules/$(uname -r)/build/include'

# ── Runtime state ──────────────────────────────────────
echo ""
echo "[ runtime ]"
check_warn "BPF filesystem mounted" 'mount | grep -q "bpffs"'
check_warn "LSM BPF enabled in cmdline" 'cat /sys/kernel/security/lsm 2>/dev/null | grep -qi "bpf" || cat /proc/1/cmdline 2>/dev/null | tr "\0" "\n" | grep -q "lsm="'

# ── Summary ────────────────────────────────────────────
echo ""
echo "====================================="
echo -e "  ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$SKIP skipped${NC}"
echo "====================================="
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "Some required checks failed. Run:  make install-deps"
    echo ""
    exit 1
fi

echo "All requirements satisfied."
echo ""
exit 0
