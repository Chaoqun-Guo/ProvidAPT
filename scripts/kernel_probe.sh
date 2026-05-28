#!/usr/bin/env bash
# =============================================================
# kernel_probe.sh — Detect kernel capabilities for eBPF mode
# selection.
#
# Detects which eBPF attachment modes the running kernel supports
# and exports the result as $PROBE_MODE:
#
#   fentry  — full fentry/fexit + LSM (kernel ≥5.11, optimal)
#   kprobe  — kprobe/kretprobe + LSM (kernel ≥5.5, fallback)
#   trace   — tracepoints only        (kernel ≥4.7, minimal)
#   none    — no eBPF support
#
# Usage:
#   source scripts/kernel_probe.sh
#   echo $PROBE_MODE   # → "fentry" or "kprobe" or "trace" or "none"
# =============================================================
set -euo pipefail

PROBE_MODE="none"
PROBE_KVER_MAJ=0
PROBE_KVER_MIN=0
PROBE_KVER_PAT=0
PROBE_BTF=false
PROBE_BPF_LSM=false

# ── Parse kernel version ────────────────────────────────
parse_kver() {
    local kver
    kver=$(uname -r | cut -d- -f1)
    PROBE_KVER_MAJ=$(echo "$kver" | cut -d. -f1)
    PROBE_KVER_MIN=$(echo "$kver" | cut -d. -f2)
    PROBE_KVER_PAT=$(echo "$kver" | cut -d. -f3 | cut -d- -f1)
    PROBE_KVER_PAT=${PROBE_KVER_PAT:-0}
}

# ── Check kernel config ─────────────────────────────────
check_config() {
    local opt="$1"
    local found=false
    for src in /proc/config.gz /boot/config-$(uname -r) /lib/modules/$(uname -r)/config; do
        if [ -f "$src" ]; then
            if zgrep -q "${opt}=y" "$src" 2>/dev/null || grep -q "${opt}=y" "$src" 2>/dev/null; then
                found=true
                break
            fi
        fi
    done
    $found && return 0 || return 1
}

# ── Check BTF ───────────────────────────────────────────
check_btf() {
    [ -f /sys/kernel/btf/vmlinux ]
}

# ── Check fentry (via kernel version) ───────────────────
check_fentry() {
    # fentry/fexit requires BPF trampoline, available since 5.11
    [ "$PROBE_KVER_MAJ" -gt 5 ] || \
        ([ "$PROBE_KVER_MAJ" -eq 5 ] && [ "$PROBE_KVER_MIN" -ge 11 ])
}

# ── Check BPF LSM support ───────────────────────────────
check_bpf_lsm() {
    check_config "CONFIG_BPF_LSM"
}

# ── Main probe ──────────────────────────────────────────
do_probe() {
    parse_kver
    PROBE_BTF=$(check_btf && echo true || echo false)
    PROBE_BPF_LSM=$(check_bpf_lsm && echo true || echo false)

    if check_fentry && $PROBE_BTF; then
        PROBE_MODE="fentry"
    elif $PROBE_BPF_LSM && $PROBE_BTF; then
        PROBE_MODE="kprobe"
    elif $PROBE_BTF; then
        PROBE_MODE="trace"
    else
        # Fallback: check if /sys/kernel/debug/kprobes exists
        if [ -d /sys/kernel/debug/kprobes ] 2>/dev/null; then
            PROBE_MODE="kprobe"
        else
            PROBE_MODE="none"
        fi
    fi
}

do_probe

# Export results for sourcing scripts
export PROBE_MODE
export PROBE_KVER_MAJ PROBE_KVER_MIN PROBE_KVER_PAT
export PROBE_BTF
export PROBE_BPF_LSM

# Print summary
echo "ProvidAPT Kernel Probe"
echo "======================"
echo "  Kernel:    $PROBE_KVER_MAJ.$PROBE_KVER_MIN.$PROBE_KVER_PAT"
echo "  BTF:       $PROBE_BTF"
echo "  BPF_LSM:   $PROBE_BPF_LSM"
echo "  Mode:      $PROBE_MODE"
echo ""
echo "  Recommended mode: $PROBE_MODE"
echo ""

# Exit with status (for non-sourcing usage)
if [ "$PROBE_MODE" = "none" ]; then
    echo "ERROR: No supported eBPF mode detected."
    echo "  Minimum requirements: kernel 4.7+ with CONFIG_BPF=y"
    exit 1
fi
exit 0
