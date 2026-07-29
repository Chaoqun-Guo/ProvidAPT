#!/usr/bin/env bash
set -euo pipefail

status=0

check_cmd() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    printf '[OK]   %s: %s\n' "$name" "$(command -v "$name")"
  else
    printf '[MISS] %s\n' "$name"
    status=1
  fi
}

check_cmd go
check_cmd make
check_cmd clang
check_cmd llvm-strip
check_cmd bpftool
check_cmd jq
check_cmd python3

if [[ -r /sys/kernel/btf/vmlinux ]]; then
  echo "[OK]   BTF: /sys/kernel/btf/vmlinux"
else
  echo "[MISS] BTF: /sys/kernel/btf/vmlinux is not readable"
  status=1
fi

if [[ -r /sys/kernel/security/lsm ]]; then
  lsm="$(cat /sys/kernel/security/lsm)"
  echo "[INFO] LSM: ${lsm}"
  if [[ ",${lsm}," != *",bpf,"* ]]; then
    echo "[WARN] BPF LSM is not listed. Add lsm=bpf to the kernel command line for full LSM coverage."
  fi
else
  echo "[WARN] Cannot read /sys/kernel/security/lsm"
fi

if command -v go >/dev/null 2>&1; then
  go version
fi

exit "$status"
