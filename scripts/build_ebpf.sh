#!/usr/bin/env bash
# build_ebpf.sh — Cross-compile eBPF for multiple architectures.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_DIR}/build/ebpf"
mkdir -p "$OUTPUT_DIR"

CLANG="${CLANG:-clang}"
LLVM_STRIP="${LLVM_STRIP:-llvm-strip}"

compile_bpf() {
    local arch="$1"
    local target="${2:-bpf}"
    local cflags="${3:-}"

    echo "  compiling for ${arch}..."

    "$CLANG" -O2 -g -target "$target"              \
        -D__TARGET_ARCH_$(echo "$arch" | tr '[:lower:]' '[:upper:]') \
        -I "${PROJECT_DIR}/kernel/include"           \
        -Wall -Werror                               \
        $cflags                                      \
        -c "${PROJECT_DIR}/kernel/bpf/lsm_hooks.bpf.c" \
        -o "${OUTPUT_DIR}/lsm_hooks_${arch}.bpf.o"

    "$LLVM_STRIP" -g "${OUTPUT_DIR}/lsm_hooks_${arch}.bpf.o" || true
}

echo "Building eBPF for supported architectures..."
compile_bpf "x86_64"  "bpf"    "-mlittle-endian"
compile_bpf "arm64"   "bpf"    "-mlittle-endian"

echo "Done. Output in ${OUTPUT_DIR}"
ls -lh "${OUTPUT_DIR}"
