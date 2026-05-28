#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== Building ProvidAPT ==="

echo "--- Building eBPF objects ---"
make ebpf

echo "--- Building userspace binaries ---"
make userspace

echo "--- Done ---"
echo "Binaries: build/bin/"
echo "eBPF:     build/ebpf/"
