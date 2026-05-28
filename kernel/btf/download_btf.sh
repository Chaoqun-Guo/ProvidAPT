#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# download_btf.sh — Download BTF files for various Linux distros.
#
# BTF (BPF Type Format) enables CO-RE (Compile Once, Run Everywhere)
# eBPF programs. This script downloads pre-generated BTF information
# from the BTFHub repository for cross-distribution compatibility.
#
# Usage:
#   ./download_btf.sh ubuntu 20.04        # download for specific distro
#   ./download_btf.sh all                  # download for all known distros
#   ./download_btf.sh list                 # list available distros

set -euo pipefail

BTFHUB_BASE="https://github.com/aquasecurity/btfhub/raw/main"
OUTPUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/btf/artifacts"

mkdir -p "$OUTPUT_DIR"

download_btf() {
    local distro="$1"
    local version="$2"
    local arch="${3:-x86_64}"
    local url="${BTFHUB_BASE}/${distro}/${version}/${arch}.btf.tar.xz"
    local outfile="${OUTPUT_DIR}/${distro}-${version}-${arch}.btf.tar.xz"

    echo "Downloading BTF: ${distro} ${version} ${arch} ..."
    if curl -fSL -o "$outfile" "$url"; then
        echo "  -> saved to ${outfile}"
    else
        echo "  -> FAILED (not found: ${url})"
        rm -f "$outfile"
    fi
}

case "${1:-help}" in
    list)
        echo "Supported distros: ubuntu, debian, fedora, centos, rhel, arch, alpine"
        echo ""
        echo "Check ${BTFHUB_BASE} for the full list."
        ;;
    all)
        download_btf "ubuntu" "20.04"
        download_btf "ubuntu" "22.04"
        download_btf "ubuntu" "24.04"
        download_btf "debian" "11"
        download_btf "debian" "12"
        download_btf "fedora" "38"
        download_btf "fedora" "39"
        download_btf "centos" "8"
        download_btf "centos" "9"
        download_btf "alpine" "3.18"
        ;;
    ubuntu|debian|fedora|centos|rhel|arch|alpine)
        if [ $# -lt 2 ]; then
            echo "Usage: $0 <distro> <version> [arch]"
            exit 1
        fi
        download_btf "$1" "${2:-}" "${3:-x86_64}"
        ;;
    help|*)
        echo "Usage: $0 {list|all|<distro> <version> [arch]}"
        echo ""
        echo "Examples:"
        echo "  $0 list"
        echo "  $0 all"
        echo "  $0 ubuntu 22.04"
        echo "  $0 debian 12 aarch64"
        ;;
esac
