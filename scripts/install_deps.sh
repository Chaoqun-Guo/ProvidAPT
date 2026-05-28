#!/usr/bin/env bash
# =============================================================
# install_deps.sh — Install ProvidAPT build & runtime
# dependencies for the detected Linux distribution.
#
# Supports: Ubuntu, Debian, Fedora, RHEL, Rocky, Alma, Arch, Alpine
#
# Usage:
#   ./scripts/install_deps.sh
#   sudo ./scripts/install_deps.sh   (if not running as root)
#   make install-deps
# =============================================================
set -euo pipefail

# Detect package manager
detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    elif command -v pacman &>/dev/null; then
        echo "pacman"
    elif command -v apk &>/dev/null; then
        echo "apk"
    else
        echo "unknown"
    fi
}

# Detect distro name
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/redhat-release ]; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

PM=$(detect_pkg_manager)
DISTRO=$(detect_distro)

echo "ProvidAPT — Installing dependencies"
echo "===================================="
echo "  Distro:   $DISTRO"
echo "  Manager:  $PM"
echo ""

if [ "$(id -u)" -ne 0 ] && [ "$PM" != "unknown" ]; then
    echo "!! Most package managers require root. Re-run with sudo if needed."
    echo ""
fi

install_apt() {
    apt-get update -qq
    apt-get install -y -qq \
        clang \
        llvm \
        lld \
        bpftool \
        libbpf-dev \
        linux-headers-$(uname -r) \
        pkg-config \
        curl \
        git \
        make \
        jq \
        python3 \
        python3-pip
}

install_dnf() {
    dnf install -y \
        clang \
        llvm \
        lld \
        bpftool \
        libbpf-devel \
        kernel-devel \
        kernel-headers \
        pkgconfig \
        curl \
        git \
        make \
        jq \
        python3 \
        python3-pip
}

install_yum() {
    yum install -y epel-release || true
    yum install -y \
        clang \
        llvm \
        lld \
        bpftool \
        libbpf-devel \
        kernel-devel \
        kernel-headers \
        pkgconfig \
        curl \
        git \
        make \
        jq
}

install_pacman() {
    pacman -Sy --noconfirm \
        clang \
        llvm \
        lld \
        bpftool \
        libbpf \
        linux-headers \
        pkgconf \
        curl \
        git \
        make \
        jq \
        python \
        python-pip
}

install_apk() {
    apk add --no-cache \
        clang \
        llvm \
        lld \
        bpftool \
        libbpf-dev \
        linux-headers \
        pkgconf \
        curl \
        git \
        make \
        jq \
        python3 \
        py3-pip
}

case "$PM" in
    apt)
        install_apt
        ;;
    dnf)
        install_dnf
        ;;
    yum)
        install_yum
        ;;
    pacman)
        install_pacman
        ;;
    apk)
        install_apk
        ;;
    *)
        echo "!! Unsupported package manager."
        echo "   Please install manually: clang, llvm, lld, bpftool, libbpf, kernel-headers"
        exit 1
        ;;
esac

echo ""
echo "✓ Dependencies installed."
echo ""

# Verify key tools
echo "Verifying installation..."
for tool in clang llvm-strip bpftool go make jq; do
    if command -v "$tool" &>/dev/null; then
        echo "  ✓ $tool"
    else
        echo "  ✗ $tool  NOT FOUND"
    fi
done

echo ""
echo "Next steps:"
echo "  make verify-env    # Confirm system readiness"
echo "  make build         # Build ProvidAPT"
echo "  make install       # Install to system"
echo ""
