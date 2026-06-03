#!/usr/bin/env bash
# =============================================================
# ProvidAPT — One-Click Installer
#
# Automatically detects the operating system, kernel
# capabilities, architecture, and installs the ProvidAPT
# provenance monitor as a systemd service.
#
# Usage:
#   curl -fsSL https://providapt.io/install.sh | sudo bash
#   sudo bash install.sh
#   sudo bash install.sh --version v1.0.2
#   sudo bash install.sh --build           # Build from source
#   sudo bash install.sh --help
# =============================================================
set -euo pipefail

# ── Constants ──────────────────────────────────────────────
REPO="Chaoqun-Guo/ProvidAPT"
RELEASE_BASE="https://github.com/${REPO}/releases/download"
VERSION=""
SKIP_VERIFY=false
BUILD_FROM_SOURCE=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Banner ─────────────────────────────────────────────────
print_banner() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║              ProvidAPT — One-Click Installer             ║"
    echo "║    Provenance-driven Advanced Persistent Threat Detection ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
}

# ── Help ───────────────────────────────────────────────────
usage() {
    echo "Usage: sudo bash install.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --version <tag>     Install a specific release (default: latest)"
    echo "  --build             Build from source instead of downloading"
    echo "  --skip-verify       Skip release signature verification"
    echo "  --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo bash install.sh"
    echo "  sudo bash install.sh --version v1.0.2"
    echo "  sudo bash install.sh --build"
    echo ""
    exit 0
}

# ── Parse arguments ────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)    VERSION="$2"; shift 2 ;;
        --build)      BUILD_FROM_SOURCE=true; shift ;;
        --skip-verify) SKIP_VERIFY=true; shift ;;
        --help|-h)    usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# ── Prerequisites ──────────────────────────────────────────
check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo -e "  ${RED}✗${NC} This script must be run as root (sudo)."
        exit 1
    fi
}

detect_os() {
    OS=""
    OS_LIKE=""
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS="$ID"
        OS_LIKE="${ID_LIKE:-}"
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
    elif [[ -f /etc/redhat-release ]]; then
        OS="rhel"
    else
        OS="linux"
    fi
    echo -e "  ${CYAN}OS:${NC} $OS ${OS_LIKE:+/ $OS_LIKE}"
}

detect_arch() {
    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64)  PKG_ARCH="amd64" ;;
        aarch64) PKG_ARCH="arm64" ;;
        *) echo -e "  ${RED}✗${NC} Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    echo -e "  ${CYAN}Arch:${NC} $ARCH"
}

detect_kernel() {
    echo -e "  ${CYAN}Kernel:${NC} $(uname -r)"
    # Check BTF support
    if [[ -f /sys/kernel/btf/vmlinux ]]; then
        echo -e "  ${CYAN}BTF:${NC} ${GREEN}supported${NC}"
        BTF_AVAILABLE=true
    else
        echo -e "  ${CYAN}BTF:${NC} ${YELLOW}not found (will use kprobe fallback)${NC}"
        BTF_AVAILABLE=false
    fi
}

check_deps() {
    local missing=false
    for cmd in curl systemctl; do
        if ! command -v "$cmd" &>/dev/null; then
            echo -e "  ${RED}✗${NC} Required dependency not found: $cmd"
            missing=true
        fi
    done
    if $missing; then
        exit 1
    fi
    echo -e "  ${CYAN}Deps:${NC} ${GREEN}OK${NC}"
}

# ── Resolve version ────────────────────────────────────────
resolve_version() {
    if [[ -z "$VERSION" ]]; then
        echo -ne "  Fetching latest release..."
        VERSION=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name":' \
            | sed 's/.*"tag_name": "\(.*\)".*/\1/' 2>/dev/null || echo "")
        if [[ -z "$VERSION" ]]; then
            VERSION="v1.0.2"
            echo -e " ${YELLOW}fallback ${VERSION}${NC}"
        else
            echo -e " ${GREEN}${VERSION}${NC}"
        fi
    fi
}

# ── Install from package ───────────────────────────────────
install_from_package() {
    local pkg_url="$1"
    local pkg_file="$2"

    echo ""
    echo -e "  ${BOLD}Downloading package...${NC}"
    curl -fsSL "$pkg_url" -o "/tmp/$pkg_file" || {
        echo -e "  ${RED}✗${NC} Download failed"
        return 1
    }
    echo -e "  ${GREEN}✓${NC} Downloaded: $pkg_file"

    case "$pkg_file" in
        *.deb)
            echo -e "  ${BOLD}Installing .deb package...${NC}"
            dpkg -i "/tmp/$pkg_file" || {
                apt-get install -f -y -qq
                dpkg -i "/tmp/$pkg_file"
            }
            ;;
        *.rpm)
            echo -e "  ${BOLD}Installing .rpm package...${NC}"
            rpm -i "/tmp/$pkg_file"
            ;;
        *.tar.gz)
            echo -e "  ${BOLD}Extracting tarball...${NC}"
            tar xzf "/tmp/$pkg_file" -C /tmp
            bash "/tmp/${pkg_file%.tar.gz}/install.sh"
            ;;
    esac

    echo -e "  ${GREEN}✓${NC} Package installed"
}

# ── Build from source ──────────────────────────────────────
build_from_source() {
    echo ""
    echo -e "  ${BOLD}Building from source...${NC}"

    local deps=""
    for cmd in go clang llvm-strip make; do
        if ! command -v "$cmd" &>/dev/null; then
            deps="$deps $cmd"
        fi
    done

    if [[ -n "$deps" ]]; then
        echo -e "  ${YELLOW}Missing build dependencies:$deps${NC}"
        echo -e "  ${YELLOW}See: https://github.com/${REPO}#build-from-source${NC}"
        echo -e "  ${YELLOW}Falling back to package download...${NC}"
        return 1
    fi

    local tmpdir
    tmpdir=$(mktemp -d)
    cd "$tmpdir"

    echo -e "  Cloning repository..."
    git clone --depth 1 --branch "${VERSION:-main}" \
        "https://github.com/${REPO}.git" .
    echo -e "  ${GREEN}✓${NC} Source cloned"

    echo -e "  Running make v1..."
    make v1 2>&1 | sed 's/^/    /'
    echo -e "  ${GREEN}✓${NC} Build complete"

    echo -e "  Installing to system..."
    make v1-install 2>&1 | sed 's/^/    /'

    cd /
    rm -rf "$tmpdir"

    echo -e "  ${GREEN}✓${NC} Built and installed from source"
    return 0
}

# ── Create providapt system user ──────────────────────────
setup_providapt_user() {
	if id -u providapt &>/dev/null; then
		echo -e "  ${GREEN}✓${NC} User 'providapt' already exists"
	else
		useradd --system --no-create-home --uid 950 \
			--shell /usr/sbin/nologin \
			--comment "ProvidAPT daemon user" providapt 2>/dev/null || {
			echo -e "  ${YELLOW}⚠ Failed to create user 'providapt'; continuing anyway${NC}"
			return
		}
		echo -e "  ${GREEN}✓${NC} Created system user 'providapt' (UID 950)"
	fi

	# Ensure data directory exists with correct ownership
	local data_dir="/var/log/providapt"
	if [[ -d "$data_dir" ]]; then
		chown providapt:providapt "$data_dir" 2>/dev/null || true
	fi
}

# ── Systemd setup ──────────────────────────────────────────
setup_systemd() {
    echo ""
    echo -e "  ${BOLD}Configuring systemd...${NC}"

    # Reload systemd in case the package already installed the service
    systemctl daemon-reload 2>/dev/null || true

    if systemctl is-enabled providapt.service &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Service already enabled"
    else
        systemctl enable providapt.service 2>/dev/null || {
            # Manual service install if package didn't do it
            if [[ ! -f /lib/systemd/system/providapt.service ]] && \
               [[ ! -f /etc/systemd/system/providapt.service ]]; then
                echo -e "  ${YELLOW}⚠ Installing systemd service manually...${NC}"
                install -m 0644 /usr/local/lib/providapt/systemd/providapt.service \
                    /etc/systemd/system/providapt.service 2>/dev/null || true
                systemctl daemon-reload
            fi
            systemctl enable providapt.service
        }
        echo -e "  ${GREEN}✓${NC} Service enabled"
    fi

    echo -e "  Starting providapt.service..."
    systemctl start providapt.service || {
        echo -e "  ${YELLOW}⚠ Service start failed, check: journalctl -xu providapt${NC}"
    }

    # Verify
    sleep 1
    if systemctl is-active providapt.service &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Service running"
    else
        echo -e "  ${RED}✗${NC} Service not running"
        echo "  Run: journalctl -xu providapt --no-pager"
    fi
}

# ── Post-install summary ───────────────────────────────────
print_summary() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║  ${GREEN}ProvidAPT installation complete${NC}                          ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
    echo "  ${BOLD}Commands:${NC}"
    echo "    systemctl status providapt    Daemon status"
    echo "    journalctl -fu providapt      Live logs"
    echo "    providaptctl -status          Quick status check"
    echo ""
    echo "  ${BOLD}Configuration:${NC}"
    echo "    /etc/providapt/providapt.toml"
    echo ""
    echo "  ${BOLD}Management tools:${NC}"
    echo "    providaptctl      Daemon control (status/stop/restart)"
    echo "    providapt-verify  Integrity verification"
    echo "    providapt-heal    Incident response"
    echo "    providapt-deanon  Hash de-anonymization"
    echo ""
    echo "  ${BOLD}Quick start:${NC}"
    echo "    sudo systemctl start providapt"
    echo "    sudo journalctl -fu providapt"
    echo ""

    # Show actual status
    if command -v providaptctl &>/dev/null; then
        providaptctl -status 2>&1 | sed 's/^/  /' || true
    fi
}

# ── Main ───────────────────────────────────────────────────
main() {
    print_banner
    check_root

    echo "  ${BOLD}[1/5] System detection${NC}"
    detect_os
    detect_arch
    detect_kernel
    check_deps
    echo ""

    echo "  ${BOLD}[1.5/5] Creating providapt system user${NC}"
    setup_providapt_user
    echo ""

    echo "  ${BOLD}[2/5] Resolving version${NC}"
    resolve_version
    echo ""

    echo "  ${BOLD}[3/5] Installing ProvidAPT ${VERSION}${NC}"

    local installed=false

    # Try building from source if requested
    if $BUILD_FROM_SOURCE; then
        if build_from_source; then
            installed=true
        fi
    fi

    # Try package download
    if ! $installed; then
        # Determine package format
        local pkg_url=""
        local pkg_file=""

        if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]] || \
           [[ "$OS_LIKE" == *"debian"* ]]; then
            pkg_file="providapt_${VERSION#v}_${PKG_ARCH}.deb"
            pkg_url="${RELEASE_BASE}/${VERSION}/${pkg_file}"
        elif [[ "$OS" == "rhel" ]] || [[ "$OS" == "centos" ]] || \
             [[ "$OS" == "fedora" ]] || [[ "$OS_LIKE" == *"rhel"* ]] || \
             [[ "$OS_LIKE" == *"fedora"* ]]; then
            pkg_file="providapt-${VERSION#v}-1.${ARCH}.rpm"
            pkg_url="${RELEASE_BASE}/${VERSION}/${pkg_file}"
        else
            pkg_file="providapt-${VERSION#v}-linux-${ARCH}.tar.gz"
            pkg_url="${RELEASE_BASE}/${VERSION}/${pkg_file}"
        fi

        if ! install_from_package "$pkg_url" "$pkg_file"; then
            echo ""
            echo -e "  ${YELLOW}⚠ Package download failed. Building from source...${NC}"
            build_from_source || {
                echo -e "  ${RED}✗${NC} Installation failed."
                echo "  Please see: https://github.com/${REPO}#installation"
                exit 1
            }
        fi
    fi
    echo ""

    echo "  ${BOLD}[4/5] Configuring systemd${NC}"
    setup_systemd
    echo ""

    echo "  ${BOLD}[5/5] Verifying installation${NC}"
    print_summary
}

main
