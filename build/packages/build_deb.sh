#!/usr/bin/env bash
# =============================================================
# build_deb.sh — Build ProvidAPT .deb package
#
# Builds a Debian package from pre-compiled binaries.
# Requires: dpkg-deb, fakeroot (optional)
#
# Usage:
#   ./build_deb.sh [version] [arch]
# =============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

VERSION="${1:-$(cd "$PROJECT_DIR" && git describe --tags --always 2>/dev/null || echo "dev")}"
ARCH="${2:-$(dpkg --print-architecture 2>/dev/null || uname -m)}"

# Map arch names
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

PKG_NAME="providapt_${VERSION}_${ARCH}"
STAGING_DIR=$(mktemp -d)
trap 'rm -rf "$STAGING_DIR"' EXIT

echo "Building .deb package: $PKG_NAME"

# ── Staging layout ─────────────────────────────────────────
BIN_DIR="$STAGING_DIR/usr/local/sbin"
CTL_DIR="$STAGING_DIR/usr/local/bin"
EBPF_DIR="$STAGING_DIR/usr/local/lib/providapt/ebpf"
CONF_DIR="$STAGING_DIR/etc/providapt"
ENV_DIR="$STAGING_DIR/etc/default"
SYSD_DIR="$STAGING_DIR/lib/systemd/system"
DEBIAN_DIR="$STAGING_DIR/DEBIAN"

mkdir -p "$BIN_DIR" "$CTL_DIR" "$EBPF_DIR" "$CONF_DIR" "$ENV_DIR" "$SYSD_DIR" "$DEBIAN_DIR"

# ── Install binaries ───────────────────────────────────────
install -m 0755 "$PROJECT_DIR/build/bin/providaptd"        "$BIN_DIR/providaptd"
install -m 0755 "$PROJECT_DIR/build/bin/providaptctl"      "$CTL_DIR/providaptctl"
install -m 0755 "$PROJECT_DIR/build/bin/providapt-watchdog"  "$BIN_DIR/providapt-watchdog"
install -m 0755 "$PROJECT_DIR/build/bin/providapt-verify"    "$CTL_DIR/providapt-verify"
install -m 0755 "$PROJECT_DIR/build/bin/providapt-heal"      "$CTL_DIR/providapt-heal"
install -m 0755 "$PROJECT_DIR/build/bin/providapt-deanon"    "$CTL_DIR/providapt-deanon"
install -m 0755 "$PROJECT_DIR/build/bin/providapt-sign"      "$CTL_DIR/providapt-sign"

# ── Install eBPF objects ───────────────────────────────────
if ls "$PROJECT_DIR/build/ebpf/"*.bpf.o 2>/dev/null; then
    install -m 0644 "$PROJECT_DIR/build/ebpf/"*.bpf.o "$EBPF_DIR/"
fi

# ── Install config ─────────────────────────────────────────
install -m 0644 "$PROJECT_DIR/build/providapt.toml" "$CONF_DIR/providapt.toml"
install -m 0644 "$PROJECT_DIR/build/providapt.env" "$ENV_DIR/providapt"

# ── Install systemd service ────────────────────────────────
install -m 0644 "$PROJECT_DIR/deploy/linux/providapt.service" \
    "$SYSD_DIR/providapt.service"

# ── DEBIAN control file ────────────────────────────────────
cat > "$DEBIAN_DIR/control" <<EOF
Package: providapt
Version: ${VERSION#v}
Section: utils
Priority: optional
Architecture: $ARCH
Maintainer: ProvidAPT Team <dev@providapt.io>
Depends: libc6 (>= 2.31), systemd (>= 245)
Recommends: bpftool, linux-headers-$(uname -r)
Description: Provenance-driven APT Detection Platform
 ProvidAPT is an eBPF-based provenance monitor that constructs
 real-time attack graphs for advanced persistent threat detection.
 It captures system call events, builds process lineage, and
 performs automated incident response.
EOF

cat > "$DEBIAN_DIR/postinst" <<'SCRIPT'
#!/bin/sh
set -e

# Create providapt system user
if ! getent passwd providapt >/dev/null 2>&1; then
    useradd --system --no-create-home --uid 950 \
        --shell /usr/sbin/nologin \
        --comment "ProvidAPT daemon user" providapt 2>/dev/null || true
fi

# Ensure data directory permissions
if [ -d /var/log/providapt ]; then
    chown providapt:providapt /var/log/providapt 2>/dev/null || true
fi
mkdir -p /var/lib/providapt /var/log/providapt /run/providapt
chown providapt:providapt /var/lib/providapt /var/log/providapt /run/providapt 2>/dev/null || true

# Enable and start systemd service
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable providapt.service >/dev/null 2>&1 || true
    systemctl start providapt.service >/dev/null 2>&1 || true
    echo "  ProvidAPT service enabled and started."
    echo "  Status: systemctl status providapt"
fi
SCRIPT
chmod 0755 "$DEBIAN_DIR/postinst"

cat > "$DEBIAN_DIR/prerm" <<'SCRIPT'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop providapt.service >/dev/null 2>&1 || true
fi
SCRIPT
chmod 0755 "$DEBIAN_DIR/prerm"

cat > "$DEBIAN_DIR/postrm" <<'SCRIPT'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
SCRIPT
chmod 0755 "$DEBIAN_DIR/postrm"

# ── Build .deb ─────────────────────────────────────────────
mkdir -p "$PROJECT_DIR/build/dist"
fakeroot dpkg-deb --build "$STAGING_DIR" "$PROJECT_DIR/build/dist/$PKG_NAME.deb" 2>/dev/null \
    || dpkg-deb --build "$STAGING_DIR" "$PROJECT_DIR/build/dist/$PKG_NAME.deb"

echo "✓ Package created: build/dist/$PKG_NAME.deb"
