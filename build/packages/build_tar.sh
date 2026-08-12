#!/usr/bin/env bash
# =============================================================
# build_tar.sh — Build ProvidAPT tarball (universal)
#
# Creates a portable tarball for systems without dpkg/rpm.
#
# Usage:
#   ./build_tar.sh [version] [arch]
# =============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

VERSION="${1:-$(cd "$PROJECT_DIR" && git describe --tags --always 2>/dev/null || echo "dev")}"
ARCH="${2:-${GOARCH:-$(uname -m)}}"

PKG_NAME="providapt-${VERSION}-linux-${ARCH}"
STAGING_DIR=$(mktemp -d)
trap 'rm -rf "$STAGING_DIR"' EXIT

echo "Building tarball: $PKG_NAME.tar.gz"

# ── Layout ─────────────────────────────────────────────────
mkdir -p "$STAGING_DIR/$PKG_NAME"/{bin,ebpf,config,systemd,scripts}

# ── Install binaries ───────────────────────────────────────
install -m 0755 "$PROJECT_DIR/build/bin/providaptd"        "$STAGING_DIR/$PKG_NAME/bin/"
install -m 0755 "$PROJECT_DIR/build/bin/providaptctl"      "$STAGING_DIR/$PKG_NAME/bin/"
install -m 0755 "$PROJECT_DIR/build/bin/providapt-watchdog"  "$STAGING_DIR/$PKG_NAME/bin/"
install -m 0755 "$PROJECT_DIR/build/bin/providapt-verify"    "$STAGING_DIR/$PKG_NAME/bin/"
install -m 0755 "$PROJECT_DIR/build/bin/providapt-heal"      "$STAGING_DIR/$PKG_NAME/bin/"
install -m 0755 "$PROJECT_DIR/build/bin/providapt-deanon"    "$STAGING_DIR/$PKG_NAME/bin/"
install -m 0755 "$PROJECT_DIR/build/bin/providapt-sign"      "$STAGING_DIR/$PKG_NAME/bin/"

# ── eBPF objects ───────────────────────────────────────────
if ls "$PROJECT_DIR/build/ebpf/"*.bpf.o 2>/dev/null; then
    install -m 0644 "$PROJECT_DIR/build/ebpf/"*.bpf.o "$STAGING_DIR/$PKG_NAME/ebpf/"
fi

# ── Config ─────────────────────────────────────────────────
install -m 0644 "$PROJECT_DIR/build/providapt.toml" "$STAGING_DIR/$PKG_NAME/config/"
install -m 0644 "$PROJECT_DIR/build/providapt.env" "$STAGING_DIR/$PKG_NAME/config/providapt.env"
install -m 0644 "$PROJECT_DIR/deploy/linux/providapt.service" \
    "$STAGING_DIR/$PKG_NAME/systemd/providapt.service"
install -m 0755 "$PROJECT_DIR/scripts/install/uninstall-linux.sh" "$STAGING_DIR/$PKG_NAME/scripts/uninstall-linux.sh"
install -m 0755 "$PROJECT_DIR/scripts/upgrade/preflight-linux.sh" "$STAGING_DIR/$PKG_NAME/scripts/preflight-linux.sh"

# ── Install helper ─────────────────────────────────────────
cat > "$STAGING_DIR/$PKG_NAME/install.sh" <<'INSTALL_SCRIPT'
#!/usr/bin/env bash
# One-command install from tarball
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root: sudo ./install.sh"
    exit 1
fi
DIR="$(cd "$(dirname "$0")" && pwd)"
echo "Installing ProvidAPT from tarball..."
if ! getent passwd providapt >/dev/null 2>&1; then
    useradd --system --no-create-home --uid 950 \
        --shell /usr/sbin/nologin \
        --comment "ProvidAPT daemon user" providapt 2>/dev/null || true
fi
install -d /usr/local/sbin /usr/local/bin /usr/local/lib/providapt/ebpf /etc/providapt /etc/default /var/lib/providapt /var/log/providapt
chown providapt:providapt /var/lib/providapt /var/log/providapt 2>/dev/null || true
install -m 0755 "$DIR/bin/providaptd" /usr/local/sbin/providaptd
install -m 0755 "$DIR/bin/providapt-watchdog" /usr/local/sbin/providapt-watchdog 2>/dev/null || true
for bin in providaptctl providapt-verify providapt-heal providapt-deanon providapt-sign; do
    [ -x "$DIR/bin/$bin" ] && install -m 0755 "$DIR/bin/$bin" "/usr/local/bin/$bin"
done
install -m 0644 "$DIR/ebpf/"*.bpf.o /usr/local/lib/providapt/ebpf/ 2>/dev/null || true
[ -f /etc/providapt/providapt.toml ] || install -m 0644 "$DIR/config/providapt.toml" /etc/providapt/providapt.toml
[ -f /etc/default/providapt ] || install -m 0644 "$DIR/config/providapt.env" /etc/default/providapt
install -m 0644 "$DIR/systemd/providapt.service" /lib/systemd/system/providapt.service
systemctl daemon-reload
systemctl enable providapt.service
systemctl start providapt.service
echo "ProvidAPT installed and started."
INSTALL_SCRIPT
chmod 0755 "$STAGING_DIR/$PKG_NAME/install.sh"

# ── Create tarball ─────────────────────────────────────────
mkdir -p "$PROJECT_DIR/build/dist"
cd "$STAGING_DIR"
tar czf "$PROJECT_DIR/build/dist/$PKG_NAME.tar.gz" "$PKG_NAME"

echo "✓ Package created: build/dist/$PKG_NAME.tar.gz"
echo "  Extract: tar xzf $PKG_NAME.tar.gz"
echo "  Install: sudo ./$PKG_NAME/install.sh"
