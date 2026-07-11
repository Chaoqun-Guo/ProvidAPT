#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/providapt}"
STATE_DIR="${STATE_DIR:-/var/lib/providapt}"
LOG_DIR="${LOG_DIR:-/var/log/providapt}"
EBPF_DIR="${EBPF_DIR:-$PREFIX/lib/providapt/ebpf}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
ENV_FILE="${ENV_FILE:-/etc/default/providapt}"
SOURCE_ROOT="${SOURCE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
SERVICE_TEMPLATE="${SERVICE_TEMPLATE:-$SOURCE_ROOT/deploy/linux/providapt.service}"
ENV_TEMPLATE="${ENV_TEMPLATE:-$SOURCE_ROOT/deploy/linux/providapt.env}"
START_SERVICE="${START_SERVICE:-1}"

need_root() {
	if [ "$(id -u)" -ne 0 ]; then
		echo "ERROR: run as root, for example: sudo $0" >&2
		exit 1
	fi
}

install_user() {
	if ! getent passwd providapt >/dev/null 2>&1; then
		useradd --system --no-create-home --uid 950 \
			--shell /usr/sbin/nologin \
			--comment "ProvidAPT daemon user" providapt 2>/dev/null || true
	fi
}

install_dirs() {
	install -d "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR" "$EBPF_DIR" "$PREFIX/sbin" "$PREFIX/bin" "$SYSTEMD_DIR"
	chown providapt:providapt "$STATE_DIR" "$LOG_DIR" 2>/dev/null || true
	chmod 0750 "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR"
}

install_binaries() {
	install -m 0755 "$SOURCE_ROOT/build/bin/providaptd" "$PREFIX/sbin/providaptd"
	install -m 0755 "$SOURCE_ROOT/build/bin/providapt-watchdog" "$PREFIX/sbin/providapt-watchdog" 2>/dev/null || true
	for bin in providaptctl providapt-verify providapt-heal providapt-deanon; do
		if [ -x "$SOURCE_ROOT/build/bin/$bin" ]; then
			install -m 0755 "$SOURCE_ROOT/build/bin/$bin" "$PREFIX/bin/$bin"
		fi
	done
}

install_assets() {
	if ls "$SOURCE_ROOT/build/ebpf/"*.bpf.o >/dev/null 2>&1; then
		install -m 0644 "$SOURCE_ROOT/build/ebpf/"*.bpf.o "$EBPF_DIR/"
	fi
	if [ ! -f "$CONFIG_DIR/providapt.toml" ]; then
		install -m 0640 "$SOURCE_ROOT/build/providapt.toml" "$CONFIG_DIR/providapt.toml"
	fi
	if [ ! -f "$ENV_FILE" ]; then
		install -m 0644 "$ENV_TEMPLATE" "$ENV_FILE"
	fi
	install -m 0644 "$SERVICE_TEMPLATE" "$SYSTEMD_DIR/providapt.service"
}

enable_service() {
	if command -v systemctl >/dev/null 2>&1; then
		systemctl daemon-reload
		systemctl enable providapt.service
		if [ "$START_SERVICE" = "1" ]; then
			systemctl restart providapt.service
		fi
	fi
}

main() {
	need_root
	install_user
	install_dirs
	install_binaries
	install_assets
	enable_service
	echo "ProvidAPT installed."
	echo "Status: systemctl status providapt.service"
}

main "$@"
