#!/usr/bin/env bash
set -euo pipefail

PURGE_DATA="${PURGE_DATA:-0}"
PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/providapt}"
STATE_DIR="${STATE_DIR:-/var/lib/providapt}"
LOG_DIR="${LOG_DIR:-/var/log/providapt}"
EBPF_DIR="${EBPF_DIR:-$PREFIX/lib/providapt/ebpf}"
SYSTEMD_FILE="${SYSTEMD_FILE:-/etc/systemd/system/providapt.service}"
ENV_FILE="${ENV_FILE:-/etc/default/providapt}"

if [ "$(id -u)" -ne 0 ]; then
	echo "ERROR: run as root, for example: sudo $0" >&2
	exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
	systemctl stop providapt.service >/dev/null 2>&1 || true
	systemctl disable providapt.service >/dev/null 2>&1 || true
fi

rm -f "$SYSTEMD_FILE"
rm -f "$PREFIX/sbin/providaptd" "$PREFIX/sbin/providapt-watchdog"
rm -f "$PREFIX/bin/providaptctl" "$PREFIX/bin/providapt-verify" "$PREFIX/bin/providapt-heal" "$PREFIX/bin/providapt-deanon"

if [ "$PURGE_DATA" = "1" ]; then
	rm -rf "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR" "$EBPF_DIR" "$ENV_FILE"
else
	echo "Keeping config and data. Set PURGE_DATA=1 to remove:"
	echo "  $CONFIG_DIR"
	echo "  $STATE_DIR"
	echo "  $LOG_DIR"
	echo "  $ENV_FILE"
fi

if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	systemctl reset-failed providapt.service >/dev/null 2>&1 || true
fi

echo "ProvidAPT uninstalled."
