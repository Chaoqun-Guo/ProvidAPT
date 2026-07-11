#!/usr/bin/env bash
set -euo pipefail

PACKAGE_PATH="${1:-${PROVIDAPT_UPGRADE_PACKAGE:-}}"
EXPECTED_SHA256="${EXPECTED_SHA256:-${PROVIDAPT_UPGRADE_SHA256:-}}"
MIN_FREE_MB="${MIN_FREE_MB:-512}"
CONFIG_PATH="${CONFIG_PATH:-/etc/providapt/providapt.toml}"
STATE_DIR="${STATE_DIR:-/var/lib/providapt}"
SERVICE_NAME="${SERVICE_NAME:-providapt.service}"

failures=0

check() {
	local name="$1"
	shift
	if "$@"; then
		printf 'PASS %-28s\n' "$name"
	else
		printf 'FAIL %-28s\n' "$name"
		failures=$((failures + 1))
	fi
}

has_systemd() { command -v systemctl >/dev/null 2>&1; }
service_known() { systemctl list-unit-files "$SERVICE_NAME" >/dev/null 2>&1; }
config_readable() { [ -r "$CONFIG_PATH" ]; }
kernel_supported() {
	local major minor
	major="$(uname -r | cut -d. -f1)"
	minor="$(uname -r | cut -d. -f2)"
	[ "$major" -gt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -ge 8 ]; }
}
btf_or_fallback() { [ -r /sys/kernel/btf/vmlinux ] || [ -r /usr/local/lib/providapt/ebpf/kprobe_fallback.bpf.o ]; }
disk_ok() {
	local path free
	path="$STATE_DIR"
	[ -d "$path" ] || path="/var/lib"
	free="$(df -Pm "$path" | awk 'NR==2 {print $4}')"
	[ "${free:-0}" -ge "$MIN_FREE_MB" ]
}
package_readable() { [ -z "$PACKAGE_PATH" ] || [ -r "$PACKAGE_PATH" ]; }
checksum_ok() {
	[ -z "$PACKAGE_PATH" ] && return 0
	[ -z "$EXPECTED_SHA256" ] && return 0
	echo "$EXPECTED_SHA256  $PACKAGE_PATH" | sha256sum -c - >/dev/null 2>&1
}

check "systemd available" has_systemd
check "service registered" service_known
check "config readable" config_readable
check "kernel >= 5.8" kernel_supported
check "BTF or kprobe fallback" btf_or_fallback
check "free disk >= ${MIN_FREE_MB}MB" disk_ok
check "package readable" package_readable
check "package checksum" checksum_ok

if [ "$failures" -ne 0 ]; then
	echo "Upgrade preflight failed: $failures check(s) failed." >&2
	exit 1
fi

echo "Upgrade preflight passed."
