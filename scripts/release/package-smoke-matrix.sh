#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST_DIR="${DIST_DIR:-$PROJECT_DIR/dist}"
REPORT_DIR="${REPORT_DIR:-$PROJECT_DIR/build/package-smoke}"
UBUNTU_IMAGE="${UBUNTU_IMAGE:-ubuntu:22.04}"
RPM_IMAGE="${RPM_IMAGE:-rockylinux:8}"
PACKAGE_SMOKE_MODE="${PACKAGE_SMOKE_MODE:-docker}"

log() {
	printf '\n==> %s\n' "$*"
}

require_docker() {
	if ! command -v docker >/dev/null 2>&1; then
		printf 'ERROR: docker is required for package smoke matrix\n' >&2
		exit 1
	fi
}

as_root() {
	if [ "$(id -u)" -eq 0 ]; then
		"$@"
	else
		sudo "$@"
	fi
}

find_one() {
	local pattern="$1"
	find "$DIST_DIR" -maxdepth 1 -type f -name "$pattern" | sort | head -n 1
}

run_ubuntu_deb() {
	local deb="$1"
	[ -n "$deb" ] || return 0
	log "Testing Debian package on $UBUNTU_IMAGE"
	docker run --rm \
		-v "$DIST_DIR:/dist:ro" \
		-v "$REPORT_DIR:/report" \
		"$UBUNTU_IMAGE" \
		bash -lc "set -euo pipefail; apt-get update >/dev/null; apt-get install -y systemd ca-certificates >/dev/null; dpkg -i /dist/$(basename "$deb") || apt-get install -f -y; providaptctl -config-check -config /etc/providapt/providapt.toml >/report/deb-config-check.txt; dpkg -r providapt >/report/deb-remove.txt"
}

run_rpm() {
	local rpm="$1"
	[ -n "$rpm" ] || return 0
	log "Testing RPM package on $RPM_IMAGE"
	docker run --rm \
		-v "$DIST_DIR:/dist:ro" \
		-v "$REPORT_DIR:/report" \
		"$RPM_IMAGE" \
		bash -lc "set -euo pipefail; rpm -Uvh /dist/$(basename "$rpm") >/report/rpm-install.txt; providaptctl -config-check -config /etc/providapt/providapt.toml >/report/rpm-config-check.txt; rpm -e providapt >/report/rpm-remove.txt"
}

run_tarball() {
	local archive="$1"
	[ -n "$archive" ] || return 0
	log "Testing tar archive on $UBUNTU_IMAGE"
	docker run --rm \
		-v "$DIST_DIR:/dist:ro" \
		-v "$REPORT_DIR:/report" \
		"$UBUNTU_IMAGE" \
		bash -lc "set -euo pipefail; mkdir -p /tmp/providapt-smoke; tar -xzf /dist/$(basename "$archive") -C /tmp/providapt-smoke; find /tmp/providapt-smoke -type f -name providaptctl -perm /111 -print -quit >/report/tar-providaptctl-path.txt; test -s /report/tar-providaptctl-path.txt"
}

run_host_deb() {
	local deb="$1"
	[ -n "$deb" ] || return 0
	log "Testing Debian package on host"
	if ! command -v dpkg >/dev/null 2>&1; then
		printf 'ERROR: host mode requires dpkg for Debian package smoke\n' >&2
		exit 1
	fi
	as_root dpkg -i "$deb" >"$REPORT_DIR/deb-install.txt" 2>"$REPORT_DIR/deb-install.err" || {
		if command -v apt-get >/dev/null 2>&1; then
			as_root apt-get install -f -y >>"$REPORT_DIR/deb-install.txt" 2>>"$REPORT_DIR/deb-install.err"
		else
			printf 'ERROR: dpkg install failed and apt-get is unavailable\n' >&2
			exit 1
		fi
	}
	providaptctl -config-check -config /etc/providapt/providapt.toml >"$REPORT_DIR/deb-config-check.txt"
	as_root dpkg -r providapt >"$REPORT_DIR/deb-remove.txt" 2>"$REPORT_DIR/deb-remove.err" || true
	as_root dpkg --purge providapt >"$REPORT_DIR/deb-purge.txt" 2>"$REPORT_DIR/deb-purge.err" || true
}

run_host_rpm_extract() {
	local rpm="$1"
	[ -n "$rpm" ] || return 0
	log "Testing RPM package metadata and extraction on host"
	if ! command -v rpm >/dev/null 2>&1 || ! command -v rpm2cpio >/dev/null 2>&1 || ! command -v cpio >/dev/null 2>&1; then
		printf 'ERROR: host mode requires rpm, rpm2cpio, and cpio for RPM smoke\n' >&2
		exit 1
	fi
	rpm -qpi "$rpm" >"$REPORT_DIR/rpm-info.txt"
	rpm -qpl "$rpm" >"$REPORT_DIR/rpm-file-list.txt"
	local tmp
	tmp="$(mktemp -d)"
	(cd "$tmp" && rpm2cpio "$rpm" | cpio -idmu >/dev/null 2>"$REPORT_DIR/rpm-extract.err")
	find "$tmp" -type f -name providaptctl -perm /111 -print -quit >"$REPORT_DIR/rpm-providaptctl-path.txt"
	test -s "$REPORT_DIR/rpm-providaptctl-path.txt"
	rm -rf "$tmp"
}

run_host_tarball() {
	local archive="$1"
	[ -n "$archive" ] || return 0
	log "Testing tar archive on host"
	local tmp
	tmp="$(mktemp -d)"
	tar -xzf "$archive" -C "$tmp"
	find "$tmp" -type f -name providaptctl -perm /111 -print -quit >"$REPORT_DIR/tar-providaptctl-path.txt"
	test -s "$REPORT_DIR/tar-providaptctl-path.txt"
	rm -rf "$tmp"
}

main() {
	mkdir -p "$REPORT_DIR"
	local deb rpm archive
	deb="$(find_one '*.deb')"
	rpm="$(find_one '*.rpm')"
	archive="$(find_one '*.tar.gz')"
	if [ -z "$deb" ] && [ -z "$rpm" ] && [ -z "$archive" ]; then
		printf 'ERROR: no package artifacts found under %s\n' "$DIST_DIR" >&2
		exit 1
	fi
	case "$PACKAGE_SMOKE_MODE" in
	docker)
		require_docker
		run_ubuntu_deb "$deb"
		run_rpm "$rpm"
		run_tarball "$archive"
		;;
	host)
		run_host_deb "$deb"
		run_host_rpm_extract "$rpm"
		run_host_tarball "$archive"
		;;
	*)
		printf 'ERROR: unsupported PACKAGE_SMOKE_MODE=%s (use docker or host)\n' "$PACKAGE_SMOKE_MODE" >&2
		exit 1
		;;
	esac
	log "Package smoke matrix complete"
	find "$REPORT_DIR" -maxdepth 1 -type f -print | sort
}

main "$@"
