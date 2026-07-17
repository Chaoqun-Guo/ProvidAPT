#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST_DIR="${DIST_DIR:-$PROJECT_DIR/dist}"
REPORT_DIR="${REPORT_DIR:-$PROJECT_DIR/build/package-smoke}"
UBUNTU_IMAGE="${UBUNTU_IMAGE:-ubuntu:22.04}"
RPM_IMAGE="${RPM_IMAGE:-rockylinux:8}"

log() {
	printf '\n==> %s\n' "$*"
}

require_docker() {
	if ! command -v docker >/dev/null 2>&1; then
		printf 'ERROR: docker is required for package smoke matrix\n' >&2
		exit 1
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

main() {
	require_docker
	mkdir -p "$REPORT_DIR"
	local deb rpm archive
	deb="$(find_one '*.deb')"
	rpm="$(find_one '*.rpm')"
	archive="$(find_one '*.tar.gz')"
	if [ -z "$deb" ] && [ -z "$rpm" ] && [ -z "$archive" ]; then
		printf 'ERROR: no package artifacts found under %s\n' "$DIST_DIR" >&2
		exit 1
	fi
	run_ubuntu_deb "$deb"
	run_rpm "$rpm"
	run_tarball "$archive"
	log "Package smoke matrix complete"
	find "$REPORT_DIR" -maxdepth 1 -type f -print | sort
}

main "$@"
