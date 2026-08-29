#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SSH_HOST="${SSH_HOST:-${1:-}}"
REMOTE_DIR="${REMOTE_DIR:-}"
OUT_DIR="${OUT_DIR:-$PROJECT_DIR/build/ebpf}"
CLANG="${CLANG:-clang}"
BPFTOOL="${BPFTOOL:-bpftool}"
MAKE="${MAKE:-make}"
KEEP_REMOTE="${KEEP_REMOTE:-0}"

die() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}

log() {
	printf '\n==> %s\n' "$*"
}

[ -n "$SSH_HOST" ] || die "set SSH_HOST, for example SSH_HOST=ubuntu@vm-ubuntu-master"
command -v ssh >/dev/null 2>&1 || die "ssh is not installed"
command -v tar >/dev/null 2>&1 || die "tar is not installed"

cd "$PROJECT_DIR"
if [ -z "$REMOTE_DIR" ]; then
	REMOTE_DIR="$(ssh "$SSH_HOST" 'mktemp -d /tmp/providapt-ebpf-build.XXXXXX')"
fi

cleanup() {
	if [ "$KEEP_REMOTE" != "1" ] && [ "$KEEP_REMOTE" != "true" ]; then
		ssh "$SSH_HOST" "rm -rf '$REMOTE_DIR'" >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

log "Copying source to $SSH_HOST:$REMOTE_DIR"
git ls-files -z \
	| tar --null -T - -czf - \
	| ssh "$SSH_HOST" "tar -xzf - -C '$REMOTE_DIR'"

log "Building eBPF objects on remote Linux host"
ssh "$SSH_HOST" "cd '$REMOTE_DIR' && CLANG='$CLANG' BPFTOOL='$BPFTOOL' $MAKE build-ebpf"

log "Copying eBPF objects back to $OUT_DIR"
mkdir -p "$OUT_DIR"
ssh "$SSH_HOST" "cd '$REMOTE_DIR' && tar -czf - build/ebpf" \
	| tar -xzf - -C "$PROJECT_DIR"

count="$(find "$OUT_DIR" -maxdepth 1 -name '*.bpf.o' -type f | wc -l | tr -d ' ')"
[ "$count" -gt 0 ] || die "remote build completed but no .bpf.o files were copied"

log "Remote eBPF build complete"
find "$OUT_DIR" -maxdepth 1 -name '*.bpf.o' -type f -print | sort
