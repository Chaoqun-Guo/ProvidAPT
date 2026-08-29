#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST_DIR="${DIST_DIR:-$PROJECT_DIR/dist}"
HANDOFF_DIR="${HANDOFF_DIR:-$PROJECT_DIR/build/handoff}"
RELEASE_TAG="${RELEASE_TAG:-$(cd "$PROJECT_DIR" && git describe --tags --abbrev=0)}"
VERSION="${VERSION:-$RELEASE_TAG}"
REPO="${GITHUB_REPO:-}"
NOTES_FILE="${NOTES_FILE:-$PROJECT_DIR/docs/project/release-evidence-${RELEASE_TAG}.md}"
TITLE="${TITLE:-ProvidAPT ${RELEASE_TAG}}"
PRERELEASE="${PRERELEASE:-auto}"
DRY_RUN="${DRY_RUN:-0}"

die() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}

log() {
	printf '\n==> %s\n' "$*"
}

command -v gh >/dev/null 2>&1 || die "gh is not installed"

cd "$PROJECT_DIR"
git rev-parse --verify "$RELEASE_TAG^{commit}" >/dev/null 2>&1 || die "release tag not found: $RELEASE_TAG"

TAG_COMMIT="$(git rev-parse "$RELEASE_TAG^{commit}")"
TAG_SHORT="$(git rev-parse --short "$RELEASE_TAG^{commit}")"

if [ -z "$REPO" ]; then
	origin="$(git config --get remote.origin.url || true)"
	case "$origin" in
		git@github.com:*) REPO="${origin#git@github.com:}"; REPO="${REPO%.git}" ;;
		https://github.com/*) REPO="${origin#https://github.com/}"; REPO="${REPO%.git}" ;;
		*) die "cannot infer GitHub repo from remote.origin.url; set GITHUB_REPO=owner/repo" ;;
	esac
fi

case "$PRERELEASE" in
	auto)
		case "$RELEASE_TAG" in
			*-rc*|*-alpha*|*-beta*) PRERELEASE=1 ;;
			*) PRERELEASE=0 ;;
		esac
		;;
	1|true|yes) PRERELEASE=1 ;;
	0|false|no) PRERELEASE=0 ;;
	*) die "PRERELEASE must be auto, 1, or 0" ;;
esac

[ -f "$NOTES_FILE" ] || die "release notes missing: $NOTES_FILE"
[ -f "$DIST_DIR/release-readiness.md" ] || die "release readiness missing: $DIST_DIR/release-readiness.md"

grep -q "$VERSION" "$DIST_DIR/release-readiness.md" || die "release-readiness.md does not mention $VERSION"
if ! grep -q "$TAG_COMMIT" "$DIST_DIR/release-readiness.md" && ! grep -q "$TAG_SHORT" "$DIST_DIR/release-readiness.md"; then
	die "release-readiness.md does not mention tag commit $TAG_COMMIT"
fi

artifacts=(
	"$DIST_DIR/providapt-${VERSION}-linux-amd64.tar.gz"
	"$DIST_DIR/providapt_${VERSION}_amd64.deb"
	"$DIST_DIR/providapt-${VERSION#v}.x86_64.rpm"
	"$DIST_DIR/providapt-helm-${VERSION}.tgz"
	"$DIST_DIR/providapt-monitoring-${VERSION}.tgz"
	"$DIST_DIR/sbom.spdx.json"
	"$DIST_DIR/sbom.cdx.json"
	"$DIST_DIR/checksums.txt"
	"$DIST_DIR/checksums.txt.sig"
	"$DIST_DIR/checksums.txt.pub"
)

handoff="$HANDOFF_DIR/providapt-${VERSION}-handoff.zip"
if [ -f "$handoff" ]; then
	artifacts+=("$handoff")
fi

for artifact in "${artifacts[@]}"; do
	[ -s "$artifact" ] || die "required release artifact missing or empty: $artifact"
done

log "Release target"
printf 'repo: %s\n' "$REPO"
printf 'tag: %s\n' "$RELEASE_TAG"
printf 'tag commit: %s\n' "$TAG_COMMIT"
printf 'notes: %s\n' "$NOTES_FILE"
printf 'artifact count: %s\n' "${#artifacts[@]}"

if [ "$DRY_RUN" = "1" ] || [ "$DRY_RUN" = "true" ]; then
	printf '%s\n' "${artifacts[@]}"
	exit 0
fi

gh auth status >/dev/null || die "gh is not authenticated; run gh auth login -h github.com or set GH_TOKEN"

flags=(--repo "$REPO" --title "$TITLE" --notes-file "$NOTES_FILE")
if [ "$PRERELEASE" = "1" ]; then
	flags+=(--prerelease)
fi

if gh release view "$RELEASE_TAG" --repo "$REPO" >/dev/null 2>&1; then
	log "Release exists; uploading artifacts with --clobber"
	gh release upload "$RELEASE_TAG" "${artifacts[@]}" --repo "$REPO" --clobber
else
	log "Creating GitHub release"
	gh release create "$RELEASE_TAG" "${flags[@]}" "${artifacts[@]}"
fi

log "GitHub release ready"
gh release view "$RELEASE_TAG" --repo "$REPO" --json url,tagName,isPrerelease
