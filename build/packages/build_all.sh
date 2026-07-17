#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERSION="${VERSION:-$(cd "$PROJECT_DIR" && git describe --tags --always 2>/dev/null || echo "dev")}"
FORMAT="${1:-auto}"
GO_TAGS="${GO_TAGS:-bpf}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo "============================================================"
echo " ProvidAPT Distribution Package Builder"
echo "============================================================"
echo "  Version: $VERSION"
echo ""

echo "[1/2] Building ProvidAPT binaries..."
cd "$PROJECT_DIR"
make build-userspace VERSION="$VERSION" GO_TAGS="$GO_TAGS" 2>&1 | sed 's/^/  /'
echo -e "  ${GREEN}OK:${NC} Binaries ready"
echo ""

mkdir -p "$PROJECT_DIR/build/dist"

case "$FORMAT" in
	deb)
		echo "[2/2] Building .deb package..."
		bash "$SCRIPT_DIR/build_deb.sh" "$VERSION"
		;;
	rpm)
		echo "[2/2] Building .rpm package..."
		bash "$SCRIPT_DIR/build_rpm.sh" "$VERSION"
		;;
	tar|tarball)
		echo "[2/2] Building tarball..."
		bash "$SCRIPT_DIR/build_tar.sh" "$VERSION"
		;;
	all)
		echo "[2/2] Building all package formats..."
		bash "$SCRIPT_DIR/build_deb.sh" "$VERSION" 2>&1 | sed 's/^/  [deb] /' || echo -e "  ${YELLOW}deb skipped${NC}"
		bash "$SCRIPT_DIR/build_rpm.sh" "$VERSION" 2>&1 | sed 's/^/  [rpm] /' || echo -e "  ${YELLOW}rpm skipped${NC}"
		bash "$SCRIPT_DIR/build_tar.sh" "$VERSION" 2>&1 | sed 's/^/  [tar] /'
		;;
	auto)
		echo "[2/2] Detecting platform..."
		if command -v dpkg-deb >/dev/null 2>&1; then
			echo "  Platform: Debian/Ubuntu; building .deb"
			bash "$SCRIPT_DIR/build_deb.sh" "$VERSION"
		elif command -v rpmbuild >/dev/null 2>&1; then
			echo "  Platform: RHEL/CentOS; building .rpm"
			bash "$SCRIPT_DIR/build_rpm.sh" "$VERSION"
		else
			echo "  Platform: unknown; building tarball"
			bash "$SCRIPT_DIR/build_tar.sh" "$VERSION"
		fi
		;;
	*)
		echo "Unknown format: $FORMAT (use: deb, rpm, tar, all, auto)" >&2
		exit 1
		;;
esac

echo ""
echo -e "${GREEN}Packaging complete.${NC}"
echo "Packages:"
ls -lh "$PROJECT_DIR/build/dist/" 2>/dev/null | sed 's/^/  /'
