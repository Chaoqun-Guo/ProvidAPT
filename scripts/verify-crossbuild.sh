# ─── ProvidAPT cross-platform build verification ─────────────────
# Usage: bash scripts/verify-crossbuild.sh
# Verifies that all non-Linux-specific packages compile on
# Windows, macOS, and Linux targets.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass=0
fail=0

check() {
    local os=$1 arch=$2 pkg=$3
    if GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build ./$pkg/... 2>/dev/null; then
        echo -e "${GREEN}✓${NC} $os/$arch  $pkg"
        pass=$((pass + 1))
    else
        echo -e "${RED}✗${NC} $os/$arch  $pkg"
        fail=$((fail + 1))
    fi
}

echo "═ ProvidAPT Cross-Platform Build Verification ═"
echo ""

# Packages that should compile everywhere (no eBPF dependency)
COMMON_PKGS=(
    "pkg/config"
    "pkg/clioutput"
    "pkg/audit"
    "pkg/verify"
    "pkg/replay"
    "pkg/archive"
    "pkg/genrules"
    "pkg/notify"
    "pkg/plugin"
    "pkg/plugin/sigma"
    "pkg/plugin/scoring"
    "pkg/plugin/threatintel"
    "cmd/cli/providaptctl"
)

# CLI only — should build on all platforms
echo "── Common packages (all platforms) ──"
for pkg in "${COMMON_PKGS[@]}"; do
    check linux   amd64 "$pkg"
    check linux   arm64 "$pkg"
    check windows amd64 "$pkg"
    check darwin  amd64 "$pkg"
done

# Linux-only packages (eBPF dependent)
echo ""
echo "── Linux-only packages ──"
LINUX_PKGS=(
    "internal/engine/loader"
    "internal/engine/profile"
    "internal/engine/collector"
)
for pkg in "${LINUX_PKGS[@]}"; do
    check linux amd64 "$pkg"
    check linux arm64 "$pkg"
done

echo ""
echo "─────────────"
echo -e "${GREEN}Passed: $pass${NC}"
echo -e "${RED}Failed: $fail${NC}"
echo "─────────────"

if [ "$fail" -gt 0 ]; then
    exit 1
fi
