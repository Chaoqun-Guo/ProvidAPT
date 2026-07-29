#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "install_deps.sh must run as root. Use: sudo make install-deps" >&2
  exit 2
fi

install_debian() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends \
    bash ca-certificates curl git make jq pkg-config \
    build-essential gcc clang llvm llvm-dev libelf-dev libbpf-dev \
    linux-tools-common linux-tools-generic bpftool \
    python3 python3-venv python3-pip \
    rpm fakeroot tar gzip xz-utils \
    iproute2 iputils-ping net-tools procps
}

install_rhel() {
  local pkg_manager="dnf"
  if ! command -v dnf >/dev/null 2>&1; then
    pkg_manager="yum"
  fi
  "${pkg_manager}" install -y \
    bash ca-certificates curl git make jq pkgconf-pkg-config \
    gcc clang llvm elfutils-libelf-devel libbpf-devel \
    bpftool python3 python3-pip rpm-build tar gzip xz \
    iproute iputils net-tools procps-ng
}

case "$(source /etc/os-release && echo "${ID_LIKE:-} ${ID:-}")" in
  *debian*|*ubuntu*)
    install_debian
    ;;
  *rhel*|*fedora*|*centos*|*rocky*|*almalinux*)
    install_rhel
    ;;
  *)
    echo "Unsupported Linux distribution. Install Go, clang, llvm, libbpf, bpftool, make, jq, and Python 3 manually." >&2
    exit 2
    ;;
esac

if ! command -v go >/dev/null 2>&1; then
  cat >&2 <<'EOF'
Go is not installed by this script because required versions can differ by host.
Install Go 1.25+ from your approved package mirror or from the official Go distribution.
EOF
fi

echo "Dependency installation finished."
