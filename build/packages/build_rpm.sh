#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

RAW_VERSION="${1:-$(cd "$PROJECT_DIR" && git describe --tags --always 2>/dev/null || echo "dev")}"
RAW_VERSION="${RAW_VERSION#v}"
PACKAGE_VERSION="$RAW_VERSION"
PACKAGE_RELEASE="1"
if [[ "$RAW_VERSION" == *-* ]]; then
	PACKAGE_VERSION="${RAW_VERSION%%-*}"
	PACKAGE_RELEASE="${RAW_VERSION#*-}"
	PACKAGE_RELEASE="${PACKAGE_RELEASE//-/.}"
fi

ARCH="${2:-$(uname -m)}"
case "$ARCH" in
	x86_64 | amd64) ARCH="x86_64" ;;
	aarch64 | arm64) ARCH="aarch64" ;;
	*)
		echo "Unsupported architecture: $ARCH" >&2
		exit 1
		;;
esac

echo "Building .rpm package: providapt-${PACKAGE_VERSION}-${PACKAGE_RELEASE}.${ARCH}"

for bin in providaptd providaptctl providapt-watchdog providapt-verify providapt-heal providapt-deanon providapt-sign; do
	if [ ! -x "$PROJECT_DIR/build/bin/$bin" ]; then
		echo "Missing built binary: build/bin/$bin" >&2
		exit 1
	fi
done

RPM_BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$RPM_BUILD_DIR"' EXIT
mkdir -p "$RPM_BUILD_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

cat > "$RPM_BUILD_DIR/SPECS/providapt.spec" <<'SPEC'
%global _prefix /usr/local
%global _unitdir /etc/systemd/system

Name:           providapt
Version:        %{version}
Release:        %{release}%{?dist}
Summary:        Provenance-driven APT Detection Platform

License:        Apache-2.0
URL:            https://github.com/Chaoqun-Guo/ProvidAPT
BuildArch:      %{_target_cpu}
Requires:       systemd

%description
ProvidAPT is an eBPF-based provenance monitor that constructs real-time
attack graphs for advanced persistent threat detection.

%prep

%build

%install
install -d %{buildroot}%{_sbindir}
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_libdir}/providapt/ebpf
install -d %{buildroot}/etc/providapt
install -d %{buildroot}/etc/default
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_datadir}/doc/providapt
install -d %{buildroot}%{_datadir}/licenses/providapt

install -m 0755 %{project_dir}/build/bin/providaptd %{buildroot}%{_sbindir}/providaptd
install -m 0755 %{project_dir}/build/bin/providapt-watchdog %{buildroot}%{_sbindir}/providapt-watchdog
install -m 0755 %{project_dir}/build/bin/providaptctl %{buildroot}%{_bindir}/providaptctl
install -m 0755 %{project_dir}/build/bin/providapt-verify %{buildroot}%{_bindir}/providapt-verify
install -m 0755 %{project_dir}/build/bin/providapt-heal %{buildroot}%{_bindir}/providapt-heal
install -m 0755 %{project_dir}/build/bin/providapt-deanon %{buildroot}%{_bindir}/providapt-deanon
install -m 0755 %{project_dir}/build/bin/providapt-sign %{buildroot}%{_bindir}/providapt-sign
install -m 0644 %{project_dir}/build/ebpf/*.bpf.o %{buildroot}%{_libdir}/providapt/ebpf/ 2>/dev/null || true
install -m 0644 %{project_dir}/build/providapt.toml %{buildroot}/etc/providapt/providapt.toml
install -m 0644 %{project_dir}/build/providapt.env %{buildroot}/etc/default/providapt
install -m 0644 %{project_dir}/deploy/linux/providapt.service %{buildroot}%{_unitdir}/providapt.service
install -m 0644 %{project_dir}/README.md %{buildroot}%{_datadir}/doc/providapt/README.md
install -m 0644 %{project_dir}/LICENSE %{buildroot}%{_datadir}/licenses/providapt/LICENSE

%pre
getent passwd providapt >/dev/null 2>&1 || \
    useradd --system --no-create-home --uid 950 \
        --shell /usr/sbin/nologin \
        --comment "ProvidAPT daemon user" providapt 2>/dev/null || true

%post
mkdir -p /var/lib/providapt /var/log/providapt /run/providapt
chown providapt:providapt /var/lib/providapt /var/log/providapt /run/providapt 2>/dev/null || true
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable providapt.service >/dev/null 2>&1 || true
    systemctl start providapt.service >/dev/null 2>&1 || true
fi

%preun
if [ "$1" = "0" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop providapt.service >/dev/null 2>&1 || true
    systemctl disable providapt.service >/dev/null 2>&1 || true
fi

%postun
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

%files
%doc %{_datadir}/doc/providapt/README.md
%license %{_datadir}/licenses/providapt/LICENSE
%{_sbindir}/providaptd
%{_sbindir}/providapt-watchdog
%{_bindir}/providaptctl
%{_bindir}/providapt-verify
%{_bindir}/providapt-heal
%{_bindir}/providapt-deanon
%{_bindir}/providapt-sign
%{_libdir}/providapt/ebpf
%config(noreplace) /etc/providapt/providapt.toml
%config(noreplace) /etc/default/providapt
%{_unitdir}/providapt.service

%changelog
* Thu Jul 16 2026 ProvidAPT Team <dev@providapt.io> - %{version}-%{release}
- Binary commercial release package
SPEC

mkdir -p "$PROJECT_DIR/build/dist"
rpmbuild --define "_topdir $RPM_BUILD_DIR" \
	--define "version $PACKAGE_VERSION" \
	--define "release $PACKAGE_RELEASE" \
	--define "project_dir $PROJECT_DIR" \
	--define "__os_install_post %{nil}" \
	--target "$ARCH" \
	-bb "$RPM_BUILD_DIR/SPECS/providapt.spec"

find "$RPM_BUILD_DIR/RPMS" -name "*.rpm" -exec cp {} "$PROJECT_DIR/build/dist/" \;
echo "Package created: build/dist/providapt-${PACKAGE_VERSION}-${PACKAGE_RELEASE}.${ARCH}.rpm"
