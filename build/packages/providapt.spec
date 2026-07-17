# ProvidAPT RPM Spec
# Build: rpmbuild -ba build/packages/providapt.spec
%global _prefix /usr/local

Name:           providapt
Version:        %{version}%{!?version:1.2.1}
Release:        1%{?dist}
Summary:        Provenance-driven APT Detection Platform

License:        Apache-2.0
URL:            https://github.com/Chaoqun-Guo/ProvidAPT
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.22
BuildRequires:  clang, llvm, libbpf-devel
Requires:       systemd >= 245
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
ProvidAPT is an eBPF-based provenance monitor that constructs real-time
attack graphs for advanced persistent threat detection. It captures
system call events, builds process lineage, and performs automated
incident response.

%prep
%setup -q

%build
make build-core VERSION=%{version}

%install
# Binaries
install -d %{buildroot}%{_sbindir}
install -d %{buildroot}%{_bindir}
install -m 0755 build/bin/providaptd        %{buildroot}%{_sbindir}/providaptd
install -m 0755 build/bin/providapt-watchdog %{buildroot}%{_sbindir}/providapt-watchdog
install -m 0755 build/bin/providaptctl      %{buildroot}%{_bindir}/providaptctl
install -m 0755 build/bin/providapt-verify  %{buildroot}%{_bindir}/providapt-verify
install -m 0755 build/bin/providapt-heal    %{buildroot}%{_bindir}/providapt-heal
install -m 0755 build/bin/providapt-deanon  %{buildroot}%{_bindir}/providapt-deanon

# eBPF objects
install -d %{buildroot}%{_libdir}/providapt/ebpf
install -m 0644 build/ebpf/*.bpf.o %{buildroot}%{_libdir}/providapt/ebpf/

# Config
install -d %{buildroot}/etc/providapt
install -m 0644 build/providapt.toml %{buildroot}/etc/providapt/providapt.toml
install -d %{buildroot}/etc/default
install -m 0644 build/providapt.env %{buildroot}/etc/default/providapt

# Systemd
install -d %{buildroot}%{_unitdir}
install -m 0644 deploy/linux/providapt.service %{buildroot}%{_unitdir}/providapt.service

%post
%systemd_post providapt.service
# Ensure data directory permissions
if [ -d /var/log/providapt ]; then
    chown providapt:providapt /var/log/providapt 2>/dev/null || true
fi
mkdir -p /var/lib/providapt /var/log/providapt /run/providapt
chown providapt:providapt /var/lib/providapt /var/log/providapt /run/providapt 2>/dev/null || true
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable providapt.service >/dev/null 2>&1 || true
    systemctl start providapt.service >/dev/null 2>&1 || true
fi

%pre
# Create providapt system user
getent passwd providapt >/dev/null 2>&1 || \
    useradd --system --no-create-home --uid 950 \
        --shell /usr/sbin/nologin \
        --comment "ProvidAPT daemon user" providapt 2>/dev/null || true

%preun
%systemd_preun providapt.service

%postun
%systemd_postun_with_restart providapt.service

%files
%license LICENSE
%doc README.md
%{_sbindir}/providaptd
%{_sbindir}/providapt-watchdog
%{_bindir}/providaptctl
%{_bindir}/providapt-verify
%{_bindir}/providapt-heal
%{_bindir}/providapt-deanon
%{_libdir}/providapt/ebpf/*.bpf.o
%config(noreplace) /etc/providapt/providapt.toml
%config(noreplace) /etc/default/providapt
%{_unitdir}/providapt.service

%changelog
* Tue Jun 03 2026 ProvidAPT Team <dev@providapt.io> - 1.0.2-1
- Initial RPM release
