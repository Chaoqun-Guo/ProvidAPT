# ProvidAPT Installation Guide

**Version 1.0** | Linux System Provenance Monitor

ProvidAPT is an eBPF-based Linux system provenance monitoring tool designed for APT attack detection and forensic analysis. This guide covers installation from source, system integration, and verification procedures.

---

## Table of Contents

- [1. Environment Requirements](#1-environment-requirements)
- [2. Dependency Installation](#2-dependency-installation)
- [3. Compilation Guide](#3-compilation-guide)
- [4. System Integration](#4-system-integration)
- [5. Quick Verification](#5-quick-verification)
- [6. Performance Tuning](#6-performance-tuning)
- [7. Troubleshooting](#7-troubleshooting)

---

## 1. Environment Requirements

### 1.1 Supported Linux Distributions

| Distribution | Minimum Version | Architecture |
|-------------|----------------|--------------|
| Ubuntu LTS | 20.04+ | x86_64, aarch64 |
| Debian | 11+ | x86_64, aarch64 |
| RHEL / Rocky Linux / AlmaLinux | 9+ | x86_64, aarch64 |
| Fedora | 37+ | x86_64, aarch64 |
| CentOS Stream | 9+ | x86_64 |
| Amazon Linux | 2023+ | x86_64, aarch64 |
| Alpine Linux | 3.18+ | x86_64 |

### 1.2 Kernel Requirements

**Minimum kernel version: 5.8** (for BPF Ring Buffer support)

Recommended: **5.11+** (for BPF LSM and sleepable BPF programs)

### 1.3 Required Kernel Configuration

The following kernel options must be enabled (check with `build/kernel_probe.sh`):

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_LSM=y              # Required for LSM hooks
CONFIG_DEBUG_INFO_BTF=y       # Required for CO-RE
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
CONFIG_TRACING=y
CONFIG_FTRACE=y
CONFIG_FUNCTION_TRACER=y
CONFIG_BPF_EVENTS=y
CONFIG_BPF_KPROBE_OVERRIDE=y
CONFIG_CGROUPS=y
```

### 1.4 Quick Kernel Check

```bash
# Check kernel version
uname -r
# Expected: 5.11.0 or later

# Check BTF availability
ls -la /sys/kernel/btf/vmlinux
# Should exist and be non-empty

# Check BPF LSM config
zgrep CONFIG_BPF_LSM /proc/config.gz 2>/dev/null || \
  grep CONFIG_BPF_LSM /boot/config-$(uname -r)
# Should output: CONFIG_BPF_LSM=y
```

---

## 2. Dependency Installation

### 2.1 Required Packages

| Package | Purpose | Minimum Version |
|---------|---------|-----------------|
| clang, llvm, lld | eBPF bytecode compilation | 14.0+ |
| bpftool | BPF program management | 7.0+ |
| libbpf-dev / libbpf-devel | BPF userspace library | 1.0+ |
| Go | Userspace agent compilation | 1.22+ |
| make | Build system | 4.0+ |
| kernel-headers | Kernel header files | matching kernel |
| git | Source code management | 2.0+ |
| jq | JSON processing (scripts) | 1.6+ |

### 2.2 Platform-Specific Installation

#### Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install -y \
    clang llvm lld bpftool \
    libbpf-dev \
    linux-headers-$(uname -r) \
    pkg-config \
    curl git make jq \
    python3 python3-pip
```

#### RHEL / Rocky Linux / AlmaLinux 9

```bash
sudo dnf install -y \
    clang llvm lld bpftool \
    libbpf-devel \
    kernel-devel kernel-headers \
    pkgconfig \
    curl git make jq \
    python3 python3-pip
```

#### Fedora

```bash
sudo dnf install -y \
    clang llvm lld bpftool \
    libbpf-devel \
    kernel-devel \
    pkgconfig \
    curl git make jq \
    python3 python3-pip
```

#### Alpine Linux

```bash
sudo apk add \
    clang llvm lld bpftool \
    libbpf-dev \
    linux-headers \
    pkgconfig \
    curl git make jq \
    python3 py3-pip
```

#### Go Installation

If Go 1.25+ is not available via your package manager:

```bash
# Download and install Go
wget https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.25.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify
go version  # Should show go1.25.0 or later
```

### 2.3 Automated Dependency Installation

```bash
# Run the automated dependency installer
sudo bash build/install_deps.sh
```

---

## 3. Compilation Guide

### 3.1 Clone the Repository

```bash
git clone https://github.com/Chaoqun-Guo/ProvidAPT.git
cd ProvidAPT
```

### 3.2 Verify System Readiness

```bash
# Run the kernel probe to determine optimal eBPF mode
bash build/kernel_probe.sh

# Expected output:
#   Kernel:     6.8.0
#   BTF:        true
#   BPF_LSM:    true
#   Mode:       fentry

# Full system verification
bash build/verify.sh
```

### 3.3 Compile eBPF Bytecode

```bash
# Compile all eBPF programs
make ebpf

# Output files in build/ebpf/:
#   lsm_hooks.bpf.o     - Core LSM hooks
#   defense.bpf.o       - Self-defence mechanisms
#   memory.bpf.o        - Memory attack detection
#   network.bpf.o       - Enhanced network events
```

Loader behavior:

- ProvidAPT first attempts to attach the core hooks through **BPF LSM**.
- If LSM attachment fails but the core object loads successfully, the daemon falls back to **kprobe** attachment for supported hooks.
- The loader searches for `lsm_hooks.bpf.o` in:
  - `build/ebpf/lsm_hooks.bpf.o`
  - `/usr/local/lib/providapt/ebpf/lsm_hooks.bpf.o`
- To use a non-standard location, set `PROVIDAPT_BPF_OBJECT_PATH`:

```bash
export PROVIDAPT_BPF_OBJECT_PATH=/opt/providapt/ebpf/lsm_hooks.bpf.o
sudo -E providaptd -config /etc/providapt/providapt.toml
```

### 3.4 Compile Userspace Agent

```bash
# Build all Go binaries
make userspace

# Output binaries in build/bin/:
#   providaptd           - Main daemon
#   providaptctl         - Control CLI
#   providapt-watchdog   - Watchdog process
#   providapt-verify     - Data integrity verifier
#   providapt-deanon     - De-anonymization tool
#   providapt-heal       - Self-healing tool
```

### 3.5 Full Build

```bash
# Build everything (eBPF + userspace)
make build
```

### 3.6 Cross-Compilation

For building on a different architecture:

```bash
# Build eBPF for multiple architectures
bash build/build_ebpf.sh

# Cross-compile Go binaries
GOARCH=arm64 make userspace
GOARCH=amd64 make userspace
```

---

## 4. System Integration

### 4.1 Installation to System Directories

```bash
# Install binaries and eBPF objects
sudo make install

# This installs:
#   /usr/local/sbin/providaptd
#   /usr/local/bin/providaptctl
#   /usr/local/sbin/providapt-watchdog
#   /usr/local/lib/providapt/ebpf/*.bpf.o
#   /etc/providapt/providapt.toml
```

### 4.2 Resource Limit Configuration

ProvidAPT includes cgroup v2 resource limits to prevent the agent from impacting other system processes:

```bash
# Configure CPU (10%) and memory (512 MB) limits
sudo bash build/setup_cgroup.sh
```

Verify limits:

```bash
cat /sys/fs/cgroup/providapt/cpu.max
# 100000 1000000
cat /sys/fs/cgroup/providapt/memory.max
# 536870912
```

### 4.3 SystemD Service Unit

ProvidAPT ships with a pre-configured systemd unit file:

```bash
# Install the systemd service
sudo cp build/providapt-cgroup.service /etc/systemd/system/providapt.service
sudo systemctl daemon-reload

# Enable and start
sudo systemctl enable providapt.service
sudo systemctl start providapt.service
```

The service unit (`build/providapt-cgroup.service`) includes:

```ini
[Service]
ExecStart=/usr/local/sbin/providaptd
CPUQuota=10%
MemoryMax=512M
MemoryHigh=480M
MemorySwapMax=0
ProtectSystem=strict
NoNewPrivileges=true
CapabilityBoundingSet=CAP_BPF CAP_SYS_ADMIN CAP_NET_ADMIN
```

### 4.4 Manual Start / Stop

```bash
# Start the daemon
sudo providaptd

# Start with watchdog (auto-restart on crash)
sudo providapt-watchdog &

# Stop the daemon
sudo providaptctl -stop
# or
sudo pkill providaptd

# Restart
sudo systemctl restart providapt
```

### 4.5 Logging and Output

ProvidAPT outputs data to the following locations:

| Path | Contents |
|------|----------|
| `/var/log/providapt/` | Event logs (NDJSON) and provenance graph |
| `/var/log/providapt/provenance.json` | Serialised provenance graph (PROV-JSON) |
| `/var/log/providapt/alerts.json` | Analyzer alerts |
| `/var/lib/providapt/store/` | RocksDB persistent storage |
| `/etc/providapt/providapt.toml` | Configuration file |

### 4.6 Configuration File

Default configuration (`/etc/providapt/providapt.toml`):

```json
{
  "kernel": {
    "verbose": false,
    "hooks": [
      "task_alloc", "task_free",
      "file_open",
      "bprm_check_security",
      "socket_connect"
    ]
  },
  "output": {
    "dir": "/var/log/providapt",
    "format": "json"
  },
  "capture": {
    "enable_net": true,
    "enable_file": true,
    "enable_proc": true
  },
  "api": {
    "grpc": ":50051",
    "rest": ":8080"
  }
}
```

### 4.7 Uninstallation

```bash
# Stop and disable the service
sudo systemctl stop providapt
sudo systemctl disable providapt

# Remove binaries and data
sudo make uninstall

# Remove cgroup limits
sudo bash build/setup_cgroup.sh --remove

# Optionally remove data
sudo rm -rf /var/log/providapt /var/lib/providapt
```

---

## 5. Quick Verification

### 5.1 Daemon Status Check

```bash
# Check if the daemon is running
pidof providaptd
# Should output a PID number

# Check process details
ps aux | grep providaptd

# Check resource usage
cat /proc/$(pidof providaptd)/status | grep -E "Name|VmRSS|Threads"
```

### 5.2 eBPF Program Verification

```bash
# List loaded eBPF programs
sudo bpftool prog show | grep -E "lsm|providapt"

# Expected output:
# 123: lsm  name probe_file_open  ...
# 124: lsm  name probe_bprm_check ...
# 125: lsm  name probe_task_alloc ...
```

### 5.3 Data Capture Verification

```bash
# Generate some system activity
ls /tmp/ > /dev/null
cat /etc/hostname > /dev/null

# Check event logs
ls -la /var/log/providapt/
cat /var/log/providapt/providapt-*.ndjson | head -5
```

### 5.4 Quick Health Check

```bash
# Hit the API status endpoint
curl -s http://localhost:8080/api/v1/status

# Expected response:
# {"status":"running","nodes":42,"edges":156,"timestamp":"2026-05-28T12:00:00Z"}
```

### 5.5 Verify Provenance Graph

```bash
# Check the provenance graph
cat /var/log/providapt/provenance.json | python3 -c "
import json,sys
d = json.load(sys.stdin)
print(f'Activities: {len(d.get(\"activity\",{}))}')
print(f'Entities:   {len(d.get(\"entity\",{}))}')
print(f'Edges:      {len(d.get(\"used\",[])) + len(d.get(\"wasGeneratedBy\",[])) + len(d.get(\"wasInformedBy\",[]))}')
"
```

### 5.6 Attack Simulation Test

```bash
# Run the built-in attack simulation
make attack-sim

# Verify capture
make verify-capture
```

---

## 6. Performance Tuning

### 6.1 Adaptive Monitoring Levels

ProvidAPT automatically adjusts monitoring intensity based on threat level:

| Level | Description | Impact |
|-------|-------------|--------|
| 1 (Default) | Core events only | ~1% CPU |
| 2 (Suspicious) | File details + env | ~3% CPU |
| 3 (Investigating) | Full syscall trace | ~10% CPU |

### 6.2 Storage Sizing

| Event Rate | Daily Storage | Monthly Storage |
|-----------|--------------|----------------|
| 10,000/sec | ~280 GB | ~8.4 TB |
| 50,000/sec | ~1.4 TB | ~42 TB |
| 100,000/sec | ~2.8 TB | ~84 TB |

Storage optimisation features:

- **RocksDB WriteBatch**: 200 ops per commit (reduces IOPS by 200x)
- **Sliding-window merge**: 5-second dedup window (reduces edges ~40%)
- **Causality-preserving reduction**: Merges intermediate nodes
- **Cold data tiering**: RocksDB -> Parquet -> S3 lifecycle

### 6.3 Benchmarking

```bash
# Run performance benchmarks
go test -bench=. -benchtime=30s ./test/benchmark/

# Run stress test (10K concurrent forks)
go run test/kernel-test/stress_test.go
```

---

## 7. Troubleshooting

### 7.1 BTF Not Available

**Symptom:** `/sys/kernel/btf/vmlinux` does not exist.

**Solution:**

```bash
# Check kernel version (need 5.10+)
uname -r

# Install BTF manually (if kernel >= 5.10 but BTF missing)
sudo apt-get install -y dwarves
sudo pahole -J /lib/modules/$(uname -r)/vmlinux 2>/dev/null || true

# Or use BTFHub for older kernels:
bash kernel/btf/download_btf.sh ubuntu 20.04
```

### 7.2 BPF LSM Not Available

**Symptom:** `CONFIG_BPF_LSM is not set` in kernel config.

**Solution:**

```bash
# Check current LSM configuration
cat /sys/kernel/security/lsm

# If 'bpf' is missing, add it to kernel cmdline:
# Edit /etc/default/grub:
# GRUB_CMDLINE_LINUX="lsm=bpf,landlock,lockdown,yama,integrity,apparmor"
sudo update-grub
sudo reboot
```

**Fallback behavior:** ProvidAPT will attempt to continue in `kprobe` fallback mode when the eBPF object loads successfully but LSM attachment is unavailable. This preserves partial visibility, but LSM-only coverage will be reduced.

### 7.3 Permission Denied (CAP_BPF)

**Symptom:** `operation not permitted` when loading eBPF programs.

**Solution:**

```bash
# Ensure the agent runs as root
sudo providaptd

# Or grant necessary capabilities
sudo setcap cap_bpf,cap_sys_admin,cap_net_admin=ep /usr/local/sbin/providaptd
```

### 7.4 eBPF Object File Not Found

**Symptom:** startup fails with a `no precompiled eBPF object found` error.

**Solution:**

```bash
# Build the object locally
make build-ebpf

# Or point the loader at an existing object
export PROVIDAPT_BPF_OBJECT_PATH=/path/to/lsm_hooks.bpf.o
sudo -E providaptd -config /etc/providapt/providapt.toml
```

### 7.5 kptr_restrict Prevents Kallsyms Access

**Symptom:** `/proc/kallsyms` shows `0000000000000000` for all addresses.

**Solution:**

```bash
# Temporarily allow kernel pointer access
echo 0 | sudo tee /proc/sys/kernel/kptr_restrict

# Make permanent:
echo "kernel.kptr_restrict = 0" | sudo tee /etc/sysctl.d/99-provident.conf
sudo sysctl -p /etc/sysctl.d/99-provident.conf
```

### 7.6 Ring Buffer Overrun

**Symptom:** Event loss at high throughput.

**Solution:**

```bash
# Increase ring buffer size (default: 4 MB)
# Edit the eBPF program or increase userspace drain rate

# Monitor drop rate
bpftool map show | grep ringbuf
bpftool map dump name rb | head -10
```

### 7.6 Memory Pressure

**Symptom:** Agent OOM-killed or slow performance.

**Solution:**

```bash
# Verify cgroup limits are active
cat /sys/fs/cgroup/providapt/memory.current

# Check agent memory usage
ps -o pid,rss,%mem,cmd -p $(pidof providaptd)

# Increase memory limit if needed
echo "1073741824" | sudo tee /sys/fs/cgroup/providapt/memory.max
```

### 7.7 File Descriptor Exhaustion

**Symptom:** `too many open files` errors.

**Solution:**

```bash
# Check current limits
cat /proc/$(pidof providaptd)/limits | grep "open files"

# Increase limit
echo "1048576" | sudo tee /proc/$(pidof providaptd)/limits
```

### 7.8 Compilation Errors

**Symptom:** `clang: error: unknown argument: '-target bpf'`

**Solution:**

```bash
# Check clang version
clang --version
# Must be 14.0+ for BPF support

# Install newer clang:
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 18
```

### 7.9 Go Dependency Issues

**Symptom:** `missing go.sum entry for module` during build.

**Solution:**

```bash
# Download all dependencies
go mod tidy
go mod download

# If network is restricted, use vendoring
go mod vendor
make userspace GOFLAGS=-mod=vendor
```

### 7.10 Diagnostic Commands

```bash
# Collect all diagnostic info for troubleshooting
echo "=== Kernel ==="
uname -a
echo "=== BTF ==="
ls -la /sys/kernel/btf/vmlinux
echo "=== LSM ==="
cat /sys/kernel/security/lsm
echo "=== BPF Programs ==="
bpftool prog show | head -20
echo "=== Agent Status ==="
pidof providaptd && ps aux | grep providaptd | grep -v grep
echo "=== Logs ==="
tail -50 /var/log/providapt/daemon.log 2>/dev/null || echo "No daemon log"
echo "=== Memory ==="
cat /proc/$(pidof providaptd 2>/dev/null)/status 2>/dev/null | grep VmRSS || echo "Agent not running"
```

#### Support Bundle Controls

ProvidAPT also exposes support bundle operations from the control plane:

- `POST /api/v1/control/support` exports a fresh support bundle
- `GET /api/v1/control/support` returns latest bundle/archive metadata
- `GET /api/v1/control/support/download` downloads the latest redacted zip archive
- `GET /api/v1/control/audit-category=admin&source=supportbundle&limit=20` queries persisted support bundle audit records

Useful environment variables:

```bash
# Keep only the newest 8 support bundle directories/archives
export PROVIDAPT_SUPPORT_RETAIN_ARCHIVES=8

# Disable redaction only for trusted internal debugging
export PROVIDAPT_SUPPORT_REDACT_ARCHIVES=false
```

Default behavior:

- archives redact common secrets, emails, IPs, and bearer tokens using stable pseudonyms
- only the most recent 5 bundle directories/zip archives are retained
- archive downloads still pass through existing control-plane auth/RBAC checks

#### License and Upgrade Controls

Operator-facing control-plane endpoints now include:

- `GET /api/v1/control/license`
- `POST /api/v1/control/license`
- `GET /api/v1/control/upgrade`
- `POST /api/v1/control/upgrade`

Recommended environment variables for commercial deployments:

```bash
export PROVIDAPT_LICENSE_PUBLIC_KEY_PATH=/etc/providapt/license.pub
export PROVIDAPT_LICENSE_REVOCATION_URL=https://licenses.example.com/revocations.json
export PROVIDAPT_LICENSE_REVOCATION_CACHE=/var/lib/providapt/revocations.json
export PROVIDAPT_LICENSE_REVOCATION_SIG_URL=https://licenses.example.com/revocations.json.sig
export PROVIDAPT_LICENSE_REVOCATION_SIG_CACHE=/var/lib/providapt/revocations.json.sig
export PROVIDAPT_LICENSE_GRACE_PERIOD_DAYS=14

export PROVIDAPT_UPGRADE_DOWNLOAD_URL=https://downloads.example.com/providapt.tar.gz
export PROVIDAPT_UPGRADE_PACKAGE_PATH=/var/lib/providapt/releases/providapt.tar.gz
export PROVIDAPT_UPGRADE_EXPECTED_SHA256=<64-char-hex>
export PROVIDAPT_UPGRADE_SIGNATURE_PATH=/var/lib/providapt/releases/providapt.tar.gz.sig
export PROVIDAPT_UPGRADE_PUBLIC_KEY_PATH=/etc/providapt/upgrade.pub
export PROVIDAPT_UPGRADE_ROLLBACK_PLAN="snapshot VM before rollout"
```

Recommended operator flow:

1. Validate license status from the control plane
2. Confirm `revocation_verified=true` when remote revocation is enabled
3. Trigger upgrade `download`
4. Trigger upgrade `preflight`
5. Approve rollout only when `preflight_ready=true`

---

## Appendix A: Directory Structure

```
ProvidAPT/
├── cmd/                         # Go binaries
│   ├── agent/                   # Daemon and watchdog
│   ├── cli/                     # CLI tools
│   ├── collector/               # Distributed collector
│   └── bpf/                     # eBPF C programs
├── internal/                    # Core libraries
│   ├── engine/                  # Provenance engine
│   ├── storage/                 # Storage layer
│   ├── stitcher/                # Cross-host stitching
│   └── policy/                  # Policy engine
├── pkg/                         # Public libraries
└── test/                        # Test suites
```

## Appendix B: Quick Start (TL;DR)

```bash
# 1. Requirements
# Linux kernel 5.11+, root access

# 2. Install dependencies
git clone https://github.com/Chaoqun-Guo/ProvidAPT.git
cd ProvidAPT
sudo bash build/install_deps.sh

# 3. Build
make build

# 4. Install
sudo make install

# 5. Configure cgroup limits
sudo bash build/setup_cgroup.sh

# 6. Start
sudo providaptd

# 7. Verify
curl -s http://localhost:8080/api/v1/status
```
