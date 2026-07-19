# Deployment Guide

**Standalone & Kubernetes** | Environment Prerequisites, Installation, Distributed Configuration

---

## 1. Environment Prerequisites

### 1.1 Minimum Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 cores | 8+ cores |
| Memory | 2 GB | 16+ GB |
| Disk | 10 GB | 200+ GB (SSD) |
| Kernel | 5.11+ | 6.2+ |
| eBPF | BTF support | CO-RE capable |

### 1.2 Kernel Verification

```bash
# Check BTF support (required for CO-RE)
ls /sys/kernel/btf/vmlinux

# Check LSM configuration
cat /sys/kernel/security/lsm | grep bpf
# Expected: "lockdown,capability,selinux,bpf" (bpf must be present)

# Check kernel version
uname -r
# Expected: 5.11+

# Check eBPF features
bpftool feature probe
```

### 1.3 LSM Configuration

Add `bpf` to the LSM list in `/etc/default/grub`:

```bash
GRUB_CMDLINE_LINUX="lsm=lockdown,capability,selinux,bpf"
update-grub
reboot
```

### 1.4 System Preparation

```bash
# Install dependencies (Ubuntu/Debian)
apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) build-essential pkg-config

# Install Go 1.25+
wget https://go.dev/dl/go1.25.12.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.25.12.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Install sysbench (for performance testing)
apt install -y sysbench

# Verify
make verify-env
```

---

## 2. Standalone Installation

### 2.1 Build from Source

```bash
git clone https://github.com/Chaoqun-Guo/ProvidAPT
cd ProvidAPT

# Full build (eBPF + userspace)
make build-core

# Install to system
sudo make install-local
```

### 2.2 Post-Install Configuration

```bash
# Configuration file: /etc/providapt/providapt.toml

# Data directory
mkdir -p /var/lib/providapt/store
chmod 0700 /var/lib/providapt

# eBPF programs
ls /usr/local/lib/providapt/ebpf/
# Expected: lsm_hooks.bpf.o defense.bpf.o memory.bpf.o network.bpf.o deception.bpf.o

# Start the daemon
sudo providaptd

# Verify status
sudo providaptctl -status
```

### 2.3 Systemd Service

```ini
# /etc/systemd/system/providapt.service
[Unit]
Description=ProvidAPT Provenance Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/providaptd -config /etc/providapt/providapt.toml
CPUQuota=50%
MemoryMax=2G
ProtectSystem=strict
NoNewPrivileges=true
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

---

## 3. Distributed Configuration

### 3.1 Central Server Setup

```bash
# Install the central server components
make cluster

# Configure collectors in /etc/providapt/collectors.toml
[[collector]]
id = "collector-1"
address = "10.0.0.1:8443"
cert = "/etc/providapt/certs/collector-1.pem"

[[collector]]
id = "collector-2"
address = "10.0.0.2:8443"
cert = "/etc/providapt/certs/collector-2.pem"
```

### 3.2 mTLS Certificate Generation

```bash
# CA key
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt

# Server certificate
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -out server.crt

# Agent certificate
openssl genrsa -out agent.key 4096
openssl req -new -key agent.key -out agent.csr
openssl x509 -req -days 365 -in agent.csr -CA ca.crt -CAkey ca.key -out agent.crt
```

### 3.3 Transport Configuration

```toml
# /etc/providapt/transport.toml
[transport]
compression = "zstd"
zstd_level = 3
enable_hash_cache = true
hash_cache_path = "/var/lib/providapt/hashcache"
low_priority_path = "/var/lib/providapt/lowprio"
flush_interval = "60s"
```

---

## 4. Kubernetes Deployment

### 4.1 DaemonSet Configuration

```yaml
# providapt-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: providapt
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: providapt
  template:
    metadata:
      labels:
        app: providapt
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: agent
        image: providapt/agent:2.2
        securityContext:
          privileged: true
          capabilities:
            add: ["BPF", "NET_ADMIN", "SYS_ADMIN"]
        volumeMounts:
        - name: btf
          mountPath: /sys/kernel/btf
          readOnly: true
        - name: cgroup
          mountPath: /sys/fs/cgroup
        - name: proc
          mountPath: /proc
        - name: store
          mountPath: /var/lib/providapt
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
      volumes:
      - name: btf
        hostPath:
          path: /sys/kernel/btf
      - name: cgroup
        hostPath:
          path: /sys/fs/cgroup
      - name: proc
        hostPath:
          path: /proc
      - name: store
        hostPath:
          path: /var/lib/providapt
```

### 4.2 Helm Chart Values

```yaml
# values.yaml
agent:
  image: providapt/agent:2.2
  resources:
    limits:
      cpu: "2"
      memory: 4Gi
    requests:
      cpu: "500m"
      memory: 512Mi
  config:
    scanInterval: 30s
    deepTaintThreshold: 3
    memoryLimitMB: 4096
    storagePath: /var/lib/providapt/store
centralServer:
  enabled: true
  replicas: 3
  storage: 100Gi
```

---

## 5. Configuration Reference

### 5.1 Agent Configuration

```toml
# /etc/providapt/providapt.toml
[agent]
scan_interval = "30s"
deep_taint_threshold = 3
quiet = false

[pipeline]
max_cache_size = 8192
merge_window = "5s"
max_memory_mb = 4096
store_path = "/var/lib/providapt/store"

[patterns]
enabled = [
  "SENSITIVE_EXFIL",
  "SCRIPT_CHILD",
  "DEEP_TAINT_CHAIN",
  "PRIVILEGE_ESCALATION",
  "MEMORY_ANOMALY",
]

[transport]
compression = "zstd"
zstd_level = 3
enable_hash_cache = true

[graphsketch]
enabled = true
entropy_alpha = 0.3
entropy_threshold = 3.0
batch_size = 50
flush_interval = "60s"
```

---

## 6. Post-Installation Verification

```bash
# 1. Check daemon is running
providaptctl -status

# 2. Verify eBPF programs loaded
bpftool prog list | grep providapt

# 3. Check event ingestion
tail -f /var/log/providapt/providapt.log | grep "scan complete"

# 4. Verify data directory
ls -la /var/lib/providapt/store/

# 5. Run verification
providapt-verify -data /var/lib/providapt/store

# 6. Run attack simulation
make attack-sim
make verify-capture
```
