# 部署指南

**单机部署 & Kubernetes** | 环境准备、安装步骤、分布式配置

---

## 1. 环境准备

### 1.1 最低要求

| 资源 | 最低配置 | 推荐配置 |
|------|---------|---------|
| CPU | 2 核 | 8+ 核 |
| 内存 | 2 GB | 16+ GB |
| 磁盘 | 10 GB | 200+ GB (SSD) |
| 内核 | 5.11+ | 6.2+ |
| eBPF | BTF 支持 | CO-RE 能力 |

### 1.2 内核验证

```bash
# 检查 BTF 支持（CO-RE 必需）
ls /sys/kernel/btf/vmlinux

# 检查 LSM 配置
cat /sys/kernel/security/lsm | grep bpf

# 检查内核版本
uname -r
```

### 1.3 LSM 配置

在 `/etc/default/grub` 的 LSM 列表中添加 `bpf`：

```bash
GRUB_CMDLINE_LINUX="lsm=lockdown,capability,selinux,bpf"
update-grub
reboot
```

---

## 2. 单机安装

### 2.1 源码编译

```bash
git clone https://github.com/Chaoqun-Guo/ProvidAPT
cd ProvidAPT

# 完整构建（eBPF + 用户空间）
make v1

# 安装到系统
sudo make v1-install
```

补充说明：

- ProvidAPT 默认优先使用 **BPF LSM**。
- 如果 LSM attach 失败，但对象文件已正确加载，系统会自动切换到 **kprobe fallback** 模式。
- 如果 `.bpf.o` 文件不在默认目录，可在启动前指定：

```bash
export PROVIDAPT_BPF_OBJECT_PATH=/opt/providapt/ebpf/lsm_hooks.bpf.o
sudo -E providaptd -config /etc/providapt/providapt.toml
```

### 2.2 安装后配置

```bash
mkdir -p /var/lib/providapt/store
chmod 0700 /var/lib/providapt

# 检查 eBPF 对象文件
ls /usr/local/lib/providapt/ebpf/

# 启动守护进程
sudo providaptd

# 验证状态
sudo providaptctl -status
```

### 2.3 Systemd 服务

```ini
# /etc/systemd/system/providapt.service
[Unit]
Description=ProvidAPT 溯源监控器
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

## 3. 分布式配置

### 3.1 中央服务器设置

```bash
# 安装中央服务器组件
make cluster

# 在 /etc/providapt/collectors.toml 中配置收集器
[[collector]]
id = "collector-1"
address = "10.0.0.1:8443"
cert = "/etc/providapt/certs/collector-1.pem"
```

### 3.2 mTLS 证书生成

```bash
# CA 密钥
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt

# 服务器证书
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -out server.crt
```

---

## 4. Kubernetes 部署

### 4.1 DaemonSet 配置

```yaml
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
```

---

## 5. 安装后验证

```bash
# 1. 检查守护进程运行状态
providaptctl -status

# 2. 验证 eBPF 程序已加载
bpftool prog list | grep providapt

# 3. 检查事件摄入
tail -f /var/log/providapt/providapt.log | grep "scan complete"

# 4. 运行验证
providapt-verify -data /var/lib/providapt/store
```
