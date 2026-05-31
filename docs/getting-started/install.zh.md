# ProvidAPT 安装指南

**版本 1.0** | Linux 系统溯源监控工具

ProvidAPT 是一款基于 eBPF 的 Linux 系统溯源监控工具，专为 APT 攻击检测和取证分析设计。本文档涵盖从源码编译安装、系统集成到验证的完整流程。

---

## 目录

- [1. 环境要求](#1-环境要求)
- [2. 依赖安装](#2-依赖安装)
- [3. 编译指南](#3-编译指南)
- [4. 系统集成](#4-系统集成)
- [5. 快速验证](#5-快速验证)
- [6. 性能调优](#6-性能调优)
- [7. 故障排除](#7-故障排除)

---

## 1. 环境要求

### 1.1 支持的 Linux 发行版

| 发行版 | 最低版本 | 架构 |
|--------|---------|------|
| Ubuntu LTS | 20.04+ | x86_64, aarch64 |
| Debian | 11+ | x86_64, aarch64 |
| RHEL / Rocky Linux / AlmaLinux | 9+ | x86_64, aarch64 |
| Fedora | 37+ | x86_64, aarch64 |
| CentOS Stream | 9+ | x86_64 |
| Amazon Linux | 2023+ | x86_64, aarch64 |
| Alpine Linux | 3.18+ | x86_64 |

### 1.2 内核要求

**最低内核版本：5.8**（需要 BPF Ring Buffer 支持）

推荐版本：**5.11+**（支持 BPF LSM 和可睡眠 BPF 程序）

### 1.3 必需的内核配置

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_LSM=y              # LSM 钩子必需
CONFIG_DEBUG_INFO_BTF=y       # CO-RE 必需
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
CONFIG_TRACING=y
CONFIG_FTRACE=y
CONFIG_FUNCTION_TRACER=y
CONFIG_BPF_EVENTS=y
CONFIG_BPF_KPROBE_OVERRIDE=y
CONFIG_CGROUPS=y
```

### 1.4 快速检查内核

```bash
# 检查内核版本
uname -r
# 应 ≥ 5.11.0

# 检查 BTF 可用性
ls -la /sys/kernel/btf/vmlinux

# 检查 BPF LSM 配置
zgrep CONFIG_BPF_LSM /proc/config.gz 2>/dev/null || \
  grep CONFIG_BPF_LSM /boot/config-$(uname -r)
```

---

## 2. 依赖安装

### 2.1 必需软件包

| 软件包 | 用途 | 最低版本 |
|--------|------|---------|
| clang, llvm, lld | eBPF 字节码编译 | 14.0+ |
| bpftool | BPF 程序管理 | 7.0+ |
| libbpf-dev / libbpf-devel | BPF 用户空间库 | 1.0+ |
| Go | 用户空间代理编译 | 1.22+ |
| make | 构建系统 | 4.0+ |
| kernel-headers | 内核头文件 | 匹配内核版本 |

### 2.2 各平台安装命令

#### Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install -y \
    clang llvm lld bpftool \
    libbpf-dev \
    linux-headers-$(uname -r) \
    pkg-config \
    curl git make jq
```

#### RHEL / Rocky Linux / AlmaLinux 9

```bash
sudo dnf install -y \
    clang llvm lld bpftool \
    libbpf-devel \
    kernel-devel kernel-headers \
    pkgconfig \
    curl git make jq
```

#### Go 安装

如果包管理器未提供 Go 1.22+：

```bash
wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

---

## 3. 编译指南

### 3.1 克隆仓库

```bash
git clone https://github.com/Chaoqun-Guo/ProvidAPT.git
cd ProvidAPT
```

### 3.2 验证系统就绪

```bash
# 运行内核探测，确定最优 eBPF 模式
bash build/kernel_probe.sh

# 完整系统验证
bash build/verify.sh
```

### 3.3 编译 eBPF 字节码

```bash
# 编译所有 eBPF 程序
make ebpf
```

### 3.4 编译用户空间代理

```bash
# 构建所有 Go 二进制文件
make userspace
```

### 3.5 完整构建

```bash
make build
```

---

## 4. 系统集成

### 4.1 安装到系统目录

```bash
sudo make install
```

### 4.2 资源限制配置

配置 cgroup v2 资源限制，防止代理影响其他系统进程：

```bash
sudo bash build/setup_cgroup.sh
```

### 4.3 SystemD 服务

```bash
# 安装 systemd 服务
sudo cp build/providapt-cgroup.service /etc/systemd/system/providapt.service
sudo systemctl daemon-reload
sudo systemctl enable providapt.service
sudo systemctl start providapt.service
```

### 4.4 手动启停

```bash
# 启动守护进程
sudo providaptd

# 停止
sudo providaptctl -stop
```

### 4.5 日志和输出目录

| 路径 | 内容 |
|------|------|
| `/var/log/providapt/` | 事件日志和溯源图 |
| `/var/lib/providapt/store/` | RocksDB 持久化存储 |
| `/etc/providapt/providapt.toml` | 配置文件 |

---

## 5. 快速验证

```bash
# 检查守护进程是否运行
pidof providaptd

# 检查 eBPF 程序
sudo bpftool prog show | grep -E "lsm|providapt"

# API 健康检查
curl -s http://localhost:8080/api/v1/status
```

---

## 6. 性能调优

### 自适应监控级别

| 级别 | 描述 | 影响 |
|------|------|------|
| 1（默认）| 仅核心事件 | ~1% CPU |
| 2（可疑）| 文件详情 + 环境 | ~3% CPU |
| 3（调查）| 完整系统调用跟踪 | ~10% CPU |

---

## 7. 故障排除

| 问题 | 原因 | 解决方案 |
|------|------|---------|
| eBPF 加载失败 | BTF 不可用 | 安装 `linux-image-$(uname -r)-dbg` |
| 无事件摄入 | LSM 未配置 | 在内核命令行中添加 `bpf` 到 LSM 列表 |
| 内存使用过高 | 缓存过大 | 减少配置中的 `max_cache_size` |
| Ring Buffer 溢出 | 事件过载 | 增大 `RINGBUF_SIZE` 或启用去重 |
