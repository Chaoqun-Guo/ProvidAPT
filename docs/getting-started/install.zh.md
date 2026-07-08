# ProvidAPT 安装指南

本文档说明如何在 Linux 主机上安装、构建、运行和验证 ProvidAPT。

## 1. 系统要求

| 项目 | 最低要求 | 推荐配置 |
| --- | --- | --- |
| 内核 | Linux 5.8+ | Linux 5.11+，启用 BPF LSM |
| BTF | `/sys/kernel/btf/vmlinux` 可用 | CO-RE 兼容内核 |
| CPU | 2 cores | 8+ cores |
| 内存 | 2 GB | 16 GB+ |
| 磁盘 | 10 GB | 200 GB+ SSD |
| Go | 1.25+ | 1.25+ |
| eBPF 工具链 | clang 12+、llvm-strip、libbpf 1.0+ | 发行版稳定包 |

## 2. 环境检查

```bash
# 检查内核版本
uname -r
# 预期：5.8+，推荐 5.11+

# 检查 BTF
ls -la /sys/kernel/btf/vmlinux

# 检查 LSM 是否包含 bpf
cat /sys/kernel/security/lsm

# 检查 eBPF 能力
bpftool feature probe
```

如果 LSM 列表没有 `bpf`，可在 `/etc/default/grub` 中配置：

```bash
GRUB_CMDLINE_LINUX="lsm=lockdown,capability,selinux,bpf"
sudo update-grub
sudo reboot
```

## 3. 安装依赖

### Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install -y \
  clang llvm libbpf-dev linux-headers-$(uname -r) \
  build-essential pkg-config bpftool curl git make jq \
  python3 python3-pip
```

### RHEL / Rocky / CentOS

```bash
sudo dnf install -y \
  clang llvm libbpf-devel kernel-devel kernel-headers \
  make gcc git curl jq python3 python3-pip
```

### Go 安装

如果包管理器未提供 Go 1.25+：

```bash
wget https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.25.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version
```

## 4. 获取源码并构建

```bash
git clone https://github.com/Chaoqun-Guo/ProvidAPT
cd ProvidAPT

# 检查环境
make verify-env

# 构建 eBPF 对象
make build-ebpf

# 构建用户态二进制
make build-userspace

# 完整构建
make build-core
```

构建产物：

```text
build/bin/providaptd          # 主 daemon
build/bin/providaptctl        # 控制 CLI
build/bin/providapt-watchdog  # watchdog
build/bin/providapt-verify    # 数据完整性验证
build/bin/providapt-deanon    # 去匿名化工具
build/bin/providapt-heal      # 自愈工具
build/ebpf/*.bpf.o            # eBPF 对象文件
```

## 5. 本地安装

```bash
sudo make install-local
```

默认路径：

| 路径 | 用途 |
| --- | --- |
| `/etc/providapt/providapt.toml` | 主配置文件 |
| `/usr/local/sbin/providaptd` | 主 daemon |
| `/usr/local/bin/providaptctl` | 控制 CLI |
| `/usr/local/lib/providapt/ebpf/` | eBPF 对象目录 |
| `/var/log/providapt/` | 日志和运行时输出目录 |
| `/var/lib/providapt/store/` | 数据存储目录 |

## 6. 启动与验证

```bash
sudo providaptd -config /etc/providapt/providapt.toml
providaptctl -status
```

可选 systemd 服务示例：

```ini
[Unit]
Description=ProvidAPT Provenance Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/providaptd -config /etc/providapt/providapt.toml
Restart=on-failure
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

## 7. eBPF Loader 行为

- ProvidAPT 优先通过 BPF LSM 挂载核心 hook。
- 如果 LSM 挂载失败但核心对象可加载，daemon 会尝试 kprobe fallback。
- Loader 默认查找：
  - `build/ebpf/lsm_hooks.bpf.o`
  - `/usr/local/lib/providapt/ebpf/lsm_hooks.bpf.o`
- 自定义对象路径：

```bash
export PROVIDAPT_BPF_OBJECT_PATH=/opt/providapt/ebpf/lsm_hooks.bpf.o
sudo -E providaptd -config /etc/providapt/providapt.toml
```

## 8. 常见问题

| 问题 | 常见原因 | 建议处理 |
| --- | --- | --- |
| 找不到 eBPF 对象 | 未运行 eBPF 构建或安装路径错误 | 执行 `make build-ebpf`，确认对象目录存在 |
| BTF 不可用 | 内核未启用 BTF 或缺少调试信息 | 检查 `/sys/kernel/btf/vmlinux`，必要时使用发行版 BTF 包 |
| LSM 不包含 `bpf` | GRUB LSM 参数未配置 | 配置 `lsm=lockdown,capability,selinux,bpf` 并重启 |
| 事件丢失 | 事件量超过消费能力 | 调整采集范围、ring buffer 或下游处理能力 |
| 权限不足 | eBPF、cgroup 或 host path 权限不够 | 确认以 root 运行或授予所需 capability |

当出现 `no precompiled eBPF object found` 时：

```bash
make build-ebpf
sudo make install-local
```

## 9. 下一步

- 客户评估与 POC：`docs/getting-started/evaluation.md`
- 部署指南：`docs/getting-started/deployment.md`
- 运维指南：`docs/user-guide/operations.md`
- 发布检查：`docs/developer/release-readiness.md`
