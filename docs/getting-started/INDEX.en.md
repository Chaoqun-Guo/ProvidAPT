# Getting Started

This section helps you quickly deploy and run ProvidAPT in different environments.

## Documents

| Document | Description |
| --- | --- |
| [install.md](install.md) | Installation guide (English) [中文版](install.zh.md) |
| [install.zh.md](install.zh.md) | 安装指南（中文版） |
| [deployment.md](deployment.md) | Deployment guide (English) [中文版](deployment.zh.md) |
| [deployment.zh.md](deployment.zh.md) | 部署指南（中文版） |

## Prerequisites

- Linux kernel ≥ 5.10 (recommended 5.15+)
- BTF support (`/sys/kernel/btf/vmlinux`)
- `clang` ≥ 12.0, `libbpf` ≥ 1.0

## Quick Commands

```bash
# Check environment
make verify-env

# Install dependencies
make install-deps

# Build and install
make v1-install

# Start the daemon
sudo providaptd -config /etc/providapt/providapt.toml
```
