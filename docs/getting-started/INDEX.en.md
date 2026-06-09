# Getting Started

This section helps you quickly deploy and run ProvidAPT in different environments.

## Documents

| Document | Description |
| --- | --- |
| [install.md](install.md) | Installation guide (English) [涓枃鐗圿(install.zh.md) |
| [install.zh.md](install.zh.md) | 瀹夎鎸囧崡锛堜腑鏂囩増锛?|
| [deployment.md](deployment.md) | Deployment guide (English) [涓枃鐗圿(deployment.zh.md) |
| [deployment.zh.md](deployment.zh.md) | 閮ㄧ讲鎸囧崡锛堜腑鏂囩増锛?|

## Prerequisites

- Linux kernel 鈮?5.10 (recommended 5.15+)
- BTF support (`/sys/kernel/btf/vmlinux`)
- `clang` 鈮?12.0, `libbpf` 鈮?1.0

## Quick Commands

```bash
# Check environment
make verify-env

# Install dependencies
make install-deps

# Build and install
make install-local

# Start the daemon
sudo providaptd -config /etc/providapt/providapt.toml
```
