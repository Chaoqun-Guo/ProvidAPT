# Getting Started

This section helps you install, evaluate, deploy, and run ProvidAPT in different environments.

## Documents

| Document | Description |
| --- | --- |
| [install.md](install.md) | Installation guide |
| [install.zh.md](install.zh.md) | Chinese installation guide |
| [commercial-install.md](commercial-install.md) | Commercial Linux install, uninstall, and upgrade preflight |
| [deployment.md](deployment.md) | Deployment guide |
| [deployment.zh.md](deployment.zh.md) | Chinese deployment guide |
| [evaluation.md](evaluation.md) | Customer evaluation and POC guide |

## Prerequisites

- Linux kernel 5.8+; 5.11+ recommended for BPF LSM.
- BTF support, usually at `/sys/kernel/btf/vmlinux`.
- `clang` 12+, `llvm-strip`, and `libbpf` 1.0+.
- Go 1.25+.

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
