# Getting Started

This section helps you install, evaluate, deploy, and run ProvidAPT in different environments.

## Documents

| Document | Description |
| --- | --- |
| [quick-start.md](quick-start.md) | Fast path from install to dashboard, alerts, and provenance trace |
| [install.md](install.md) | Installation guide |
| [commercial-install.md](commercial-install.md) | Commercial Linux install, uninstall, and upgrade preflight |
| [docker-compose.md](docker-compose.md) | Docker Compose deployment and operations |
| [helm.md](helm.md) | Helm install, upgrade, rollback, and uninstall workflows |
| [deployment.md](deployment.md) | Deployment guide |
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
