# Getting Started

This section explains how to install, evaluate, deploy, and operate ProvidAPT in common Linux environments.

## Documents

| Document | Description |
| --- | --- |
| [quick-start.md](quick-start.md) | Fast path from install to dashboard, alerts, and provenance trace |
| [install.md](install.md) | Installation guide for source and package-based installs |
| [commercial-install.md](commercial-install.md) | Commercial Linux installation, removal, upgrade, and preflight checks |
| [docker-compose.md](docker-compose.md) | Docker Compose deployment and operations |
| [helm.md](helm.md) | Helm install, upgrade, rollback, and uninstall workflows |
| [deployment.md](deployment.md) | Production deployment guide |
| [evaluation.md](evaluation.md) | Customer evaluation and proof-of-concept guide |

## Prerequisites

- Linux kernel 5.8 or later; kernel 5.11 or later is recommended for BPF LSM.
- BTF support, typically available at `/sys/kernel/btf/vmlinux`.
- `clang` 12 or later, `llvm-strip`, and `libbpf` 1.0 or later.
- Go 1.25 or later for source builds.

## Quick Commands

```bash
make verify-env
make install-deps
make install-local
sudo systemctl start providapt.service
```
