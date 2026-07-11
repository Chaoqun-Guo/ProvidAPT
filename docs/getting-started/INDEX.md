# 快速入门

本节帮助你在不同环境中安装、评估、部署并运行 ProvidAPT。

## 文档列表

| 文档 | 说明 |
| --- | --- |
| [install.md](install.md) | 英文安装指南 |
| [install.zh.md](install.zh.md) | 中文安装指南 |
| [commercial-install.md](commercial-install.md) | 商业 Linux 安装、卸载与升级预检 |
| [deployment.md](deployment.md) | 英文部署指南 |
| [deployment.zh.md](deployment.zh.md) | 中文部署指南 |
| [evaluation.md](evaluation.md) | 客户评估与 POC 指南 |

## 前置要求

- Linux 内核 5.8+；推荐 5.11+ 以启用 BPF LSM。
- BTF 支持，通常位于 `/sys/kernel/btf/vmlinux`。
- `clang` 12+、`llvm-strip`、`libbpf` 1.0+。
- Go 1.25+。

## 快速命令

```bash
# 检查环境
make verify-env

# 安装依赖
make install-deps

# 构建并安装
make install-local

# 启动 daemon
sudo systemctl start providapt.service
```
