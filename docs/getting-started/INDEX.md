# 快速入门

本节文档帮助你在不同环境中快速部署和运行 ProvidAPT。

## 文档列表

| 文档 | 说明 |
| --- | --- |
| [install.md](install.md) | 安装指南（英文）[中文版](install.zh.md) |
| [install.zh.md](install.zh.md) | 安装指南（中文版） |
| [deployment.md](deployment.md) | 部署指南（英文）[中文版](deployment.zh.md) |
| [deployment.zh.md](deployment.zh.md) | 部署指南（中文版） |

## 前置要求

- Linux 内核 ≥ 5.10（推荐 5.15+）
- BTF 支持（`/sys/kernel/btf/vmlinux`）
- `clang` ≥ 12.0、`libbpf` ≥ 1.0

## 快速命令

```bash
# 检查环境
make verify-env

# 安装依赖
make install-deps

# 构建并安装
make v1-install

# 启动守护进程
sudo providaptd -config /etc/providapt/providapt.toml
```
