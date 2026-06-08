# 快速入门

本节帮助你在不同环境中安装、部署并启动 ProvidAPT。

## 文档列表

| 文档 | 说明 |
| --- | --- |
| [install.md](install.md) | 英文安装指南 |
| [install.zh.md](install.zh.md) | 中文安装指南 |
| [deployment.md](deployment.md) | 英文部署指南 |
| [deployment.zh.md](deployment.zh.md) | 中文部署指南 |

## 前置要求

- Linux 内核 5.10+，推荐 5.15+
- BTF 支持，通常为 `/sys/kernel/btf/vmlinux`
- `clang` 12+ 与 `libbpf` 1.0+

## 快速命令

```bash
# 检查环境
make verify-env

# 安装依赖
make install-deps

# 构建并安装
make v1-install

# 启动 daemon
sudo providaptd -config /etc/providapt/providapt.toml
```
