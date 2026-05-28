# ProvidAPT

Linux 全系统溯源记录工具，基于 eBPF LSM 技术，参考 CamFlow 设计，用于 APT 攻击分析与溯源。

## 架构

```
┌────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  eBPF LSM      │───▶│  Go 用户态       │───▶│  存储/告警      │
│  内核钩子       │    │  溯源图构建       │    │  (NDJSON/SIEM)  │
└────────────────┘    └─────────────────┘    └─────────────────┘
```

## 快速开始

```bash
# 1. 编译
make build

# 2. 部署 (需 root)
sudo make install
# 或手动
sudo ./scripts/deploy.sh

# 3. 启动
sudo providaptd

# 4. 查看日志
tail -f /var/log/providapt/providapt-*.ndjson
```

## 内核要求

- Linux 5.7+ (BPF LSM 支持)
- 内核编译选项: `CONFIG_BPF_LSM=y`
- BTF 支持: `/sys/kernel/btf/vmlinux` 存在

## 支持的事件

| 类别 | 事件 | LSM Hook |
|------|------|----------|
| 进程 | fork, exec, exit | task_alloc, bprm_check_security |
| 文件 | open, read, write, unlink | file_open, file_permission |
| 网络 | connect, accept, send, recv | socket_connect |
| 凭据 | setuid, capable | (kprobe/security_capable) |

## 项目结构

```
├── kernel/          eBPF 内核态程序 (C)
├── userspace/       用户态程序 (Go)
│   ├── cmd/         入口 (providaptd + providaptctl)
│   └── pkg/         库代码
├── docs/            设计文档
├── scripts/         构建部署脚本
├── test/            集成测试与攻击模拟
└── examples/        示例代码
```

## License

GPL v2
