# ProvidAPT 用户手册

**发布版本：** `v1.2.2`

本文档覆盖 ProvidAPT 的日常使用流程，包括命令行操作、溯源调查、策略控制、报告导出、性能调优和清理步骤。

## 1. 命令行工具

ProvidAPT 提供以下主要工具：

- `providaptctl`：控制与诊断 CLI。
- `providaptd`：主守护进程。
- `providapt-watchdog`：守护与健康检查工具。
- `providapt-verify`：数据完整性校验工具。
- `providapt-deanon`：去匿名化辅助工具。
- `providapt-heal`：进程隔离、回滚和自愈工具。

### `providaptctl`

```bash
providaptctl -status
providaptctl -restart
providaptctl -diagnose
providaptctl -verify -json
providaptctl -audit -audit-cat=admin -json
```

### `providaptd`

```bash
sudo providaptd
sudo providaptd -config /etc/providapt/providapt.toml
sudo providaptd -v
```

启动时会自动检查：

- 当前内核是否启用 `BPF LSM`。
- 是否可以使用 `kprobe` fallback。
- eBPF 对象文件是否存在于默认路径：
  - `build/ebpf/lsm_hooks.bpf.o`
  - `/usr/local/lib/providapt/ebpf/lsm_hooks.bpf.o`

也可以显式指定 eBPF 对象路径：

```bash
export PROVIDAPT_BPF_OBJECT_PATH=/opt/providapt/ebpf/lsm_hooks.bpf.o
sudo -E providaptd -config /etc/providapt/providapt.toml
```

### 仅监控特定命令

如果客户端只需要关注少量命令，可以在配置中使用 `capture.include_comms`：

```yaml
capture:
  include_comms:
    - curl
    - wget
    - ssh
```

也可以通过环境变量设置：

```bash
export PROVIDAPT_CAPTURE_INCLUDE_COMMS=curl,wget,ssh
sudo -E providaptd -config /etc/providapt/providapt.yaml
```

事件进入溯源图、存储和告警管线前会先经过 `include_comms` 白名单过滤。启动时，ProvidAPT 还会扫描当前 `/proc`，将 `comm` 不在白名单中的已运行进程加入内核 PID 排除表。建议同时配合检测规则和 `hot_paths` 使用，以便对这些命令保留更高质量的事件和溯源证据。

### `providapt-verify`

```bash
sudo providapt-verify -data /var/lib/providapt/store
sudo providapt-verify -data /var/lib/providapt/store -verbose
```

常见退出码：

- `0`：校验通过。
- `2`：发现完整性错误或证据链异常。

### `providapt-heal`

```bash
providapt-heal -pid 1234
providapt-heal -pid 1234 -rollback -dry-run=false
providapt-heal -pid 1234 -firewall
```

## 2. ProvQL 调查示例

### 查询读取 `/etc/shadow` 的进程

```sql
MATCH (p:Process)-[:READ]->(f:File)
WHERE f.path = '/etc/shadow'
RETURN p.pid, p.comm, f.path
```

### 查询 SSH 外联行为

```sql
MATCH (p:Process)-[:CONNECTED]->(n:Network)
WHERE n.label CONTAINS ':22' AND p.comm = 'ssh'
RETURN p.pid, p.comm, n.label
```

### 查询 `curl -> 临时文件 -> bash` 链路

```sql
MATCH (a:Process)-[:WROTE]->(f:File)-[:READ]->(b:Process)
WHERE f.path STARTSWITH '/tmp'
  AND a.comm CONTAINS 'curl'
  AND b.comm = 'bash'
RETURN a.comm, f.path, b.comm
```

## 3. 运维 API

常用接口：

- `GET /api/v1/status`
- `GET /api/v1/graph/export`
- `GET /api/v1/alerts`
- `POST /api/v1/control/support`
- `GET /api/v1/control/support/download`
- `GET /api/v1/control/backup`
- `POST /api/v1/control/backup`
- `GET /api/v1/control/backup/download`
- `GET /api/v1/control/license`
- `POST /api/v1/control/license`
- `GET /api/v1/control/upgrade`
- `POST /api/v1/control/upgrade`

## 4. 报告与证据

报告通常包含：

- 攻击链时间线。
- MITRE ATT&CK 技术映射。
- 进程、文件、网络与权限变化证据。
- 审计日志、原始事件和完整性校验结果。

建议在告警处置完成后导出报告，并将报告、校验结果和相关原始事件一起归档。

## 5. 性能调优

- 将数据目录放在 SSD 上，减少写入延迟。
- 对高频事件启用采样或策略过滤。
- 根据事件量调整 ring buffer 与下游处理能力。
- 发布前运行 `go test ./...` 和 release-scoped 测试。

## 6. 卸载与清理

```bash
providaptctl -stop
sudo systemctl disable providapt
sudo rm -rf /var/lib/providapt/store
sudo rm -rf /var/log/providapt
sudo rm -f /etc/providapt/providapt.toml
```
