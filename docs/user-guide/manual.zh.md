# ProvidAPT 用户手册

**版本 1.0** | 溯源监控和 APT 检测操作指南

本手册涵盖 ProvidAPT 的日常操作，包括溯源图查询、检测策略配置、告警解读和性能调优。

---

## 目录

- [1. 命令行工具](#1-命令行工具)
- [2. ProvQL 查询指南](#2-provql-查询指南)
- [3. 策略配置](#3-策略配置)
- [4. 可视化与报告](#4-可视化与报告)
- [5. 性能调优](#5-性能调优)
- [6. 卸载与清理](#6-卸载与清理)

---

## 1. 命令行工具

ProvidAPT 包含六个命令行工具。

### 1.1 providaptctl — 控制与管理

守护进程管理的主要管理工具。

```bash
# 检查守护进程状态
providaptctl -status

# 停止守护进程
providaptctl -stop

# 重启守护进程
providaptctl -restart
```

### 1.2 providaptd — 主守护进程

溯源监控守护进程，通常作为 systemd 服务运行。

```bash
# 使用默认配置启动
sudo providaptd

# 使用自定义配置启动
sudo providaptd -config /etc/providapt/custom.toml

# 启用详细日志
sudo providaptd -v
```

Loader 行为说明：

- `providaptd` 会优先使用 **BPF LSM** 挂载核心 Hook。
- 如果 `lsm_hooks.bpf.o` 已成功加载，但 LSM attach 失败，守护进程会自动切换到 **kprobe fallback** 模式。
- Loader 默认搜索以下对象文件位置：
  - `build/ebpf/lsm_hooks.bpf.o`
  - `/usr/local/lib/providapt/ebpf/lsm_hooks.bpf.o`
- 如果对象文件位于非默认位置，可在启动前设置 `PROVIDAPT_BPF_OBJECT_PATH`：

```bash
export PROVIDAPT_BPF_OBJECT_PATH=/opt/providapt/ebpf/lsm_hooks.bpf.o
sudo -E providaptd -config /etc/providapt/providapt.toml
```

### 1.3 providapt-watchdog — 高可用监控器

监控主守护进程，在崩溃时自动重启。

```bash
# 使用默认路径启动看门狗
sudo providapt-watchdog &
```

### 1.4 providapt-verify — 数据完整性验证器

扫描溯源数据，验证 Merkle 树哈希链完整性。

```bash
# 验证所有存储数据
sudo providapt-verify -data /var/lib/providapt/store

# 保存报告到文件
sudo providapt-verify -data /var/lib/providapt/store -output /tmp/report.txt
```

退出码：`0` = 数据完整，`2` = 检测到篡改。

### 1.5 providapt-deanon — 授权去匿名化

从匿名哈希中恢复原始敏感值。

```bash
providapt-deanon -hash a3f8b2c1 -key /etc/providapt/deanon.key
```

### 1.6 providapt-heal — 自动化事件响应

评估攻击影响、回滚变更、阻断 C2 通信。

```bash
# 评估恶意进程影响范围
providapt-heal -pid 1234

# 完整响应：终止进程 + 隔离文件
providapt-heal -pid 1234 -rollback -dry-run=false

# 阻断 C2 IP
providapt-heal -pid 1234 -firewall
```

---

## 2. ProvQL 查询指南

ProvQL（溯源查询语言）是一种受 Neo4j Cypher 启发的声明式图查询语言。

### 2.1 语法参考

```sql
MATCH (variable:Label)-[:RELATION]->(variable:Label)
WHERE condition
DURING [start_time, end_time]
RETURN variable.field, variable.field
```

### 2.2 检测权限提升

```sql
MATCH (p:Process)-[:READ]->(f:File)
WHERE f.path = '/etc/shadow'
  AND p.comm CONTAINS 'sudo'
RETURN p.pid, p.comm, f.path
```

### 2.3 检测横向移动

```sql
MATCH (p:Process)-[:CONNECTED]->(n:Network)
WHERE n.label CONTAINS ':22' AND p.comm = 'ssh'
RETURN p.pid, p.comm, n.label
```

### 2.4 检测无文件恶意软件执行

```sql
MATCH (a:Process)-[:WROTE]->(f:File)-[:READ]->(b:Process)
WHERE f.path STARTSWITH '/tmp' AND a.comm CONTAINS 'curl' AND b.comm = 'bash'
RETURN a.comm, f.path, b.comm
```

### 2.5 检测敏感数据外泄

```sql
MATCH (p:Process)-[:READ]->(f:File)
WHERE f.path STARTSWITH '/etc'
RETURN p.pid, p.comm, f.path
```

### 2.6 重构完整攻击链

```sql
MATCH (a:Process)-[:FORKED]->(b:Process)-[:WROTE]->(f:File)-[:READ]->(c:Process)-[:CONNECTED]->(n:Network)
RETURN a.comm, b.comm, f.path, c.comm, n.label
```

---

## 3. 策略配置

### 3.1 主动防御规则

规则从 `/etc/providapt/rules.yaml` 加载。

```yaml
version: "1.0"

whitelist:
  pids: [1, 2]
  comms: ["yum", "dnf", "apt", "dpkg", "make"]
  paths: ["/usr/share/*", "/usr/lib/*"]

blacklist:
  sensitive_files: ["/etc/shadow", "/etc/passwd", "/etc/sudoers"]
  untrusted_dirs: ["/tmp/*", "/dev/shm/*", "/var/tmp/*"]
  dangerous_comms: ["nc", "ncat", "tftp", "socat"]
```

### 3.2 自适应监控策略

| 级别 | 名称 | 触发条件 | 能力 |
|------|------|---------|------|
| 1 | DEFAULT | 基线 | exec, fork, connect |
| 2 | SUSPICIOUS | 分数 ≥ 5 | +文件详情, +网络流, +环境捕获 |
| 3 | INVESTIGATING | 分数 ≥ 20 或重复告警 | +系统调用跟踪, +内存跟踪, +内存转储 |

---

## 4. 可视化与报告

### 4.1 图导出格式

ProvidAPT 支持 PROV-JSON 和 GraphML 两种导出格式。

```bash
# 通过 API 手动触发
curl -s "http://localhost:8080/api/v1/graph/export?pid=1234"
```

### 4.2 AI 生成的攻击报告

配置 LLM 连接后可生成自然语言攻击分析报告：

```bash
# 在 providapt.toml 中配置：
# { "ai": { "provider": "ollama", "endpoint": "http://localhost:11434/api/chat", "model": "llama3" } }
```

### 4.3 性能仪表板

```bash
curl -s http://localhost:8080/api/v1/status
# 响应：{"status":"running","nodes":15234,"edges":89201}
```

---

## 5. 性能调优

### 5.1 LRU 缓存大小

| 缓存大小 | 估计内存 | 适用场景 |
|---------|---------|---------|
| 2,048 | ~50 MB | 低内存 / 容器环境 |
| 8,192 | ~200 MB | 默认配置 |
| 32,768 | ~800 MB | 高吞吐服务器 |

### 5.2 Merge Window（合并窗口）

```go
cfg.MergeWindow = 5 * time.Second   // 默认
// 增大可获得更高压缩比：30秒
// 减小可获得实时精度：1秒
```

---

## 6. 卸载与清理

如果启动时报错 `no precompiled eBPF object found`，可先执行 `make v1-ebpf` 重新生成对象文件，或通过 `PROVIDAPT_BPF_OBJECT_PATH` 指向已有的 `lsm_hooks.bpf.o` 后再启动。

```bash
# 优雅停止守护进程
sudo providaptctl -stop

# 卸载二进制文件
sudo make uninstall

# 卸载 eBPF 程序
sudo rm -rf /sys/fs/bpf/providapt 2>/dev/null || true

# 删除数据和配置
sudo rm -rf /var/log/providapt/ /var/lib/providapt/ /etc/providapt/

# 移除 systemd 服务
sudo systemctl disable providapt.service
sudo rm /etc/systemd/system/providapt.service
sudo systemctl daemon-reload
```
