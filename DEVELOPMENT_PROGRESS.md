# ProvidAPT 开发进度文档

> 生成时间: 2026-06-07
> 版本: v1.1.x (dev)
> 模块路径: `github.com/Chaoqun-Guo/ProvidAPT`
> Go 版本: 1.25

---

## 一、产品概述

ProvidAPT 是一款基于 eBPF 的 APT 攻击溯源与实时防御系统。通过内核态 eBPF 探针采集系统调用和 LSM 事件，构建进程-文件-网络的 provenance graph（溯源图），结合多策略分析引擎检测 APT 攻击链。

### 核心架构

```
eBPF 探针 (RingBuf) → Collector → Pipeline (merge/dedup/cache) → Provenance Graph → Analyzer → Alert/Notify
                                      ↓
                              PebbleDB (持久化)
```

---

## 二、模块完成状态

### 2.1 内核探针层 (eBPF)

| 组件 | 文件 | 状态 | 说明 |
|------|------|------|------|
| LSM hooks | `cmd/bpf/probes/lsm/lsm_hooks.bpf.c` | ✅ 实现 | file_open, bprm_check, task_alloc, socket_connect |
| Defense | `cmd/bpf/probes/lsm/defense.bpf.c` | ✅ 实现 | 执行保护、文件完整性 |
| Deception | `cmd/bpf/probes/lsm/deception.bpf.c` | ✅ 实现 | 蜜罐文件监控 |
| Network | `cmd/bpf/probes/net/network.bpf.c` | ✅ 实现 | 网络连接追踪 |
| Memory | `cmd/bpf/probes/task/memory.bpf.c` | ✅ 实现 | 内存执行监控 |
| Kprobes | `cmd/bpf/probes/task/kprobes.bpf.c` | ✅ 实现 | 内核探针补充 |
| Tracepoints | `cmd/bpf/probes/task/tracepoints.bpf.c` | ✅ 实现 | tracepoint 采集 |
| Container | `cmd/bpf/probes/task/container_kern.c` | ✅ 实现 | 容器事件 |
| TCP features | `cmd/bpf/probes/net/tcp_features_kern.c` | ✅ 实现 | JA3 指纹等 |
| Dedup | `cmd/bpf/probes/dedup.bpf.h` | ✅ 实现 | eBPF 侧去重 |
| 共享头文件 | `cmd/bpf/headers/` | ✅ 实现 | events.h, taint.h, providapt.h, vmlinux.h |
| CO-RE Loader | `internal/engine/loader/bpf_loader.go` | ✅ 实现 | .o 文件搜索 + LoadAndAssign |
| Stub Loader | `internal/engine/loader/bpf_stub.go` | ✅ 实现 | 非 bpf 标签编译时桩实现 |
| Loader Manager | `internal/engine/loader/loader.go` | ✅ 实现 | PinMaps, 默认排除, Ctrl 接口，LSM→kprobe fallback |
| LSM Manager | `internal/engine/loader/lsm_manager.go` | ✅ 实现 | LSM attach/detach，Hook 配置解析与校验 |
| bpf2go Generate | `internal/engine/loader/generate.go` | ✅ 实现 | `go generate` 入口 |
| 共享类型 | `internal/engine/loader/bpf_types.go` | ✅ 实现 | 双标签共享 bpfObjects |

**完成要点**:
- Makefile `v1-ebpf` / `v1-gen` 目标完整
- CO-RE 加载 + 非 CO-RE stub 双路径
- `//go:build linux && bpf` / `linux && !bpf` 标签分离
- 已支持 **LSM attach 失败后的 kprobe fallback**，并对 `file_open` 等 hook 提供多符号尝试
- `Kernel.Hooks` 已接入 loader，可按配置裁剪启用的内核 hook
- `loader_test.go` 已补充纯逻辑测试，覆盖 hook 解析、去重、spec 生成等路径
- `.bpf.o` 搜索已支持 `PROVIDAPT_BPF_OBJECT_PATH` 覆盖，缺失时会给出更明确的构建/排障提示
- `README`、安装文档、运维手册已补充 loader fallback 与对象文件覆盖路径说明
- 中文安装/部署文档已同步补充 loader fallback 与 `PROVIDAPT_BPF_OBJECT_PATH` 用法
- 中英文长篇手册已补充 loader fallback 与对象文件覆盖路径说明
- 已新增 Linux `loader_smoke.sh` 验证脚本与 `make loader-smoke` 入口，用于真实 eBPF loader 启动验证
- GitHub Actions CI 已新增手动触发的 `loader smoke` job，用于 Linux 运行态 loader 校验闭环

### 2.2 事件采集层 (Collector)

| 组件 | 文件 | 状态 | 说明 |
|------|------|------|------|
| RingBuf 读取 | `internal/engine/collector/ringbuf.go` | ✅ 实现 | eBPF ring buffer 消费者 |
| 事件解析 | `internal/engine/collector/event_parser.go` | ✅ 实现 | 原始 bytes → Event 结构 |
| Fuzz 测试 | `internal/engine/collector/event_parser_test.go` | ✅ 实现 | FuzzParseRawEvent |
| 单元测试 | `internal/engine/collector/event_parser_test.go` | ✅ 实现 | 正常路径 + 边界测试 |

### 2.3 溯源图引擎 (Provenance Graph)

| 组件 | 文件 | 状态 | 说明 |
|------|------|------|------|
| Graph | `internal/engine/provenance/graph.go` | ✅ 实现 | DAG 核心，AddEdge/AddNode 等 |
| Edge | `internal/engine/provenance/edge.go` | ✅ 实现 | 关系边定义 |
| Node | `internal/engine/provenance/node.go` | ✅ 实现 | 节点定义（进程/文件/网络/内存） |
| 序列化 | `internal/engine/provenance/serialize.go` | ✅ 实现 | JSON + GraphML 导出 |
| Pruner | `internal/engine/provenance/pruner.go` | ✅ 实现 | 图裁剪 |
| Memory | `internal/engine/provenance/memory.go` | ✅ 实现 | 内存图存储 |
| Identity | `internal/engine/provenance/identity.go` | ✅ 实现 | 节点身份管理 |
| 凭证 | `internal/engine/provenance/credential.go` | ✅ 实现 | 凭证实体 |
| Camflow | `internal/engine/provenance/camflow_test.go` | ✅ 实现 | CamFlow 集成测试 |
| 测试覆盖 | `internal/engine/provenance/*_test.go` | ✅ 实现 | 全路径覆盖 |

### 2.4 流水线处理 (Pipeline)

| 组件 | 文件 | 状态 | 说明 |
|------|------|------|------|
| Pipeline 主循环 | `internal/engine/pipeline/pipeline.go` | ✅ 实现 | 事件入队/处理循环 |
| BatchWriter | `internal/engine/pipeline/batchwriter.go` | ✅ 实现 | 批量写入 PebbleDB |
| Merger | `internal/engine/pipeline/merger.go` | ✅ 实现 | 滑动窗口 edge 合并 |
| Backpressure | `internal/engine/pipeline/backpressure.go` | ✅ 实现 | 内存压力监控 |
| LockFree | `internal/engine/pipeline/lockfree.go` | ✅ 实现 | SPSC lock-free 队列 |
| WorkerPool | `internal/engine/pipeline/workerpool.go` | ✅ 实现 | 协程池 |
| ZeroCopy | `internal/engine/pipeline/zerocopy.go` | ✅ 实现 | 零拷贝 buffer |
| Opt 优化 | `internal/engine/pipeline/opt_test.go` | ✅ 实现 | 性能优化检测 |
| 测试覆盖 | `internal/engine/pipeline/pipeline_test.go` | ✅ 实现 | 多场景全覆盖 |

### 2.5 分析引擎 (Analyzer)

| 组件 | 文件 | 状态 | 说明 |
|------|------|------|------|
| Analyzer 主循环 | `internal/engine/analyzer/analyzer.go` | ✅ 实现 | 定时扫描 + 多模式匹配 |
| 告警 | `internal/engine/analyzer/alert.go` | ✅ 实现 | Alert 结构定义 |
| Pattern | `internal/engine/analyzer/patterns.go` | ✅ 实现 | 攻击模式定义 |
| Sketch | `internal/engine/analyzer/sketch.go` | ✅ 实现 | 图 Sketch 异常检测 |
| Taint | `internal/engine/analyzer/taint.go` | ✅ 实现 | 污点分析集成 |
| 测试覆盖 | `internal/engine/analyzer/analyzer_test.go` | ✅ 实现 | 含多 pattern 测试 |

### 2.6 存储层 (Storage)

| 组件 | 文件 | 状态 | 说明 |
|------|------|------|------|
| Schema | `internal/storage/schema/schema.go` | ✅ 实现 | 键前缀 "e:", "n:", "r:" 等 |
| Fuzz 测试 | `internal/storage/schema/schema_test.go` | ✅ 实现 | FuzzParseEdgeKey/FuzzParseNodeKey |
| PebbleDB Store | `internal/storage/pebblestore/store.go` | ✅ 实现 | PebbleDB 包装 |
| 批量写入 | `internal/storage/pebblestore/batch.go` | ✅ 实现 | 批量提交 |
| Lifecycle | `internal/storage/pebblestore/lifecycle.go` | ✅ 实现 | Stop 前 flush |
| Config | `internal/storage/pebblestore/config.go` | ✅ 实现 | Pebble 配置 |
| Version | `internal/storage/pebblestore/version.go` | ✅ 实现 | 版本兼容 |
| ZeroCopy Reader | `internal/storage/pebblestore/zc_reader.go` | ✅ 实现 | 零拷贝读取 |
| Cache | `internal/storage/cache/lru.go` | ✅ 实现 | LRU 热节点缓存 |
| Format Writer | `internal/storage/format/writer.go` | ✅ 实现 | NDJSON 写入 |
| Parquet | `internal/storage/format/parquet.go` | ✅ 实现 | Parquet 格式支持 |
| GraphDB | `internal/storage/graphdb/graphdb.go` | ✅ 实现 | 图数据库层 |
| gRPC Export | `internal/storage/grpcexport/grpc.go` | ✅ 实现 | 远程导出 |
| Export | `internal/storage/export/export.go` | ✅ 实现 | 数据导出 API |
| Snapshot | `internal/storage/snapshot/snapshot.go` | ✅ 实现 | 快照 + diff |
| Store 包装 | `internal/storage/store/store.go` | ✅ 实现 | 统一存储接口 |
| 集成测试 | `test/integration/schema_store_test.go` | ✅ 实现 | 端到端存储测试 |

### 2.7 策略引擎 (Policy)

| 组件 | 文件 | 状态 | 说明 |
|------|------|------|------|
| Alert | `internal/policy/alert/` | ✅ 实现 | 告警匹配/摘要/事件 |
| Armor | `internal/policy/armor/` | ✅ 实现 | eBPF map 完整性审计 |
| Blast Radius | `internal/policy/blastradius/` | ✅ 实现 | 攻击半径分析 |
| Deception | `internal/policy/deception/` | ✅ 实现 | 蜜罐/诱饵 |
| Defense | `internal/policy/defense/` | ✅ 实现 | 主动防御 |
| Heal | `internal/policy/heal/` | ✅ 实现 | 自愈恢复 |
| Honeypot | `internal/policy/honeypot/` | ✅ 实现 | 路径蜜罐 |
| Incident | `internal/policy/incident/` | ✅ 实现 | 事件评分/集群/报告 |
| Mgmt | `internal/policy/mgmt/` | ✅ 实现 | gRPC 管理服务 |
| Respond | `internal/policy/respond/` | ✅ 实现 | 阻断/隔离/策略 |
| Response | `internal/policy/response/` | ✅ 实现 | 证据采集/抓取/dump |
| RuleScanner | `internal/policy/rulescanner/` | ✅ 实现 | 规则扫描/权重 |
| SelfHeal | `internal/policy/selfheal/` | ✅ 实现 | eBPF 缺失检测 + 重载 |
| Sigma | `internal/policy/sigma/` | ✅ 实现 | Sigma 规则引擎 |
| SupplyChain | `internal/policy/supplychain/` | ✅ 实现 | 供应链安全 |
| Adaptive | `internal/policy/adaptive/` | ✅ 实现 | 自适应策略控制 |
| 各模块测试覆盖 | `internal/policy/*/*_test.go` | ✅ 实现 | 基本覆盖 |

### 2.8 额外引擎模块

| 组件 | 文件 | 状态 | 说明 |
|------|------|------|------|
| AI Provider | `internal/engine/ai/` | ✅ 实现 | Provider 接口 + OpenAI/Ollama 实现 |
| Backtrace | `internal/engine/backtrace/` | ✅ 实现 | 攻击回溯 |
| Chain | `internal/engine/chain/` | ✅ 实现 | 攻击链构建 |
| Compact | `internal/engine/compact/` | ✅ 实现 | 图压缩合并 |
| Container | `internal/engine/container/` | ✅ 实现 | 容器信息富化 |
| Control | `internal/engine/control/` | ✅ 实现 | 控制命令 |
| EdgeReduce | `internal/engine/edgereduce/` | ✅ 实现 | 边缩减 |
| Filter | `internal/engine/filter/` | ✅ 实现 | 信誉/基线过滤 |
| Fold | `internal/engine/fold/` | ✅ 实现 | I/O 聚合/去重 |
| Forensic | `internal/engine/forensic/` | ✅ 实现 | YARA/哈希/异常 |
| GraphQuery | `internal/engine/graphquery/` | ✅ 实现 | 图查询 DSL |
| Identity | `internal/engine/identity/` | ✅ 实现 | 会话身份 |
| JA3 | `internal/engine/ja3/` | ✅ 实现 | JA3 指纹关联 |
| MemForensic | `internal/engine/memforensic/` | ✅ 实现 | 内存取证 |
| MemTrack | `internal/engine/memtrack/` | ✅ 实现 | 内存追踪 |
| ML | `internal/engine/ml/` | ✅ 实现 | 机器学习检测 |
| NetFinger | `internal/engine/netfinger/` | ✅ 实现 | 网络指纹 |
| NetMon | `internal/engine/netmon/` | ✅ 实现 | DNS/HTTP/Socket 监控 |
| Opt | `internal/engine/opt/` | ✅ 实现 | 热点路径/并行优化 |
| Predict | `internal/engine/predict/` | ✅ 实现 | ATT&CK 预测 |
| Probe | `internal/engine/probe/` | ✅ 实现 | 内核探测/kallsyms |
| Profile | `internal/engine/profile/` | ✅ 实现 | bpftool 性能画像 |
| Query | `internal/engine/query/` | ✅ 实现 | 查询引擎 |
| RateLimit | `internal/engine/ratelimit/` | ✅ 实现 | 速率限制 |
| Stream | `internal/engine/stream/` | ✅ 实现 | 流式处理/NFA |
| Syscall | `internal/engine/syscall/` | ✅ 实现 | 系统调用表 |
| Taint | `internal/engine/taint/` | ✅ 实现 | 污点传播引擎 |
| Viz | `internal/engine/viz/` | ✅ 实现 | 图可视化 |

### 2.9 公共库 (pkg)

| 组件 | 文件 | 状态 | 说明 |
|------|------|------|------|
| Anonymize | `pkg/anonymize/` | ✅ 实现 | 数据脱敏 |
| API | `pkg/api/` | ✅ 实现 | REST API + Dashboard + gRPC + Search + 控制面总览接口 |
| Archive | `pkg/archive/` | ✅ 实现 | 日志归档压缩 |
| Audit | `pkg/audit/` | ✅ 实现 | 审计日志框架（NDJSON 持久化） |
| Backup | `pkg/backup/` | ✅ 实现 | 存储备份/恢复 |
| CertAuth | `pkg/certauth/` | ✅ 实现 | 证书认证 |
| Client | `pkg/client/` | ✅ 实现 | API 客户端 |
| CLIOutput | `pkg/clioutput/` | ✅ 实现 | 格式化输出/表格 |
| Config | `pkg/config/` | ✅ 实现 | TOML 配置加载 |
| Diagnose | `pkg/diagnose/` | ✅ 实现 | 诊断包收集 |
| GenRules | `pkg/genrules/` | ✅ 实现 | Prometheus 规则生成 |
| HWAccel | `pkg/hwaccel/` | ✅ 实现 | GPU/NVMe/SmartNIC 检测 |
| I18n | `pkg/i18n/` | ✅ 实现 | 国际化支持 |
| LogX | `pkg/logx/` | ✅ 实现 | 结构化日志 |
| Metrics | `pkg/metrics/` | ✅ 实现 | Prometheus 指标 |
| Notify | `pkg/notify/` | ✅ 实现 | 通知（Email/Slack/Webhook）+ delivery 审计、失败重试、dead-letter 跟踪 |
| Plugin | `pkg/plugin/` | ✅ 实现 | 插件框架 + Sigma/ThreatIntel |
| Purge | `pkg/purge/` | ✅ 实现 | 数据清理 |
| Replay | `pkg/replay/` | ✅ 实现 | 事件回放 |
| Sanity | `pkg/sanity/` | ✅ 实现 | 启动自检 |
| Secure | `pkg/secure/` | ✅ 实现 | 加密/权限/Merkle/Signing |
| SupportBundle | `pkg/supportbundle/` | ✅ 实现 | 崩溃快照 |
| Telemetry | `pkg/telemetry/` | ✅ 实现 | 遥测上报 + agent summary reporter + 健康状态暴露 |
| Transport | `pkg/transport/` | ✅ 实现 | gRPC 传输/压缩 |
| Verify | `pkg/verify/` | ✅ 实现 | 存储一致性检查 |

### 2.10 CLI 工具

| 组件 | 文件 | 状态 | 说明 |
|------|------|------|------|
| providaptctl | `cmd/cli/providaptctl/main.go` | ✅ 实现 | 统一 CLI，20+ 子命令 |
| BPF inspect | `cmd/cli/providaptctl/bpf.go` | ✅ 实现 | eBPF 状态检查 |
| Verify | `cmd/cli/providaptctl/verify.go` | ✅ 实现 | 存储校验 |
| Audit | `cmd/cli/providaptctl/audit.go` | ✅ 实现 | 审计日志查询 |
| Dashboard | `cmd/cli/providaptctl/dashboard.go` | ✅ 实现 | 实时终端仪表盘 |
| Report | `cmd/cli/providaptctl/report.go` | ✅ 实现 | MITRE ATT&CK 报告 |
| Profile | `cmd/cli/providaptctl/profile.go` | ✅ 实现 | 性能画像 |
| Backup | `cmd/cli/providaptctl/backup.go` | ✅ 实现 | 备份/恢复 |
| Archive | `cmd/cli/providaptctl/archive.go` | ✅ 实现 | 归档管理 |
| Config | `cmd/cli/providaptctl/config.go` | ✅ 实现 | 配置检查 |
| GenRules | `cmd/cli/providaptctl/genrules.go` | ✅ 实现 | 规则生成 |
| Replay | `cmd/cli/providaptctl/replay.go` | ✅ 实现 | 事件回放 |
| CLI 测试 | `cmd/cli/providaptctl/main_test.go` | ✅ 实现 | 完整 CLI 测试 |
| providapt-verify | `cmd/cli/providapt-verify/` | ✅ 实现 | 独立校验工具 |
| providapt-deanon | `cmd/cli/providapt-deanon/` | ✅ 实现 | 去匿名化工具 |
| providapt-heal | `cmd/cli/providapt-heal/` | ✅ 实现 | 自愈恢复工具 |
| providapt-watchdog | `cmd/agent/watchdog/` | ✅ 实现 | 看门狗 |
| DSL | `cmd/cli/dsl/` | ✅ 实现 | 查询 DSL |
| Trace | `cmd/cli/trace/` | ✅ 实现 | 追踪工具 |

---

## 三、测试覆盖状态

### 3.1 单元测试

```
internal/  55 个包全部通过
pkg/       25 个包全部通过
```

### 3.2 Fuzz 测试

| Fuzz 函数 | 包 | 种子语料 | 状态 |
|-----------|-----|---------|------|
| FuzzParseRawEvent | internal/engine/collector | ✅ | ✅ |
| FuzzParseEdgeKey | internal/storage/schema | ✅ | ✅ |
| FuzzParseNodeKey | internal/storage/schema | ✅ | ✅ |
| FuzzConfigLoad | pkg/config | ✅ | ✅ |
| FuzzMatchTaint | internal/engine/taint | ✅ | ✅ |
| FuzzParseQuery | internal/engine/query | ✅ | ✅ |

### 3.3 集成测试

| 测试 | 文件 | 状态 |
|------|------|------|
| Archive | `test/integration/archive_test.go` | ✅ |
| Capture | `test/integration/capture_test.go` | ✅ |
| Container Trace | `test/integration/container_trace_test.go` | ✅ |
| Detect | `test/integration/detect_test.go` | ✅ |
| Dist | `test/integration/dist_test.go` | ✅ |
| GenRules | `test/integration/genrules_test.go` | ✅ |
| JA3 | `test/integration/ja3_test.go` | ✅ |
| Orchestration | `test/integration/orch_test.go` | ✅ |
| Replay | `test/integration/replay_test.go` | ✅ |
| Schema Store | `test/integration/schema_store_test.go` | ✅ |
| Server | `test/integration/server_test.go` | ✅ |
| Stitch | `test/integration/stitch_test.go` | ✅ |
| Store | `test/integration/store_test.go` | ✅ |
| Transport | `test/integration/transport_test.go` | ✅ |
| Verify | `test/integration/verify_test.go` | ✅ |
| Kernel Stress | `test/integration/kernel-test/stress_test.go` | ✅ |

### 3.4 负载测试

| 测试 | 文件 | 状态 |
|------|------|------|
| API 负载 | `test/load/api_load_test.go` | ✅ |
| Pipeline 基准 | `test/benchmark/pipeline_bench_test.go` | ✅ |
| 延迟测试 | `test/benchmark/latency_test.go` | ✅ |

---

## 四、测试结果（代码质量）

```
$ go vet ./cmd/... ./internal/... ./pkg/...   →  通过
$ go build ./cmd/cli/providaptctl/...          →  通过 (Linux)
$ make fmt                                     →  通过
```

### 已知测试缺口

| 包 | 说明 | 优先级 |
|---|------|--------|
| `internal/engine/loader` | 空测试文件（Linux build tag） | 高 |
| `internal/policy/response` | 无测试文件 | 中 |
| `internal/policy/mgmt` | 已有基础测试，Linux 专属路径仍需在 Linux runner 执行运行态校验 | 中 |
| `internal/engine/forensic` | 无测试文件（YARA 依赖） | 中 |
| `pkg/backup` | 无测试文件 | 低 |
| `internal/storage/pebblestore` | Lifecycle 测试跳过（Windows） | 中 |

---

## 五、基础设施

### 5.1 CI/CD

| 组件 | 状态 | 说明 |
|------|------|------|
| GitHub Actions lint | `.github/workflows/lint.yml` | ✅ |
| GitHub Actions release | `.github/workflows/release.yml` | ✅ |
| GoReleaser | `.goreleaser.yml` | ✅ |
| Dockerfile | `Dockerfile` | ✅ |
| Docker Compose | `docker-compose.yml` | ✅ |
| Pre-commit hooks | `.pre-commit-config.yaml` | ✅ |
| GolangCI Lint | `.golangci.yml` | ✅ |
| Verify cross-build | `scripts/verify-crossbuild.sh` | ✅ |

### 5.2 部署

| 组件 | 状态 | 说明 |
|------|------|------|
| Ansible | `deploy/ansible/` | ✅ 完整 playbook |
| Terraform | `deploy/terraform/` | ✅ 云部署（AWS） |
| Helm Chart | `deploy/helm/providapt/` | ✅ K8s 部署 |
| Prometheus | `deploy/terraform/templates/prometheus.yml.j2` | ✅ 监控模板 |
| OpenAPI | `openapi.yml` | ✅ REST API 规范 |

### 5.3 法律与文档

| 组件 | 状态 | 说明 |
|------|------|------|
| LICENSE | `LICENSE` | ✅ Apache 2.0 |
| EULA | `EULA.md` | ✅ |
| CLA | `CLA.md` | ✅ |
| DPA | `DPA.md` | ✅ 数据处理协议 |
| CODE_OF_CONDUCT | `CODE_OF_CONDUCT.md` | ✅ |
| SECURITY | `SECURITY.md` | ✅ |
| Issue/PR 模板 | `.github/` | ✅ 4 种模板 |

---

## 六、已知待完成工作

### 6.1 高优先级

| 任务 | 涉及文件 | 说明 |
|------|---------|------|
| **CO-RE 无对象文件场景优化** | `internal/engine/loader/bpf_loader.go` | 当前已支持 attach fallback，但 `.bpf.o` 缺失时仍会直接返回加载错误，可继续补充诊断与引导 |
| **Loader Linux 验证** | `internal/engine/loader/loader_test.go` | 纯逻辑测试已补齐，仍需在 Linux+bpf 环境补充真实 attach 验证 |
| **e2e 端到端测试** | 跨模块 | 需要 Linux 环境验证全流程 |

### 6.2 可优化项

| 任务 | 说明 |
|------|------|
| 遥测聚合与控制台可视化 | 基础 agent summary 上报、mgmt ingest、health 暴露、控制台多节点总览 MVP 已接通，并新增 Fleet 分组/标签基础能力与最近 Fleet 操作审计时间线 |
| Forensic 测试 | `internal/engine/forensic/` 无测试文件，YARA 规则需要维护 |
| gRPC mgmt 测试 | `internal/policy/mgmt/` 已补基础测试，仍需补 Linux 运行态与更完整集成校验 |
| 文档补充 | 架构设计文档、API 文档、部署文档 |
| Dashboard 完善 | `pkg/api/dashboard.go` + `dashboard.html` 已新增控制面总览 MVP、Fleet 过滤视图、角色感知展示、最近 Fleet 操作审计时间线、Support Bundle 导出入口、最新脱敏归档下载入口与最近导出状态、策略中心概览卡片、策略动作时间线、Alert Workflow 状态总览与工作流动作时间线，后续可继续补案件视图与更完整 Fleet 管理 |
| RBAC 最小集 | `pkg/api/` + `pkg/config/` | ✅ 实现 | Admin / Analyst / Auditor 三角色已接入 API Key 鉴权与控制面接口授权 |
| 策略中心 MVP | `internal/policy/mgmt/` + `pkg/api/` + `cmd/agent/daemon/` | ✅ 实现 | 已支持策略快照、草稿刷新、版本发布/回滚骨架、`/api/v1/control/policies`、控制台概览展示，以及 `actor/role` 注入与最近策略动作审计时间线 |
| 告警工作流 MVP | `pkg/alertflow/` + `pkg/api/` + `cmd/agent/daemon/` | ✅ 实现 | 已支持告警去重、静默、分派、关闭/重开、`/api/v1/control/alerts`、通知前 workflow gating，以及 `actor/role/note` 注入与最近工作流动作审计时间线 |
| 通知交付可靠性 | `pkg/notify/` + `pkg/api/` + `cmd/agent/daemon/` | ✅ 实现 | 已支持发送重试、delivery 审计、dead-letter 跟踪、`/api/v1/control/deliveries` 与控制台 Delivery Health 面板 |
| Dead-letter 重放 / 工单骨架 | `pkg/notify/` + `pkg/ticketing/` + `pkg/api/` + `cmd/agent/daemon/` | ✅ 实现 | 已支持单条/批量 dead-letter replay、单条/批量工单创建、`/api/v1/control/deliveries` 动作接口，以及 Jira / generic webhook / ServiceNow 工单创建骨架、基础幂等、控制台动作入口、最近操作审计时间线、工单评论回写，以及 `actor/role/note` 操作上下文；现支持 `api.auth_identities` 绑定可读操作者身份 |
| Support Bundle 控制面 | `pkg/supportbundle/` + `pkg/api/` + `cmd/agent/daemon/` | ✅ 实现 | 已支持 `GET/POST /api/v1/control/support`、稳定伪名化脱敏 zip 归档、`GET /api/v1/control/support/download` 受控下载、`GET /api/v1/control/audit` 查询持久化支持包审计、下载动作审计、长期 `pkg/audit/` 管理审计落盘、自动保留最近归档并清理旧文件、`PROVIDAPT_SUPPORT_RETAIN_ARCHIVES` / `PROVIDAPT_SUPPORT_REDACT_ARCHIVES` 配置覆盖、最近导出状态与路径回显、`actor/role/note` 注入、最近导出审计时间线，以及控制台导出/下载入口 |
| 许可证 / 升级控制面 MVP | `pkg/api/` + `cmd/agent/daemon/` + `pkg/config/` + `scripts/upgrade/` | ✅ 实现 | 已支持 `GET/POST /api/v1/control/license` 与 `GET/POST /api/v1/control/upgrade`、许可证文件存在性/大小/修改时间校验、可选 YAML/JSON 许可证元数据解析、到期时间与剩余天数计算、吊销列表与宽限期判断、远端吊销列表同步 + 本地缓存回退、吊销源签名校验与 `revocation_verified` 状态、公钥 `Ed25519` 与 HMAC 双模式许可证签名校验、升级包下载 URL / 本地路径双来源、`download` / `preflight` 控制面动作、升级包 SHA256 校验、公钥 `Ed25519` 与 HMAC 双模式升级签名文件校验、回滚计划/就绪状态、`scripts/upgrade/rollback-example.sh` 回滚脚本骨架、`PROVIDAPT_LICENSE_*` / `PROVIDAPT_UPGRADE_*` 配置覆盖、`actor/role/note` 注入、统一控制面审计时间线、长期 `pkg/audit/` 管理审计落盘，以及 Dashboard 上的 License & Upgrade 面板 |
| Audit 集成深化 | 更多模块接入 `pkg/audit/` 审计框架，并继续补敏感信息脱敏/留痕策略 |
| 文档检查与归类 | `docs/` + `README.md` | ✅ 实现 | 已新增 `docs/DOCUMENTATION_AUDIT.md`，按产品入口、法律/社区、用户文档、开发文档、流程模板进行归类，并补充推荐阅读路径；`README.md` 已添加文档归类入口 |

### 6.3 安全审计项

| 任务 | 说明 |
|------|------|
| K8s TLS 修复 | ✅ 已完成 — CA 证书验证替代 InsecureSkipVerify |
| Email TLS 验证 | ✅ 已完成 — 465 直连 TLS / 587 STARTTLS |
| 权限降级 | ✅ 已完成 — eBPF map pin 后 drop root |
| 存储加密 | ✅ 已完成 — AES-GCM + Merkle 树 |
| Supply Chain | ✅ 已完成 — SBOM 生成 + syft 集成 |
| 审计日志 | ✅ 已完成 — NDJSON 持久化 |

---

## 七、构建产物

| 二进制 | 来源 | 说明 |
|--------|------|------|
| `providaptd` | `cmd/agent/daemon` | 主守护进程 |
| `providaptctl` | `cmd/cli/providaptctl` | 统一管理 CLI |
| `providapt-watchdog` | `cmd/agent/watchdog` | 系统看门狗 |
| `providapt-verify` | `cmd/cli/providapt-verify` | 存储校验 |
| `providapt-deanon` | `cmd/cli/providapt-deanon` | 去匿名化 |
| `providapt-heal` | `cmd/cli/providapt-heal` | 自愈恢复 |

---

## 八、模块依赖关系示意图

```
                    ┌─────────────────────┐
                    │   eBPF Probes (C)   │  cmd/bpf/probes/
                    └─────────┬───────────┘
                              │ ringbuf
                    ┌─────────▼───────────┐
                    │   Collector         │  internal/engine/collector/
                    └─────────┬───────────┘
                              │ events
                    ┌─────────▼───────────┐
                    │  Pipeline           │  internal/engine/pipeline/
                    │  (merge/dedup/cache)│
                    └──┬──────────────┬───┘
                       │ hot nodes    │ cold edges
             ┌─────────▼───┐   ┌─────▼──────────┐
             │ LRU Cache   │   │  PebbleDB      │  internal/storage/
             └─────────┬───┘   └─────┬──────────┘
                       │             │
             ┌─────────▼─────────────▼───┐
             │   Provenance Graph        │  internal/engine/provenance/
             └─────────┬─────────────────┘
                       │ scan
             ┌─────────▼─────────────────┐
             │   Analyzer + Policy       │  internal/engine/analyzer/
             │   (Patterns/Sigma/Taint)  │  internal/policy/*/
             └─────────┬─────────────────┘
                       │ alerts
             ┌─────────▼─────────────────┐
             │   Alert/Notify/Audit      │  internal/policy/alert/
             │   (Email/Slack/Webhook)   │  pkg/notify/ + pkg/audit/
             └───────────────────────────┘
```

---

## 九、版本历史

| 版本 | 说明 |
|------|------|
| v1.0.0 | 完整代码仓库重构 — 标准 Go 项目布局 + 版本目录统一化 |
| v1.0.1 | 全量测试修复 — 所有测试用例通过 |
| v1.0.2 | 新增测试覆盖 + CI 路径修复 + providaptctl 增强 |
| v1.1.0 | 运维工具增强（diagnose/purge/sanity/notify/CLI 格式化） |
| dev (current) | 商业就绪：法律文档、CI/CD、IaC、SDK、遥测、i18n、eBPF Loader、AI Provider |

---

## 十、商业化推进计划

- 已新增 `COMMERCIALIZATION_ROADMAP.md`，用于收敛 P0 / P1 以及阶段 1-3 的商业化目标、执行顺序、验收标准与里程碑

- 2026-06-08: Cleaned release-facing documentation entry points (README.md, docs/developer/INDEX.md, docs/DOCUMENTATION_AUDIT.md) and refreshed release consistency guidance.

- 2026-06-08: Rewrote Chinese documentation index entry points (docs/getting-started/INDEX.md, docs/user-guide/INDEX.md, docs/architecture/INDEX.md, docs/benchmarks/INDEX.md, docs/compliance/INDEX.md) to clean UTF-8 for GA release review.

- 2026-06-08: Added docs/developer/release-notes-draft.md and rewrote CHANGELOG.md / docs/developer/changelog.md into clean release-oriented summaries for final release handoff.

- 2026-06-08: Updated GitHub Actions workflows for Node 24 compatibility (`actions/checkout@v5`, `actions/setup-go@v6`, `goreleaser/goreleaser-action@v7`, plus `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true`).

- 2026-06-08: Fixed `actions/setup-go@v6` cache restore failure by disabling cache in release workflow and pinning `cache-dependency-path` to `go.mod` / `go.sum` in CI workflows.
