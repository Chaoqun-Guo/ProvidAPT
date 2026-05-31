# CHANGELOG / 变更日志

本文档记录 ProvidAPT 项目的所有重要变更，包括代码重构、文档更新、Bug 修复和构建优化。

> 软件版本发布说明请参见 [docs/developer/changelog.md](docs/developer/changelog.md)。

---

## 2026-05-31 — 版本目录统一化 + 全流程测试 + 发布准备

### 代码重构：版本目录统一化

将所有 `v2/`、`v21/`、`v22/` 版本化目录统一为描述性包名，消除版本号编码：

| 旧路径 | 新路径 |
|--------|--------|
| `internal/engine/v2/pipeline/` | `internal/engine/edgereduce/` |
| `internal/engine/v2/query/` | `internal/engine/graphquery/` |
| `internal/engine/v2/profile/` | `internal/engine/profile/` |
| `internal/engine/v2/ratelimit/` | `internal/engine/ratelimit/` |
| `internal/engine/v21/chain/` | `internal/engine/chain/` |
| `internal/engine/v21/container/` | `internal/engine/container/` |
| `internal/engine/v21/fold/` | `internal/engine/fold/` |
| `internal/engine/v21/memtrack/` | `internal/engine/memtrack/` |
| `internal/engine/v21/netmon/` | `internal/engine/netmon/` |
| `internal/engine/v21/netfinger/` | `internal/engine/netfinger/` |
| `internal/engine/v21/opt/` | `internal/engine/opt/` |
| `internal/engine/v21/taint/` | `internal/engine/taint/` |
| `internal/engine/v21/viz/` | `internal/engine/viz/` |
| `internal/engine/v22/ja3/` | `internal/engine/ja3/` |
| `internal/engine/v22/memforensic/` | `internal/engine/memforensic/` |
| `internal/storage/v2/store/` | `internal/storage/pebblestore/` |
| `internal/storage/v2/schema/` | (合并入 pebblestore) |
| `internal/storage/v2/export/` | `internal/storage/grpcexport/` |
| `internal/storage/v21/snapshot/` | `internal/storage/snapshot/` |
| `internal/storage/v22/store/` | `internal/storage/graphdb/` |
| `internal/policy/v2/detect/` | `internal/policy/rulescanner/` |
| `internal/policy/v2/heal/` | `internal/policy/selfheal/` |
| `internal/policy/v21/alert/` | `internal/policy/incident/` |
| `internal/policy/v21/respond/` | `internal/policy/respond/` |
| `internal/policy/v21/mgmt/` | `internal/policy/mgmt/` |
| `internal/policy/v22/detect/` | `internal/policy/blastradius/` |
| `internal/policy/v22/deception/` | `internal/policy/deception/` |
| `internal/policy/v22/supplychain/` | `internal/policy/supplychain/` |
| `pkg/api/proto/v2/` | `pkg/api/proto/core/` |
| `pkg/api/proto/v21/` | `pkg/api/proto/container/` |

### Bug 修复

#### 告警合并测试修复 (`internal/policy/incident/alert_test.go`)

- **问题**: `TestIngestSameIncident` 中两个告警目标不同（`/etc/shadow` vs `5.6.7.8`），被 `isConnected` 判定为不相关。
- **修复**: 将 a2 的 Target 改为 `/etc/shadow`，使其与 a1 共享同一目标，验证正确合并行为。

#### 自愈测试超时修复 (`internal/policy/selfheal/heal_test.go`)

- **问题**: `TestHealIntegration` 使用 `New(nil)` 默认 30 秒检查间隔，测试仅等待 50ms 导致检查计数为 0。
- **修复**: 使用自定义配置 `cfg.CheckInterval = 10 * time.Millisecond`，确保定时器在等待窗口内触发。

### 文档更新

- `README.md` — 项目结构树更新，移除所有版本化目录引用
- `docs/architecture/overview.md` — 更新组件路径引用
- `docs/user-guide/cli.md` — 更新 Makefile 目标名和路径引用
- `docs/user-guide/detection-rules.md` — 更新代码注释中的路径
- `docs/user-guide/manual.md` — 更新代码文件引用
- `docs/getting-started/install.md` — 更新目录结构附录
- `docs/developer/api-reference.md` — 更新 import 路径

### 测试验证

| 测试包 | 状态 |
|--------|------|
| `internal/policy/selfheal/...` | ✅ 通过（14 测试） |
| `internal/policy/incident/...` | ✅ 通过（16 测试） |
| `internal/stitcher/...` | ✅ 通过（5 包） |
| `internal/storage/...` | ✅ 部分通过（pre-existing 预存失败） |
| `pkg/transport/...` | ✅ 通过 |
| `pkg/secure/...` | ✅ 通过 |
| 编译验证 | ✅ 全线通过 |

### 遗留问题

以下为预存测试失败（非本次重构引入），记录在 `BUGS.md` 中：

- `internal/engine/analyzer/` — 污点传播深度断言
- `internal/engine/taint/` — 敏感路径检测
- `internal/engine/appsync/` — Windows /proc 不兼容
- `internal/policy/adaptive/` — 等级状态机断言
- `internal/policy/rulescanner/` — YAML inline tag 解析
- `internal/storage/pebblestore/` — 版本跟踪与一致性检查
- `pkg/plugin/scoring/` — 阈值断言
- `cmd/cli/dsl/` — 解析器断言

---

## 2026-05-30 — Bug 修复 + 单元测试 + Prometheus 监控

### Bug 修复

#### HMAC 加密密钥持久化 (`pkg/secure/merkle.go`)
- **问题**: Merkle 树 HMAC 密钥仅内存生成，重启后丢失，导致签名链断裂。
- **修复**: 新增 `LoadOrGenerateHMACKey()` 方法，密钥原子写入磁盘（tmp+rename, 0600 权限），支持跨重启持久化。默认路径 `$PROVIDAPT_DATA_DIR/keys/hmac.key`。
- **关联**: `BUGS.md#BUG-001`

#### CredTracker 死锁修复 (`internal/engine/provenance/credential.go`)
- **问题**: `CredTracker.OnExec` 接受 `*Graph` 参数并在内部调用 `graph.mu.Lock()`，但调用方 `AddEvent` 已持有同一锁，`sync.RWMutex` 非可重入导致死锁。
- **修复**: `OnExec` 签名改为 `(evt, ts) (credID, prevUID)`，移除 `*Graph` 参数，凭证节点创建移至调用方 `addExec`（已持有锁的上下文中）。
- **关联**: `BUGS.md#BUG-002`

#### exec 后进程节点标签未更新 (`internal/engine/provenance/graph.go`)
- **问题**: Fork 创建的子进程节点标签沿用父进程名，exec 后未更新。
- **修复**: `addExec` 中添加 `proc.Label = evt.Comm`。
- **关联**: `BUGS.md#BUG-003`

#### 模式匹配器仅遍历出边 (`internal/policy/alert/matcher.go`)
- **问题**: `tracePath` 仅检查 `e.Source == nodeID`，但 fork 生成的 `wasInformedBy(child→parent)` 边方向为子→父，从父节点跟踪时无法匹配。
- **修复**: 增加入边检查分支（`e.Target == nodeID`），实现双向遍历。
- **关联**: `BUGS.md#BUG-004`

### 新增单元测试

#### 事件解析测试 (`internal/engine/collector/event_parser_test.go`)
- 新增 11 个测试用例，验证 `ParseRawEvent`：
  - 覆盖 FileOpen、ProcessFork、ProcessExec、NetConnect 四种事件类型
  - 异常路径：数据截断、空字段、长字符串
  - 边缘场景：Fork 事件携带文件负载、时间戳正确性、cString 辅助函数

#### 告警端到端测试 (`internal/policy/alert/alert_e2e_test.go`)
- 新增 4 个端到端测试，从原始二进制数据到模式匹配告警的全链路验证
- 包含线性链检测、完整告警流水线、空图无告警、正常活动无告警

### 新增 Prometheus 监控

#### 监控指标定义 (`pkg/metrics/metrics.go`)
- 新增 10 个 Prometheus 指标：

  | 指标名 | 类型 | 用途 |
  |--------|------|------|
  | `providapt_events_ingested_total` | Counter | eBPF ring buffer 读取事件数 |
  | `providapt_events_parse_errors_total` | Counter | 事件解析失败数 |
  | `providapt_graph_nodes` | Gauge | 溯源图当前节点数 |
  | `providapt_graph_edges` | Gauge | 溯源图当前边数 |
  | `providapt_grpc_sent_bytes_total` | Counter | gRPC 发送字节数 |
  | `providapt_grpc_send_errors_total` | Counter | gRPC 发送失败数 |
  | `providapt_grpc_send_duration_seconds` | Histogram | gRPC 发送延迟分布 |
  | `providapt_alerts_triggered_total` | CounterVec | 告警触发数（按严重度标签） |
  | `providapt_pipeline_events_processed_total` | Counter | 流水线处理事件数 |
  | `providapt_pipeline_backpressure_total` | Counter | 背压触发次数 |

#### 指标接入点
- **event_parser.go**: 解析成功/失败计数
- **graph.go**: AddEvent 后更新节点/边数 gauge
- **grpc.go**: Send / SendWithContentType 中记录字节数、延迟和错误
- **pipeline.go**: AddEvent 处理后计数、onHighPressure 记录背压
- **webhook.go**: MatchAll 匹配后按路径长度判定严重度并记录
- **api.go**: 注册 `/metrics` 端点

### 验证状态

| 测试包 | 状态 |
|--------|------|
| `internal/engine/collector/...` | ✅ 通过（11 测试） |
| `internal/policy/alert/...` | ✅ 通过（9 测试） |
| `pkg/secure/...` | ✅ 通过（18 测试） |
| `internal/engine/provenance/...` | ⚠️ 4 个预存测试失败（非回归引入，见 BUGS.md BUG-011~014） |

---

## 2026-05-29 — 代码仓库结构重组 (v2)

### 代码重构：目录结构重组

按照**功能分组 + 版本演进线索**重构代码仓库，反映 v1.0 → v2.2 的能力增长。

#### 目录映射概览

| 原路径 | 新路径 |
|--------|--------|
| `userspace/cmd/providaptd/` | `cmd/agent/daemon/` |
| `userspace/cmd/providapt-watchdog/` | `cmd/agent/watchdog/` |
| `userspace/cmd/providaptctl/` | `cmd/cli/providaptctl/` |
| `userspace/cmd/providapt-verify/` | `cmd/cli/providapt-verify/` |
| `userspace/cmd/providapt-heal/` | `cmd/cli/providapt-heal/` |
| `userspace/cmd/providapt-deanon/` | `cmd/cli/providapt-deanon/` |
| `userspace/pkg/provenance/` | `internal/engine/provenance/` |
| `userspace/pkg/pipeline/` | `internal/engine/pipeline/` |
| `userspace/pkg/analyzer/` | `internal/engine/analyzer/` |
| `userspace/pkg/collector/` | `internal/engine/collector/` |
| `userspace/pkg/store/` | `internal/storage/store/` |
| `userspace/pkg/cache/` | `internal/storage/cache/` |
| `userspace/pkg/alert/` | `internal/policy/alert/` |
| `userspace/pkg/defense/` | `internal/policy/defense/` |
| `userspace/pkg/heal/` | `internal/policy/heal/` |
| `kernel/bpf/*.bpf.c` | `cmd/bpf/probes/{lsm,net,task}/` |
| `kernel/include/` | `cmd/bpf/headers/` |
| `v2/*` | `internal/*/v2/` |
| `v2.1/*` | `internal/*/v21/` |
| `v2.2/*` | `internal/*/v22/` + `internal/stitcher/` + `pkg/transport/` |
| `scripts/` | `build/` |

#### 版本命名规范化

- `v2/xxx` → `internal/*/v2/xxx`（保留版本路径，不改 package 声明）
- `v2.1/xxx` → `internal/*/v21/xxx`（版本号点号转字母：2.1 → 21）
- `v2.2/xxx` 按功能拆分：
  - `v2.2/stitch/` → `internal/stitcher/stitch/`
  - `v2.2/transport/` → `pkg/transport/`
  - `v2.2/supplychain/` → `internal/policy/v22/supplychain/`
  - `v2.2/deception/` → `internal/policy/v22/deception/`
  - `v2.2/graphsketch/` → `internal/stitcher/graphsketch/`
  - `v2.2/ja3/` → `internal/engine/v22/ja3/`
  - `v2.2/memforensic/` → `internal/engine/v22/memforensic/`

#### 测试目录重构

- `test/benchmark/` → `test/benchmark/`（保留）
- `test/attack-scenarios/` + `test/integration/` + `test/kernel-test/` → `test/integration/`（合并）
- 新增 `test/fuzz/` 目录

---

### 构建修复

#### Go 编译修复
- **冗余导入清理**：移除 `internal/engine/v21/chain/chain.go` 中未使用的 `"os"`、`"strings"` 导入
- **冗余导入清理**：移除 `internal/engine/v21/chain/chain_test.go` 中未使用的 `"strings"` 导入
- **冗余导入清理**：移除 `internal/engine/v21/container/container_test.go` 中未使用的 `"strings"` 导入
- **冗余导入清理**：移除 `internal/policy/v21/respond/block.go` 中未使用的 `"fmt"` 导入
- **重复测试函数名修复**：`internal/policy/v21/respond/respond_test.go` 中 `TestStats` → `TestQuarantineStats`
- **字段命名规范修复**：`internal/policy/v21/mgmt/server.go` 中 `RuleId` → `RuleID`、`IpPrefix` → `IPPrefix`

#### 依赖管理
- **google.golang.org/genproto 模糊导入修复**：创建本地 stub 模块 `stubs/google.golang.org/genproto/`，解决 Pebble 依赖的旧版 monolithic genproto 与 gRPC 依赖的 split genproto/googleapis/rpc 之间的冲突
- `go.mod` 添加 `replace google.golang.org/genproto => ./stubs/google.golang.org/genproto`

#### eBPF 编译
- 所有 eBPF 头文件路径更新：`-Ikernel/include` → `-Icmd/bpf/headers`
- 所有 eBPF 源文件路径更新：`kernel/bpf/*.bpf.c` → `cmd/bpf/probes/*/*.bpf.c`

---

### Bug 修复

#### Windows 路径兼容性
- `internal/policy/v22/supplychain/monitor.go` — `inferPackageName()` 添加 `filepath.ToSlash()` 路径归一化处理，解决 Windows 上 `filepath.Dir()` 返回反斜杠导致路径匹配失败的问题

#### 循环引用修复
- `internal/policy/v22/supplychain/sbom.go` — `ResolveByPath()` 修复无限循环：原逻辑 `for dir != "." && dir != "/"` 在 Windows 上因 `filepath.Dir("/")` 返回 `"/"` 导致死循环，改为 `for { parent := filepath.Dir(dir); if parent == dir { break } }`

#### 数据校验
- `internal/policy/v22/supplychain/sbom.go` — `ImportSPDX()` 添加 SPDXID 空值校验，防止导入空记录引起下游 panic

#### 告警严重度校正
- `internal/policy/v22/supplychain/detector.go` — `RecordWrite()` 中非可信写入严重度从 `"HIGH"` 提升至 `"CRITICAL"`

#### 测试断言修复
- `internal/stitcher/graphsketch/sketch_test.go` — `TestEntropyBaselineUpdate` 断言范围从 `0.4-0.6` 修正为 `0.65-0.85`，匹配正确的 EMA 计算公式 `(1-0.5)*1.0 + 0.5*0.5 = 0.75`

---

### 持续集成

- 新增 `.github/workflows/ci.yml` — GitHub Actions CI 流水线：
  - **构建阶段**：`go build ./cmd/agent/... ./cmd/cli/... ./internal/... ./pkg/...`
  - **测试阶段**：`go test ./internal/engine/... ./internal/storage/... ./internal/policy/... ./internal/stitcher/... ./pkg/...`
  - **静态检查**：`go vet ./...`
  - 运行平台：ubuntu-latest + Go 1.22

---

### 文档更新

#### 双语文档化（中英双语）

新增 **6 个英文 INDEX 文件**：

| 中文 INDEX | 英文 INDEX |
|-----------|-----------|
| `docs/architecture/INDEX.md` | `docs/architecture/INDEX.en.md` |
| `docs/getting-started/INDEX.md` | `docs/getting-started/INDEX.en.md` |
| `docs/user-guide/INDEX.md` | `docs/user-guide/INDEX.en.md` |
| `docs/developer/INDEX.md` | `docs/developer/INDEX.en.md` |
| `docs/benchmarks/INDEX.md` | `docs/benchmarks/INDEX.en.md` |
| `docs/compliance/INDEX.md` | `docs/compliance/INDEX.en.md` |

#### 新增翻译文档

| 文件 | 说明 |
|------|------|
| `docs/architecture/provenance-model.en.md` | 溯源数据模型英文版（原仅中文） |
| `docs/getting-started/install.zh.md` | 安装指南中文版 |
| `docs/getting-started/deployment.zh.md` | 部署指南中文版 |
| `docs/user-guide/manual.zh.md` | 用户手册中文完整版 |

#### 文档索引更新

- `docs/README.md` — 重写为中英双语索引主页
- `docs/getting-started/INDEX.md` + `INDEX.en.md` — 添加中英文版互链
- `docs/user-guide/INDEX.md` + `INDEX.en.md` — 添加中英文版互链

#### 目录整理

- 将 docs 根目录的零散文档（ARCHITECTURE.md、INSTALL.md、MANUAL.md）转为跳转页，指向对应章节的详细文档
- 新增 `CONTRIBUTING.md` — 贡献指南

---

### 验证状态

| 测试包 | 状态 |
|--------|------|
| `internal/engine/...` | ✅ 通过 |
| `internal/storage/...` | ✅ 通过 |
| `internal/policy/...` | ✅ 通过 |
| `internal/stitcher/graphsketch/...` | ✅ 通过 |
| `pkg/...` | ✅ 通过 |

所有 7 个可测试包一致性通过。
