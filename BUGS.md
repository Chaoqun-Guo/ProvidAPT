# Bug 跟踪 / Bug Tracker

本文档记录 ProvidAPT 项目已发现、已修复和已知的 Bug。

> 每次 Bug 修复应同步更新本文档和 [CHANGELOG.md](CHANGELOG.md)。

---

## 状态说明 / Status Legend

| 状态 | 说明 |
|------|------|
| Open | 未修复 / Unresolved |
| In Progress | 修复中 / Fix in progress |
| Fixed | 已修复 / Resolved |
| Won't Fix | 不修复 / Intentional or deferred |
| Needs Triage | 待确认 / Requires investigation |

---

## 已修复 Bug / Fixed Bugs

### BUG-001: HMAC 加密密钥未持久化

- **状态**: Fixed
- **发现日期**: 2026-05-29
- **修复日期**: 2026-05-29
- **组件**: `pkg/secure/merkle.go`
- **严重度**: High
- **描述**: Merkle 树的 HMAC 密钥仅内存生成，重启后丢失，导致重启前后签名链断裂。
- **根因**: `NewMerkleAnchoring` 使用固定测试密钥 `bytes.Repeat([]byte{0x01}, 32)`，无持久化机制。
- **修复**: 添加 `LoadOrGenerateHMACKey(keyPath string, keySize int)` 方法，自动检测密钥文件存在性，不存在时生成新密钥并原子写入（tmp+rename, 0600 权限）。默认路径 `$PROVIDAPT_DATA_DIR/keys/hmac.key` 或 `/var/lib/providapt/keys/hmac.key`。
- **验证**: `go test ./pkg/secure/` — 全部 18 个测试通过。

### BUG-002: CredTracker 死锁 — 重入锁导致 AddEvent 阻塞

- **状态**: Fixed
- **发现日期**: 2026-05-29
- **修复日期**: 2026-05-29
- **组件**: `internal/engine/provenance/credential.go`
- **严重度**: Critical
- **描述**: `CredTracker.OnExec` 调用 `graph.mu.Lock()` 申请写锁，但调用者 `AddEvent` 已持有同一锁，`sync.RWMutex` 非可重入导致死锁。
- **根因**: `OnExec(evt, ts, graph *Graph)` 接受 `*Graph` 参数并直接操作其 `nodes` 和 `addEdge`，但调用路径 `AddEvent → addExec → OnExec` 全程持有 graph 锁，`OnExec` 内再次 Lock() 造成死锁。
- **修复**: 将 `OnExec` 签名改为 `OnExec(evt, ts) (credID string, prevUID uint32)`，移除 `*Graph` 参数，返回凭证变更信息由调用方 `addExec` 在已持有的锁内创建节点和边。
- **验证**: `TestGraphExecWithSetuidCreatesCredential` 测试通过（修复前超时），`go test ./internal/engine/provenance/` 无回归。

### BUG-003: exec 后进程节点标签未更新

- **状态**: Fixed
- **发现日期**: 2026-05-29
- **修复日期**: 2026-05-29
- **组件**: `internal/engine/provenance/graph.go`
- **严重度**: Medium
- **描述**: Fork 创建的子进程节点持有父进程的 `comm` 作为标签，exec 后节点 label 未更新，图谱中显示为父进程名。
- **根因**: `addExec` 中 `proc := g.getOrCreateNode(...)` 返回已有节点后未修改 `proc.Label`。
- **修复**: `addExec` 中添加 `proc.Label = evt.Comm`。
- **验证**: 图谱可视化中 exec 后节点显示正确的二进制名。

### BUG-004: 模式匹配器仅遍历出边，漏检 fork 子节点

- **状态**: Fixed
- **发现日期**: 2026-05-29
- **修复日期**: 2026-05-29
- **组件**: `internal/policy/alert/matcher.go`
- **严重度**: High
- **描述**: `tracePath` 仅检查出边（`e.Source == nodeID`），但 fork 事件生成 `wasInformedBy(child→parent)` 边方向为子→父，从父节点跟踪时无法到达子节点。
- **根因**: 溯源图边方向是固定的 PROV 语义方向，模式匹配器需要双向遍历能力以支持父子关系检测。
- **修复**: `tracePath` 增加入边检查（`e.Target == nodeID`），当出边不满足时跳转至 `incoming` 分支继续匹配入边。
- **验证**: `TestE2E_LinearChainDetection` 测试通过，完整覆盖 fork → exec → 文件操作的链式检测。

### BUG-005: Windows 路径兼容性 — 反斜杠导致路径匹配失败

- **状态**: Fixed
- **发现日期**: 2026-05-29
- **修复日期**: 2026-05-29
- **组件**: `internal/policy/v22/supplychain/monitor.go`
- **严重度**: Medium
- **描述**: Windows 上 `filepath.Dir()` 返回反斜杠分隔路径，与包名提取逻辑不兼容。
- **修复**: 添加 `filepath.ToSlash()` 路径归一化处理。
- **验证**: Windows 环境供应链监控功能正常。

### BUG-006: SPDX 导入空记录导致下游 panic

- **状态**: Fixed
- **发现日期**: 2026-05-29
- **修复日期**: 2026-05-29
- **组件**: `internal/policy/v22/supplychain/sbom.go`
- **严重度**: High
- **描述**: `ImportSPDX()` 处理 SPDX 文件时未校验 `SPDXID` 空值，下游代码对空 ID 进行 map 操作时引发 panic。
- **修复**: 添加 SPDXID 空值校验，跳过空记录。
- **验证**: 导入含空 ID 的 SPDX 文件不再 panic。

### BUG-007: sbom.go ResolveByPath 无限循环

- **状态**: Fixed
- **发现日期**: 2026-05-29
- **修复日期**: 2026-05-29
- **组件**: `internal/policy/v22/supplychain/sbom.go`
- **严重度**: Critical
- **描述**: `ResolveByPath()` 循环条件 `for dir != "." && dir != "/"` 在 Windows 上因 `filepath.Dir("/")` 返回 `"/"` 导致死循环。
- **修复**: 改为 `for { parent := filepath.Dir(dir); if parent == dir { break } }` 结构。
- **验证**: Windows 环境 `ResolveByPath` 正常返回。

### BUG-008: 非可信写入严重度校正

- **状态**: Fixed
- **发现日期**: 2026-05-29
- **修复日期**: 2026-05-29
- **组件**: `internal/policy/v22/supplychain/detector.go`
- **严重度**: Medium
- **描述**: 非可信来源的写入操作严重度仅标记为 `"HIGH"`，与实际风险不匹配。
- **修复**: 提升至 `"CRITICAL"`。
- **验证**: 告警输出严重度正确。

### BUG-009: 测试断言范围错误

- **状态**: Fixed
- **发现日期**: 2026-05-29
- **修复日期**: 2026-05-29
- **组件**: `internal/stitcher/graphsketch/sketch_test.go`
- **严重度**: Low
- **描述**: `TestEntropyBaselineUpdate` 断言范围 `0.4-0.6` 与 EMA 公式计算值 `0.75` 不匹配。
- **修复**: 断言范围修正为 `0.65-0.85`。
- **验证**: `go test ./internal/stitcher/graphsketch/` 通过。

### BUG-010: graph.go sed 操作导致文件损坏

- **状态**: Fixed
- **发现日期**: 2026-05-30
- **修复日期**: 2026-05-30
- **组件**: `internal/engine/provenance/graph.go`
- **严重度**: High
- **描述**: 多次 sed 操作在 AddEvent 函数的 metrics 代码段中残留 `t}` 字符和多余闭合大括号，导致编译错误 `non-declaration statement outside function body`。
- **根因**: Windows 环境下 sed 插入文本时 `\t` 转义符被解释为字面字符 `t` 而非制表符。
- **修复**: 使用 `sed -i '94s/t}/}/'` 和 `sed -i '99d'` 清除残留字符。
- **验证**: `go build ./internal/engine/provenance/` 通过。

---

## 已知 Bug / Known Issues

### BUG-011: TestGraphReadTargetsLatest 断言失败

- **状态**: Needs Triage
- **发现日期**: 2026-05-30
- **组件**: `internal/engine/provenance/camflow_test.go:170`
- **严重度**: Low
- **描述**: 测试期望读操作 `used` 边指向文件版本 `v1`，但当前行为可能指向 `v0`（初始版本）。可能为版本追踪逻辑变更后的测试期望值未更新。
- **备注**: 在代码重构前即存在，非本次回归引入。

### BUG-012: TestGraphAddFileWrite 断言失败

- **状态**: Needs Triage
- **发现日期**: 2026-05-30
- **组件**: `internal/engine/provenance/graph_test.go:156`
- **严重度**: Low
- **描述**: 测试期望写入操作产生 1 条边，但实际产生 2 条（含 `wasDerivedFrom` 版本链接边）。可能为版本追踪功能引入后测试未更新。
- **备注**: 在代码重构前即存在，非本次回归引入。

### BUG-013: TestGraphDeduplicateNodes 断言失败

- **状态**: Needs Triage
- **发现日期**: 2026-05-30
- **组件**: `internal/engine/provenance/graph_test.go:180`
- **严重度**: Low
- **描述**: 测试期望 3 节点 + 2 边（去重进程），实际得到 2 节点 + 1 边。
- **备注**: 在代码重构前即存在，非本次回归引入。

### BUG-014: TestGraphMultipleTypes 断言失败

- **状态**: Needs Triage
- **发现日期**: 2026-05-30
- **组件**: `internal/engine/provenance/graph_test.go:221`
- **严重度**: Low
- **描述**: 测试期望 5 节点 + 4 边，实际少 1 节点和 1 边。
- **备注**: 在代码重构前即存在，非本次回归引入。

---

## 待办改进 / Pending Improvements

| ID | 描述 | 优先级 | 备注 |
|----|------|--------|------|
| TODO-001 | 解析 UID → /etc/passwd 用户名（惰性查询+缓存） | Low | `internal/engine/collector/event_parser.go:8` |
| TODO-002 | 从 /proc/\<pid\>/exe 解析二进制路径 | Low | `internal/engine/collector/event_parser.go:9` |
| TODO-003 | IP 地址 → 主机名解析（可选，速率限制） | Low | `internal/engine/collector/event_parser.go:10` |
| TODO-004 | 验证集成测试输出包含文件打开事件 | Medium | `test/integration/capture_test.go:36` |

---

## Bug 修复统计 / Fix Statistics

| 指标 | 值 |
|------|----|
| 已修复总数 | 10 |
| Open 待确认 | 4 |
| Critical | 2 |
| High | 3 |
| Medium | 4 |
| Low | 5 |

> 最后更新: 2026-05-30
