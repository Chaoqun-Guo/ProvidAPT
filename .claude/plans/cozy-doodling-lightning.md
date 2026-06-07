# 集中化配置管理实现计划

## Context

产品缺少集中化配置管理能力：配置仅支持 JSON 格式（虽以 .toml 为后缀），无环境变量/CLI 标志覆盖；告警规则和白名单变更必须重启 daemon；无商业授权管理机制。本计划实现三项功能：
1. **多层级配置** — YAML 解析 + 环境变量覆盖 + daemon CLI 标志
2. **动态重载** — SIGHUP 信号触发配置热更新，联动 gRPC UpdatePolicy 真实操作
3. **License 管理** — RSA 签名授权校验，API 查询，CLI 展示

---

## Feature 1: Multi-level Config (`pkg/config/` + daemon CLI)

### 现有状况

- `pkg/config/config.go`: `Load(path)` 只读 JSON 文件，不支持 YAML
- `cmd/agent/daemon/main.go`: 硬编码配置路径 `"providapt.toml"`，无 CLI 标志
- 优先级：仅有文件默认值，无分层覆盖

### 改动

#### 1a. `pkg/config/config.go` — 新增 YAML 解析 + 环境变量覆盖

```go
// 新增导入: gopkg.in/yaml.v3, os, strconv, strings

// Load 扩展为: 先尝试 YAML 解析（保留兼容 JSON 格式）
// 然后应用环境变量覆盖:
//   PROVIDAPT_KERNEL_VERBOSE  → c.Kernel.Verbose
//   PROVIDAPT_OUTPUT_DIR     → c.Output.Dir
//   PROVIDAPT_CAPTURE_NET    → c.Capture.EnableNet
//   PROVIDAPT_API_REST       → c.API.REST
//   PROVIDAPT_STORAGE_ENCRYPT → c.Storage.Encrypt
// 环境变量命名规则: PROVIDAPT_{SECTION}_{KEY}
// bool/int/string 自动类型转换
```

具体修改:
1. `Load(path string)` 改为先用 `yaml.Unmarshal` 解析（兼容 JSON），保留原有 `json.Unmarshal` 作为 fallback
2. 新增 `applyEnvOverrides(cfg *Config)` — 遍历 Config 字段，按 `PROVIDAPT_` 前缀环境变量覆盖
3. 优先级：环境变量 > 配置文件 > `DefaultConfig()`

#### 1b. `cmd/agent/daemon/main.go` — 新增 CLI 标志

保留现有 `config.Load()` 调用，在 `main()` 开头新增 `flag` 解析:

```go
var configPath = flag.String("config", "providapt.toml", "Config file path")
var logLevel = flag.String("log-level", "", "Override log level (debug|info|warn|error)")
flag.Parse()
// 如果有 -log-level，设置环境变量让 logx 读取
```

### 涉及文件

| 文件 | 操作 |
|---|---|
| `pkg/config/config.go` | 新增 yaml 解析、环境变量覆盖函数 |
| `cmd/agent/daemon/main.go` | 新增 `-config`、`-log-level` flag |
| `go.mod` | 新增 `gopkg.in/yaml.v3` 依赖 |

---

## Feature 2: Dynamic Config Reload

### 现有状况

- **信号处理**: 只处理 SIGINT/SIGTERM，无 SIGHUP 处理
- **Analyzer**: `a.cfg` 是 `*Config` 指针，`scan()` 每次迭代读取 `a.cfg.EnablePatterns` — 原子替换即可热更新
- **Taint seeds**: `untrustedComms`, `networkTools`, `sensitivePaths` 是 `analyzer/taint.go` 中的包级全局 map，不可配置不可更新
- **Controller**: `ExcludePID()`/`UnExcludePID()`/`AddHotPath()`/`RemoveHotPath()` 已经是实时操作 eBPF map
- **gRPC UpdatePolicy**: handler 是空壳，只打日志
- **Analyzer Config** 未集成到主配置: `main.go` 中 `analyzer.DefaultConfig()` 硬编码创建

### 改动

#### 2a. SIGHUP 信号处理

`cmd/agent/daemon/main.go` 信号注册新增 SIGHUP:

```go
signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
```

在 `select` 的 `sig := <-sigCh` 分支中判断:

```go
if sig == syscall.SIGHUP {
    logx.System().Info("SIGHUP received, reloading config")
    // 1. 重新加载配置文件
    newCfg, err := config.Load(cfgPath)
    if err != nil {
        logx.System().Error("config reload failed", "error", err)
        continue
    }
    // 2. 热更新 analyzer 配置
    apt.ReloadConfig(analyzer.ConfigFromMainConfig(newCfg))
    // 3. 热更新 taint seeds
    apt.ReloadTaintSeeds(newCfg)
    // 4. 热更新 controller（PID whitelist、hot paths）
    if newCfg.Capture.ExcludePIDs != nil {
        // 通过 Controller 实时操作 eBPF map
    }
    // 5. 更新 pipeline 可热更新参数
    pipe.ReloadConfig(newCfg)
    continue // 不退出
}
```

注意: 需要让 pipeline 实例、controller 实例可被外层访问（当前 `main()` 局部变量）。在 main 函数中将这些变量提升为闭包可访问的局部变量即可。

#### 2b. Analyzer 热更新支持

`internal/engine/analyzer/analyzer.go` 新增:

```go
// ReloadConfig 原子替换 analyzer 配置（goroutine-safe）
func (a *Analyzer) ReloadConfig(cfg *Config) {
    a.cfg = cfg  // 指针原子替换，scan() 下次迭代即生效
}

// ReloadTaintSeeds 更新包级 taint 全局变量
// 在 analyze.go 中新增导出函数
func ReloadTaintSeeds(untrusted, network map[string]bool, sensitive []string) {
    // 加 sync.RWMutex 保护包级变量
}
```

taint.go 中的三个包级全局变量改为 `sync.RWMutex` 保护:

```go
var (
    untrustedMu    sync.RWMutex
    untrustedComms = map[string]bool{...}
    networkMu      sync.RWMutex
    networkTools   = map[string]bool{...}
    sensitiveMu    sync.RWMutex
    sensitivePaths = []string{...}
)
```

所有读取处加 RLock，`ReloadTaintSeeds` 加 Lock 全量替换。

#### 2c. Config 新增 analyzer/taint/controller 字段

`pkg/config/config.go` — `Config` 新增:

```go
type Config struct {
    // ... 现有字段 ...

    // Analyzer 配置
    Analyzer struct {
        ScanInterval       Duration `json:"scan_interval" yaml:"scan_interval"`
        DeepTaintThreshold int      `json:"deep_taint_threshold" yaml:"deep_taint_threshold"`
        EnablePatterns     []string `json:"enable_patterns" yaml:"enable_patterns"`
        Quiet              bool     `json:"quiet" yaml:"quiet"`
    } `json:"analyzer" yaml:"analyzer"`

    // Taint 种子配置（动态可重载）
    TaintSecrets struct {
        UntrustedComms  []string `json:"untrusted_comms" yaml:"untrusted_comms"`
        NetworkTools    []string `json:"network_tools" yaml:"network_tools"`
        SensitivePaths  []string `json:"sensitive_paths" yaml:"sensitive_paths"`
    } `json:"taint_secrets" yaml:"taint_secrets"`

    // 进程白名单（动态下发到 eBPF）
    Capture struct {
        // 现有字段 ...
        ExcludePIDs  []uint32 `json:"exclude_pids" yaml:"exclude_pids"`
        ExcludeComms []string `json:"exclude_comms" yaml:"exclude_comms"`
        HotPaths     []string `json:"hot_paths" yaml:"hot_paths"`
    }
}
```

新增 `config.ConfigToAnalyzerConfig(cfg *Config) *analyzer.Config` 转换函数。

#### 2d. gRPC UpdatePolicy 真实实现

`internal/policy/mgmt/server.go` — `UpdatePolicy` handler 调用真实操作:

```go
// Server 新增字段:
type Server struct {
    // ... 现有字段 ...
    analyzer  *analyzer.Analyzer
    ctrl      *control.Controller
    pipe      *pipeline.Pipeline
}

// UpdatePolicy handler 改为真实操作:
case *mgmtpb.PolicyUpdate_Whitelist:
    switch u.Whitelist.Target {
    case "pid":
        pidVal, _ := strconv.ParseUint(u.Whitelist.Value, 10, 32)
        switch u.Whitelist.Action {
        case "add":
            s.ctrl.ExcludePID(uint32(pidVal))
        case "remove":
            s.ctrl.UnExcludePID(uint32(pidVal))
        }
    case "path":
        switch u.Whitelist.Action {
        case "add":
            s.ctrl.AddHotPath(u.Whitelist.Value)
        case "remove":
            s.ctrl.RemoveHotPath(u.Whitelist.Value)
        case "clear":
            s.ctrl.ClearHotPaths()
        }
    }
case *mgmtpb.PolicyUpdate_TaintSource:
    // Reload taint seeds
```

`cmd/agent/daemon/main.go` 创建 mgmtServer 时传入 analyzer/ctrl/pipe:

```go
mgmtServer, err := mgmt.NewServer(mgmtCfg, analyzer, ctrl, pipe)
```

#### 2e. POST /api/v1/admin/reload API 端点

`pkg/api/api.go` — 新增管理端点，触发与 SIGHUP 相同的 reload 逻辑:

```go
// Server 新增:
type Server struct {
    // ...
    reloadFn func() error  // SIGHUP 相同逻辑
}

mux.HandleFunc("/api/v1/admin/reload", s.jsonHandler(s.handleReload))
```

`handleReload` 调用 `s.reloadFn()` 重新加载配置并热更新各组件。仅在 daemon 中注册 reloadFn。

### 涉及文件

| 文件 | 操作 |
|---|---|
| `cmd/agent/daemon/main.go` | 新增 SIGHUP 处理、Config 扩展字段解析 |
| `internal/engine/analyzer/analyzer.go` | 新增 `ReloadConfig()` |
| `internal/engine/analyzer/taint.go` | 包级变量加 RWMutex 保护、导出 `ReloadTaintSeeds()` |
| `pkg/config/config.go` | 新增 Analyzer/TaintSecrets/Capture 配置字段 |
| `internal/policy/mgmt/server.go` | 新增 analyzer/ctrl/pipe 引用，UpdatePolicy 真实实现 |
| `pkg/api/api.go` | 新增 `/api/v1/admin/reload` 端点 |
| `internal/engine/pipeline/pipeline.go` | 新增 `ReloadConfig(*Config)` |

---

## Feature 3: License Management (`pkg/license/`)

### 现有状况

无任何 license/activation 代码。`internal/version/version.go` 只有三个 ldflags。

### 改动

#### 3a. 新建 `pkg/license/license.go`

License 结构:

```go
package license

import (
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/base64"
    "encoding/json"
    "encoding/pem"
    "fmt"
    "time"
)

// License 授权许可
type License struct {
    Product      string `json:"product"`       // "ProvidAPT"
    Version      string `json:"version"`       // 授权版本
    Licensee     string `json:"licensee"`      // 被授权方
    Expiry       int64  `json:"expiry"`        // Unix 过期时间戳
    HardwareID   string `json:"hardware_id"`   // 机器绑定标识
    FeatureFlags int64  `json:"feature_flags"` // 功能位图
    IssuedAt     int64  `json:"issued_at"`
    Issuer       string `json:"issuer"`
}

type SignedLicense struct {
    License   License `json:"license"`
    Signature string  `json:"signature"` // base64(RSA-SHA256)
}
```

核心函数:

```go
// Generate 生成 RSA 签名的授权（管理端使用）
func Generate(privKey *rsa.PrivateKey, lic License) (string, error)

// Verify 验证 RSA 签名
func Verify(pubKey *rsa.PublicKey, token string) (*License, error)

// LoadFromFile 从文件加载并验证 license
func LoadFromFile(path string) (*License, error)

// IsExpired 检查是否过期
func (l *License) IsExpired() bool

// HardwareID 返回本机硬件标识（用于绑定验证）
func HardwareID() string

// LoadPublicKey 从 PEM 文件加载公钥
func LoadPublicKey(path string) (*rsa.PublicKey, error)
```

`HardwareID()` 实现: 读取 `/etc/machine-id`（Linux），若不存在则使用 `dmidecode -s system-uuid` 的哈希。跨平台 fallback 为 MAC 地址哈希。

#### 3b. API 集成

`pkg/api/api.go` 新增端点:

```
GET /api/v1/license → {"product":"ProvidAPT","licensee":"...","expiry":"...","expired":false,"days_remaining":365}
```

`cmd/agent/daemon/main.go` 中加载:

```go
// 可选: 如果配置指定了 license 文件路径
if cfg.License.Path != "" {
    lic, err := license.LoadFromFile(cfg.License.Path)
    if err != nil {
        logx.System().Warn("license load failed", "error", err)
    } else {
        if lic.IsExpired() {
            logx.System().Warn("license expired", "expiry", lic.Expiry)
        } else {
            logx.System().Info("license valid", "licensee", lic.Licensee, "expiry", lic.Expiry)
        }
        apiServer.SetLicense(lic) // API 展示
    }
}
```

`pkg/config/config.go` 新增:

```go
License struct {
    Path    string `json:"path" yaml:"path"`    // license 文件路径，可选
} `json:"license" yaml:"license"`
```

#### 3c. CLI 展示

`cmd/cli/providaptctl/main.go` 新增 `-license` 标志:

```
providaptctl -license → 显示授权信息（通过 API 查询或直接读取本地文件）
```

#### 3d. 构建注入公钥

`Makefile` LDFLAGS 新增注入公钥路径或编译时嵌入:

```go
// internal/version/version.go 增加
var PublicKeyPEM = "" // 可通过 ldflags 注入或编译时嵌入
```

### 涉及文件

| 文件 | 操作 |
|---|---|
| `pkg/license/license.go` | 新建 (RSA 签名、验证、hardware ID) |
| `pkg/license/license_test.go` | 新建 |
| `pkg/api/api.go` | 新增 `/api/v1/license` 端点 |
| `cmd/agent/daemon/main.go` | daemon 启动加载 license |
| `cmd/cli/providaptctl/main.go` | 新增 `-license` 标志 |
| `pkg/config/config.go` | 新增 License.Path 配置 |

---

## 验证步骤

1. `go build ./pkg/config/...` — 配置包编译
2. `go vet ./pkg/config/...` — 静态分析
3. `go test -count=1 ./pkg/config/...` — 配置测试
4. `go build ./pkg/license/...` — license 包编译
5. `go test -count=1 ./pkg/license/...` — license 生成/验证测试
6. `go vet ./internal/engine/analyzer/... ./internal/policy/mgmt/...` — 热更新组件静态分析
7. `go test -count=1 ./internal/engine/analyzer/...` — analyzer 回归测试
8. `go build ./cmd/agent/daemon/...` — daemon 编译（需 GOOS=linux）
9. `go build ./cmd/cli/providaptctl/...` — CLI 编译
