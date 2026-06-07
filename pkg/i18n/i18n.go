// Package i18n provides minimal internationalization for ProvidAPT.
//
// Supported locales: en (default), zh.
//
// Usage:
//
//	i18n.SetLocale("zh")
//	fmt.Println(i18n.T("daemon_running")) // → "守护进程运行中"
package i18n

import (
	"os"
	"sync"
)

var (
	mu     sync.RWMutex
	locale = "en"
	catalog = enUS
)

// SetLocale sets the active locale. Supported values: "en", "zh".
// Falls back to "en" for unknown locales.
func SetLocale(l string) {
	mu.Lock()
	defer mu.Unlock()

	switch l {
	case "en", "en_US", "en-US":
		locale = "en"
		catalog = enUS
	case "zh", "zh_CN", "zh-CN", "zh_Hans", "zh-Hans":
		locale = "zh"
		catalog = zhCN
	default:
		locale = "en"
		catalog = enUS
	}
}

// Locale returns the current locale code.
func Locale() string {
	mu.RLock()
	defer mu.RUnlock()
	return locale
}

// T returns the translated string for the given key.
// Falls back to the key itself if no translation is found.
func T(key string) string {
	return Targs(key)
}

// Targs returns the translated string, using fmt.Sprintf-style arguments.
func Targs(key string, args ...interface{}) string {
	mu.RLock()
	msg, ok := catalog[key]
	mu.RUnlock()
	if !ok {
		return key
	}
	if len(args) == 0 {
		return msg
	}
	return fmtString(msg, args...)
}

// InitFromEnv reads the PROVIDAPT_LOCALE env var and sets the locale.
func InitFromEnv() {
	if l := os.Getenv("PROVIDAPT_LOCALE"); l != "" {
		SetLocale(l)
	}
}

// localeMap is a message catalog.
type localeMap map[string]string

// English (default) catalog
var enUS = localeMap{
	"daemon_starting":      "ProvidAPT daemon starting",
	"daemon_started":       "ProvidAPT daemon started (PID %d)",
	"daemon_stopping":      "ProvidAPT daemon stopping",
	"daemon_stopped":       "ProvidAPT daemon stopped",
	"config_loading":       "Loading configuration from %s",
	"config_loaded":        "Configuration loaded",
	"config_invalid":       "Invalid configuration: %v",
	"bpf_loading":          "Loading eBPF programs",
	"bpf_loaded":           "eBPF programs loaded",
	"bpf_fallback":         "CO-RE load failed, falling back to kprobe",
	"api_listening":        "REST API listening on %s",
	"grpc_listening":       "gRPC API listening on %s",
	"tls_enabled":          "TLS enabled",
	"auth_enabled":         "API authentication enabled (%d key(s))",
	"rate_limit_enabled":   "Rate limiting enabled (%.0f req/s, burst %d)",
	"storage_opening":      "Opening storage at %s",
	"storage_opened":       "Storage opened",
	"storage_closed":       "Storage closed",
	"capture_started":      "Event capture started",
	"capture_stopped":      "Event capture stopped",
	"pipeline_started":     "Processing pipeline started",
	"pipeline_stopped":     "Processing pipeline stopped",
	"health_healthy":       "healthy",
	"health_unhealthy":     "unhealthy",
	"health_unknown":       "unknown",
	"purge_started":        "Data purge started (mode=%s)",
	"purge_completed":      "Data purge completed",
	"backup_started":       "Backup started",
	"backup_completed":     "Backup completed",
	"restore_warning":      "Stopping daemon before restore",
	"verify_started":       "Store verification started",
	"verify_completed":     "Store verification completed",
	"reload_triggered":     "Configuration reload triggered",
	"diagnose_collecting":  "Collecting diagnostic information",
	"diagnose_completed":   "Diagnostic bundle created: %s",
}

// Chinese (Simplified) catalog
var zhCN = localeMap{
	"daemon_starting":      "ProvidAPT 守护进程正在启动",
	"daemon_started":       "ProvidAPT 守护进程已启动（PID %d）",
	"daemon_stopping":      "ProvidAPT 守护进程正在停止",
	"daemon_stopped":       "ProvidAPT 守护进程已停止",
	"config_loading":       "正在加载配置：%s",
	"config_loaded":        "配置加载完成",
	"config_invalid":       "配置无效：%v",
	"bpf_loading":          "正在加载 eBPF 程序",
	"bpf_loaded":           "eBPF 程序加载完成",
	"bpf_fallback":         "CO-RE 加载失败，降级到 kprobe 模式",
	"api_listening":        "REST API 正在监听 %s",
	"grpc_listening":       "gRPC API 正在监听 %s",
	"tls_enabled":          "TLS 已启用",
	"auth_enabled":         "API 认证已启用（%d 个密钥）",
	"rate_limit_enabled":   "速率限制已启用（%.0f 请求/秒，突发 %d）",
	"storage_opening":      "正在打开存储：%s",
	"storage_opened":       "存储已打开",
	"storage_closed":       "存储已关闭",
	"capture_started":      "事件捕获已启动",
	"capture_stopped":      "事件捕获已停止",
	"pipeline_started":     "处理管道已启动",
	"pipeline_stopped":     "处理管道已停止",
	"health_healthy":       "健康",
	"health_unhealthy":     "不健康",
	"health_unknown":       "未知",
	"purge_started":        "数据清理已启动（模式=%s）",
	"purge_completed":      "数据清理已完成",
	"backup_started":       "备份已启动",
	"backup_completed":     "备份已完成",
	"restore_warning":      "恢复前正在停止守护进程",
	"verify_started":       "存储验证已启动",
	"verify_completed":     "存储验证已完成",
	"reload_triggered":     "配置重载已触发",
	"diagnose_collecting":  "正在收集诊断信息",
	"diagnose_completed":   "诊断包已创建：%s",
}
