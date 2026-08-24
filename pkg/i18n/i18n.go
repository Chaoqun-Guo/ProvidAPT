// Package i18n provides a small English message catalog for ProvidAPT.
//
// ProvidAPT currently ships product text in English only. Locale selection
// accepts common English locale aliases and falls back to English for all other
// values.
package i18n

import (
	"os"
	"sync"
)

var (
	mu      sync.RWMutex
	locale  = "en"
	catalog = enUS
)

// SetLocale sets the active locale. Supported values are "en", "en_US", and
// "en-US". Unknown values fall back to English.
func SetLocale(l string) {
	mu.Lock()
	defer mu.Unlock()

	switch l {
	case "en", "en_US", "en-US":
		locale = "en"
	default:
		locale = "en"
	}
	catalog = enUS
}

// Locale returns the current locale code.
func Locale() string {
	mu.RLock()
	defer mu.RUnlock()
	return locale
}

// T returns the message for the given key. It returns the key itself when no
// message is defined.
func T(key string) string {
	return Targs(key)
}

// Targs returns the message for the given key, using fmt.Sprintf-style
// arguments when provided.
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

// InitFromEnv reads PROVIDAPT_LOCALE and applies the supported locale policy.
func InitFromEnv() {
	if l := os.Getenv("PROVIDAPT_LOCALE"); l != "" {
		SetLocale(l)
	}
}

type localeMap map[string]string

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
	"control_plane_access": "open-source control plane access enabled",
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
