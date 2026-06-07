// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds all ProvidAPT configuration.
type Config struct {
	Kernel struct {
		Verbose bool     `json:"verbose" yaml:"verbose"`
		Hooks   []string `json:"hooks" yaml:"hooks"`
	} `json:"kernel" yaml:"kernel"`

	Output struct {
		Dir    string `json:"dir" yaml:"dir"`
		Format string `json:"format" yaml:"format"`
	} `json:"output" yaml:"output"`

	Log struct {
		Level  string `json:"level" yaml:"level"`
		Format string `json:"format" yaml:"format"`
	} `json:"log" yaml:"log"`

	Capture struct {
		MaxEvents    int      `json:"max_events" yaml:"max_events"`
		EnableNet    bool     `json:"enable_net" yaml:"enable_net"`
		EnableFile   bool     `json:"enable_file" yaml:"enable_file"`
		EnableProc   bool     `json:"enable_proc" yaml:"enable_proc"`
		SensitiveDir bool     `json:"sensitive_dir" yaml:"sensitive_dir"`
		ExcludePIDs  []uint32 `json:"exclude_pids" yaml:"exclude_pids"`
		ExcludeComms []string `json:"exclude_comms" yaml:"exclude_comms"`
		HotPaths     []string `json:"hot_paths" yaml:"hot_paths"`
	} `json:"capture" yaml:"capture"`

	API struct {
		GRPC           string   `json:"grpc" yaml:"grpc"`
		REST           string   `json:"rest" yaml:"rest"`
		AuthEnabled    bool     `json:"auth_enabled" yaml:"auth_enabled"`
		AuthKeys       []string `json:"auth_keys" yaml:"auth_keys"`
		RateLimitPerSec float64 `json:"rate_limit_per_sec" yaml:"rate_limit_per_sec"`
		RateLimitBurst int      `json:"rate_limit_burst" yaml:"rate_limit_burst"`
		CORSOrigins    []string `json:"cors_origins" yaml:"cors_origins"`
	} `json:"api" yaml:"api"`

	TLS struct {
		Enable   bool   `json:"enable" yaml:"enable"`
		CertFile string `json:"cert_file" yaml:"cert_file"`
		KeyFile  string `json:"key_file" yaml:"key_file"`
		CAFile   string `json:"ca_file" yaml:"ca_file"`
	} `json:"tls" yaml:"tls"`

	Storage struct {
		Encrypt bool   `json:"encrypt" yaml:"encrypt"`
		KeyFile string `json:"key_file" yaml:"key_file"`
	} `json:"storage" yaml:"storage"`

	Analyzer struct {
		ScanInterval       Duration `json:"scan_interval" yaml:"scan_interval"`
		DeepTaintThreshold int      `json:"deep_taint_threshold" yaml:"deep_taint_threshold"`
		EnablePatterns     []string `json:"enable_patterns" yaml:"enable_patterns"`
		Quiet              bool     `json:"quiet" yaml:"quiet"`
	} `json:"analyzer" yaml:"analyzer"`

	TaintSecrets struct {
		UntrustedComms []string `json:"untrusted_comms" yaml:"untrusted_comms"`
		NetworkTools   []string `json:"network_tools" yaml:"network_tools"`
		SensitivePaths []string `json:"sensitive_paths" yaml:"sensitive_paths"`
	} `json:"taint_secrets" yaml:"taint_secrets"`
		Notify struct {
			SlackWebhook  string   `json:"slack_webhook" yaml:"slack_webhook"`
			SlackChannel  string   `json:"slack_channel" yaml:"slack_channel"`
			SMTPAddr      string   `json:"smtp_addr" yaml:"smtp_addr"`
			SMTPUser      string   `json:"smtp_user" yaml:"smtp_user"`
			SMTPPass      string   `json:"smtp_pass" yaml:"smtp_pass"`
			EmailFrom     string   `json:"email_from" yaml:"email_from"`
			EmailTo       []string `json:"email_to" yaml:"email_to"`
			WebhookURL    string   `json:"webhook_url" yaml:"webhook_url"`
			WebhookSecret string   `json:"webhook_secret" yaml:"webhook_secret"`
			MinInterval   string   `json:"min_interval" yaml:"min_interval"`
		} `json:"notify" yaml:"notify"`

	License struct {
		Path string `json:"path" yaml:"path"`
	} `json:"license" yaml:"license"`
}

// Duration is a wrapper for time.Duration that supports YAML/JSON parsing
// from strings like "30s", "5m", "1h".
type Duration struct {
	Duration int64 `json:"-" yaml:"-"` // nanoseconds
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	return d.parse(s)
}

func (d *Duration) parse(s string) error {
	// Support simple suffixes: s, m, h
	if len(s) == 0 {
		return nil
	}
	unit := s[len(s)-1]
	numStr := s[:len(s)-1]
	var multiplier int64
	switch unit {
	case 's':
		multiplier = 1e9
	case 'm':
		multiplier = 60 * 1e9
	case 'h':
		multiplier = 3600 * 1e9
	default:
		return fmt.Errorf("invalid duration unit %q (use s, m, h)", unit)
	}
	n, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = n * multiplier
	return nil
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	c := &Config{}
	c.Kernel.Verbose = false
	c.Kernel.Hooks = []string{"task_alloc", "task_free", "file_open",
		"bprm_check_security", "socket_connect"}
	c.Output.Dir = "/var/log/providapt"
	c.Output.Format = "json"
	c.Log.Level = "info"
	c.Log.Format = "json"
	c.Capture.EnableNet = true
	c.Capture.EnableFile = true
	c.Capture.EnableProc = true
	c.API.GRPC = ":50051"
	c.API.REST = ":8080"
	c.API.RateLimitPerSec = 100
	c.API.RateLimitBurst = 200
	c.API.CORSOrigins = []string{"*"}
	return c
}

// Load reads configuration from a YAML or JSON file.
// Falls back to defaults if the file doesn't exist.
// After loading, applies PROVIDAPT_* environment variable overrides,
// resolves env: prefixed secrets, then validates the result.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			applyEnvOverrides(cfg)
			resolveSecrets(cfg)
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	// YAML is a superset of JSON, so this handles both formats
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	applyEnvOverrides(cfg)
	resolveSecrets(cfg)

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// resolveSecrets replaces "env:SOME_VAR" values with the actual environment
// variable content. This allows sensitive config fields (passwords, keys)
// to reference environment variables instead of plaintext in the config file.
func resolveSecrets(cfg *Config) {
	resolveSecretString(&cfg.Notify.SMTPPass, "PROVIDAPT_NOTIFY_SMTP_PASS")
	resolveSecretString(&cfg.Notify.WebhookSecret, "PROVIDAPT_NOTIFY_WEBHOOK_SECRET")
}

func resolveSecretString(field *string, envKey string) {
	if field == nil {
		return
	}
	// Check for env: prefix
	if len(*field) > 4 && (*field)[:4] == "env:" {
		envVar := (*field)[4:]
		if val, ok := os.LookupEnv(envVar); ok {
			*field = val
		}
		// Also check PROVIDAPT_ fallback for backward compat
		if val, ok := os.LookupEnv(envKey); ok && *field != "" {
			*field = val
		}
	}
}

// Validate checks configuration values and returns an error for invalid values.
func (c *Config) Validate() error {
	if c.Output.Format != "json" && c.Output.Format != "parquet" {
		return fmt.Errorf("unsupported output format %q (use json or parquet)", c.Output.Format)
	}
	if c.Log.Level != "debug" && c.Log.Level != "info" && c.Log.Level != "warn" && c.Log.Level != "error" {
		return fmt.Errorf("unsupported log level %q (use debug, info, warn, or error)", c.Log.Level)
	}
	if c.API.REST != "" && !strings.HasPrefix(c.API.REST, ":") {
		return fmt.Errorf("REST address %q should be in format :port (e.g. :8080)", c.API.REST)
	}
	if c.API.GRPC != "" && !strings.HasPrefix(c.API.GRPC, ":") {
		return fmt.Errorf("gRPC address %q should be in format :port (e.g. :50051)", c.API.GRPC)
	}
	if c.Storage.Encrypt && c.Storage.KeyFile == "" {
		return fmt.Errorf("storage encryption enabled but no key_file specified")
	}
	if c.Analyzer.ScanInterval.Duration > 0 && c.Analyzer.ScanInterval.Duration < 1e9 {
		return fmt.Errorf("scan_interval must be at least 1s")
	}
	if c.Analyzer.DeepTaintThreshold < 0 {
		return fmt.Errorf("deep_taint_threshold must be non-negative")
	}
	return nil
}

// ── Environment variable overrides ──────────────────────────

// applyEnvOverrides reads PROVIDAPT_* environment variables and overrides
// matching config fields. Environment variables take highest priority.
//
// Naming convention: PROVIDAPT_{SECTION}_{KEY}
// Examples:
//
//	PROVIDAPT_LOG_LEVEL=debug
//	PROVIDAPT_OUTPUT_DIR=/var/log/providapt
//	PROVIDAPT_API_REST=:9090
//	PROVIDAPT_CAPTURE_ENABLE_NET=false
func applyEnvOverrides(cfg *Config) {
	overrideString(&cfg.Log.Level, "PROVIDAPT_LOG_LEVEL")
	overrideString(&cfg.Log.Format, "PROVIDAPT_LOG_FORMAT")
	overrideString(&cfg.Output.Dir, "PROVIDAPT_OUTPUT_DIR")
	overrideString(&cfg.Output.Format, "PROVIDAPT_OUTPUT_FORMAT")
	overrideString(&cfg.API.GRPC, "PROVIDAPT_API_GRPC")
	overrideString(&cfg.API.REST, "PROVIDAPT_API_REST")
	overrideString(&cfg.Storage.KeyFile, "PROVIDAPT_STORAGE_KEY_FILE")

	overrideBool(&cfg.Kernel.Verbose, "PROVIDAPT_KERNEL_VERBOSE")
	overrideBool(&cfg.Capture.EnableNet, "PROVIDAPT_CAPTURE_ENABLE_NET")
	overrideBool(&cfg.Capture.EnableFile, "PROVIDAPT_CAPTURE_ENABLE_FILE")
	overrideBool(&cfg.Capture.EnableProc, "PROVIDAPT_CAPTURE_ENABLE_PROC")
	overrideBool(&cfg.Capture.SensitiveDir, "PROVIDAPT_CAPTURE_SENSITIVE_DIR")
	overrideBool(&cfg.Storage.Encrypt, "PROVIDAPT_STORAGE_ENCRYPT")
	overrideBool(&cfg.TLS.Enable, "PROVIDAPT_TLS_ENABLE")
	overrideBool(&cfg.API.AuthEnabled, "PROVIDAPT_API_AUTH_ENABLED")

	overrideInt(&cfg.Capture.MaxEvents, "PROVIDAPT_CAPTURE_MAX_EVENTS")
	overrideInt(&cfg.API.RateLimitBurst, "PROVIDAPT_API_RATE_LIMIT_BURST")

	overrideFloat(&cfg.API.RateLimitPerSec, "PROVIDAPT_API_RATE_LIMIT_PER_SEC")
}

func overrideString(field *string, envKey string) {
	if v, ok := os.LookupEnv(envKey); ok {
		*field = v
	}
}

func overrideBool(field *bool, envKey string) {
	if v, ok := os.LookupEnv(envKey); ok {
		*field = v == "true" || v == "1" || v == "yes"
	}
}

func overrideInt(field *int, envKey string) {
	if v, ok := os.LookupEnv(envKey); ok {
		if n, err := strconv.Atoi(v); err == nil {
			*field = n
		}
	}
}

func overrideFloat(field *float64, envKey string) {
	if v, ok := os.LookupEnv(envKey); ok {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			*field = n
		}
	}
}
