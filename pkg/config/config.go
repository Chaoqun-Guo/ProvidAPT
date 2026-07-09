// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package config loads, validates, and overrides ProvidAPT runtime
// configuration from files and environment variables.
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
		Verbose        bool     `json:"verbose" yaml:"verbose"`
		AttachmentMode string   `json:"attachment_mode" yaml:"attachment_mode"`
		Hooks          []string `json:"hooks" yaml:"hooks"`
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
		MaxEvents        int      `json:"max_events" yaml:"max_events"`
		EnableNet        bool     `json:"enable_net" yaml:"enable_net"`
		EnableFile       bool     `json:"enable_file" yaml:"enable_file"`
		EnableProc       bool     `json:"enable_proc" yaml:"enable_proc"`
		SensitiveDir     bool     `json:"sensitive_dir" yaml:"sensitive_dir"`
		AutoExcludeNoisy bool     `json:"auto_exclude_noisy" yaml:"auto_exclude_noisy"`
		ExcludePIDs      []uint32 `json:"exclude_pids" yaml:"exclude_pids"`
		ExcludeComms     []string `json:"exclude_comms" yaml:"exclude_comms"`
		IncludeComms     []string `json:"include_comms" yaml:"include_comms"`
		HotPaths         []string `json:"hot_paths" yaml:"hot_paths"`
	} `json:"capture" yaml:"capture"`

	API struct {
		GRPC            string            `json:"grpc" yaml:"grpc"`
		REST            string            `json:"rest" yaml:"rest"`
		AuthEnabled     bool              `json:"auth_enabled" yaml:"auth_enabled"`
		AuthKeys        []string          `json:"auth_keys" yaml:"auth_keys"`
		AuthRoles       map[string]string `json:"auth_roles" yaml:"auth_roles"`
		AuthIdentities  map[string]string `json:"auth_identities" yaml:"auth_identities"`
		RateLimitPerSec float64           `json:"rate_limit_per_sec" yaml:"rate_limit_per_sec"`
		RateLimitBurst  int               `json:"rate_limit_burst" yaml:"rate_limit_burst"`
		CORSOrigins     []string          `json:"cors_origins" yaml:"cors_origins"`
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
		SlackWebhook      string   `json:"slack_webhook" yaml:"slack_webhook"`
		SlackChannel      string   `json:"slack_channel" yaml:"slack_channel"`
		SMTPAddr          string   `json:"smtp_addr" yaml:"smtp_addr"`
		SMTPUser          string   `json:"smtp_user" yaml:"smtp_user"`
		SMTPPass          string   `json:"smtp_pass" yaml:"smtp_pass"`
		EmailFrom         string   `json:"email_from" yaml:"email_from"`
		EmailTo           []string `json:"email_to" yaml:"email_to"`
		WebhookURL        string   `json:"webhook_url" yaml:"webhook_url"`
		WebhookSecret     string   `json:"webhook_secret" yaml:"webhook_secret"`
		MinInterval       string   `json:"min_interval" yaml:"min_interval"`
		MaxAttempts       int      `json:"max_attempts" yaml:"max_attempts"`
		RetryBackoff      string   `json:"retry_backoff" yaml:"retry_backoff"`
		TicketProvider    string   `json:"ticket_provider" yaml:"ticket_provider"`
		TicketWebhookURL  string   `json:"ticket_webhook_url" yaml:"ticket_webhook_url"`
		TicketWebhookAuth string   `json:"ticket_webhook_auth" yaml:"ticket_webhook_auth"`
		JiraBaseURL       string   `json:"jira_base_url" yaml:"jira_base_url"`
		JiraEmail         string   `json:"jira_email" yaml:"jira_email"`
		JiraAPIToken      string   `json:"jira_api_token" yaml:"jira_api_token"`
		JiraProjectKey    string   `json:"jira_project_key" yaml:"jira_project_key"`
		JiraIssueType     string   `json:"jira_issue_type" yaml:"jira_issue_type"`
		ServiceNowBaseURL string   `json:"servicenow_base_url" yaml:"servicenow_base_url"`
		ServiceNowUser    string   `json:"servicenow_user" yaml:"servicenow_user"`
		ServiceNowPass    string   `json:"servicenow_pass" yaml:"servicenow_pass"`
		ServiceNowTable   string   `json:"servicenow_table" yaml:"servicenow_table"`
	} `json:"notify" yaml:"notify"`

	Telemetry struct {
		Endpoint   string `json:"endpoint" yaml:"endpoint"`
		Interval   string `json:"interval" yaml:"interval"`
		EnableTLS  bool   `json:"enable_tls" yaml:"enable_tls"`
		CertFile   string `json:"cert_file" yaml:"cert_file"`
		KeyFile    string `json:"key_file" yaml:"key_file"`
		CAFile     string `json:"ca_file" yaml:"ca_file"`
		ServerName string `json:"server_name" yaml:"server_name"`
	} `json:"telemetry" yaml:"telemetry"`

	SupportBundle struct {
		RetainArchives int  `json:"retain_archives" yaml:"retain_archives"`
		RedactArchives bool `json:"redact_archives" yaml:"redact_archives"`
	} `json:"support_bundle" yaml:"support_bundle"`

	License struct {
		Path               string   `json:"path" yaml:"path"`
		SigningKey         string   `json:"signing_key" yaml:"signing_key"`
		PublicKeyPath      string   `json:"public_key_path" yaml:"public_key_path"`
		RevokedIDs         []string `json:"revoked_ids" yaml:"revoked_ids"`
		RevocationURL      string   `json:"revocation_url" yaml:"revocation_url"`
		RevocationCache    string   `json:"revocation_cache" yaml:"revocation_cache"`
		RevocationSigURL   string   `json:"revocation_sig_url" yaml:"revocation_sig_url"`
		RevocationSigCache string   `json:"revocation_sig_cache" yaml:"revocation_sig_cache"`
		GracePeriodDays    int      `json:"grace_period_days" yaml:"grace_period_days"`
	} `json:"license" yaml:"license"`

	Upgrade struct {
		DownloadURL    string `json:"download_url" yaml:"download_url"`
		PackagePath    string `json:"package_path" yaml:"package_path"`
		ExpectedSHA256 string `json:"expected_sha256" yaml:"expected_sha256"`
		SignaturePath  string `json:"signature_path" yaml:"signature_path"`
		SigningKey     string `json:"signing_key" yaml:"signing_key"`
		PublicKeyPath  string `json:"public_key_path" yaml:"public_key_path"`
		RollbackPlan   string `json:"rollback_plan" yaml:"rollback_plan"`
	} `json:"upgrade" yaml:"upgrade"`
}

// Duration is a wrapper for time.Duration that supports YAML/JSON parsing
// from strings like "30s", "5m", "1h".
type Duration struct {
	Duration int64 `json:"-" yaml:"-"` // nanoseconds
}

// UnmarshalYAML parses duration strings such as "30s", "5m", and "1h".
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
	c.Kernel.AttachmentMode = "auto"
	c.Kernel.Hooks = []string{"task_alloc", "task_free", "file_open",
		"bprm_check_security", "socket_connect"}
	c.Output.Dir = "/var/log/providapt"
	c.Output.Format = "json"
	c.Log.Level = "info"
	c.Log.Format = "json"
	c.Capture.EnableNet = true
	c.Capture.EnableFile = true
	c.Capture.EnableProc = true
	c.Capture.AutoExcludeNoisy = false
	c.API.GRPC = ":50051"
	c.API.REST = ":8080"
	c.API.RateLimitPerSec = 100
	c.API.RateLimitBurst = 200
	c.API.CORSOrigins = []string{"*"}
	c.Notify.MaxAttempts = 3
	c.Notify.RetryBackoff = "250ms"
	c.Telemetry.Interval = "30s"
	c.SupportBundle.RetainArchives = 5
	c.SupportBundle.RedactArchives = true
	c.License.GracePeriodDays = 0
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
	resolveSecretString(&cfg.Notify.TicketWebhookAuth, "PROVIDAPT_NOTIFY_TICKET_WEBHOOK_AUTH")
	resolveSecretString(&cfg.Notify.JiraAPIToken, "PROVIDAPT_NOTIFY_JIRA_API_TOKEN")
	resolveSecretString(&cfg.Notify.ServiceNowPass, "PROVIDAPT_NOTIFY_SERVICENOW_PASS")
	resolveSecretString(&cfg.License.SigningKey, "PROVIDAPT_LICENSE_SIGNING_KEY")
	resolveSecretString(&cfg.Upgrade.SigningKey, "PROVIDAPT_UPGRADE_SIGNING_KEY")
}

func resolveSecretString(field *string, envKey string) {
	if field == nil {
		return
	}
	resolved := false
	// Check for env: prefix
	if len(*field) > 4 && (*field)[:4] == "env:" {
		envVar := (*field)[4:]
		if val, ok := os.LookupEnv(envVar); ok {
			*field = val
			resolved = true
		}
	}
	// Also check PROVIDAPT_ fallback for backward compat
	if !resolved {
		if val, ok := os.LookupEnv(envKey); ok && val != "" {
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
	if mode := strings.ToLower(strings.TrimSpace(c.Kernel.AttachmentMode)); mode != "" &&
		mode != "auto" && mode != "lsm" && mode != "kprobe" {
		return fmt.Errorf("unsupported kernel.attachment_mode %q (use auto, lsm, or kprobe)", c.Kernel.AttachmentMode)
	}
	if c.API.REST != "" && !strings.HasPrefix(c.API.REST, ":") {
		return fmt.Errorf("REST address %q should be in format :port (e.g. :8080)", c.API.REST)
	}
	if c.API.GRPC != "" && !strings.HasPrefix(c.API.GRPC, ":") {
		return fmt.Errorf("gRPC address %q should be in format :port (e.g. :50051)", c.API.GRPC)
	}
	for key, role := range c.API.AuthRoles {
		if role != "admin" && role != "analyst" && role != "auditor" {
			return fmt.Errorf("unsupported API auth role %q for key %q", role, key)
		}
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
	if c.Notify.MaxAttempts < 1 {
		return fmt.Errorf("notify.max_attempts must be at least 1")
	}
	if c.Notify.TicketProvider != "" {
		switch strings.ToLower(strings.TrimSpace(c.Notify.TicketProvider)) {
		case "webhook", "jira", "servicenow":
		default:
			return fmt.Errorf("unsupported notify.ticket_provider %q", c.Notify.TicketProvider)
		}
	}
	if c.SupportBundle.RetainArchives < 0 {
		return fmt.Errorf("support_bundle.retain_archives must be non-negative")
	}
	if c.License.GracePeriodDays < 0 {
		return fmt.Errorf("license.grace_period_days must be non-negative")
	}
	if checksum := strings.TrimSpace(c.Upgrade.ExpectedSHA256); checksum != "" {
		if len(checksum) != 64 {
			return fmt.Errorf("upgrade.expected_sha256 must be a 64-character hex digest")
		}
		for _, ch := range checksum {
			if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') && (ch < 'A' || ch > 'F') {
				return fmt.Errorf("upgrade.expected_sha256 must be hexadecimal")
			}
		}
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
	overrideString(&cfg.Kernel.AttachmentMode, "PROVIDAPT_KERNEL_ATTACHMENT_MODE")
	overrideString(&cfg.Output.Dir, "PROVIDAPT_OUTPUT_DIR")
	overrideString(&cfg.Output.Format, "PROVIDAPT_OUTPUT_FORMAT")
	overrideString(&cfg.API.GRPC, "PROVIDAPT_API_GRPC")
	overrideString(&cfg.API.REST, "PROVIDAPT_API_REST")
	overrideString(&cfg.Storage.KeyFile, "PROVIDAPT_STORAGE_KEY_FILE")
	overrideString(&cfg.Telemetry.Endpoint, "PROVIDAPT_TELEMETRY_ENDPOINT")
	overrideString(&cfg.Telemetry.Interval, "PROVIDAPT_TELEMETRY_INTERVAL")
	overrideString(&cfg.Telemetry.CertFile, "PROVIDAPT_TELEMETRY_CERT_FILE")
	overrideString(&cfg.Telemetry.KeyFile, "PROVIDAPT_TELEMETRY_KEY_FILE")
	overrideString(&cfg.Telemetry.CAFile, "PROVIDAPT_TELEMETRY_CA_FILE")
	overrideString(&cfg.Telemetry.ServerName, "PROVIDAPT_TELEMETRY_SERVER_NAME")
	overrideString(&cfg.Notify.RetryBackoff, "PROVIDAPT_NOTIFY_RETRY_BACKOFF")
	overrideString(&cfg.Notify.TicketProvider, "PROVIDAPT_NOTIFY_TICKET_PROVIDER")
	overrideString(&cfg.Notify.TicketWebhookURL, "PROVIDAPT_NOTIFY_TICKET_WEBHOOK_URL")
	overrideString(&cfg.Notify.TicketWebhookAuth, "PROVIDAPT_NOTIFY_TICKET_WEBHOOK_AUTH")
	overrideString(&cfg.Notify.JiraBaseURL, "PROVIDAPT_NOTIFY_JIRA_BASE_URL")
	overrideString(&cfg.Notify.JiraEmail, "PROVIDAPT_NOTIFY_JIRA_EMAIL")
	overrideString(&cfg.Notify.JiraAPIToken, "PROVIDAPT_NOTIFY_JIRA_API_TOKEN")
	overrideString(&cfg.Notify.JiraProjectKey, "PROVIDAPT_NOTIFY_JIRA_PROJECT_KEY")
	overrideString(&cfg.Notify.JiraIssueType, "PROVIDAPT_NOTIFY_JIRA_ISSUE_TYPE")
	overrideString(&cfg.Notify.ServiceNowBaseURL, "PROVIDAPT_NOTIFY_SERVICENOW_BASE_URL")
	overrideString(&cfg.Notify.ServiceNowUser, "PROVIDAPT_NOTIFY_SERVICENOW_USER")
	overrideString(&cfg.Notify.ServiceNowPass, "PROVIDAPT_NOTIFY_SERVICENOW_PASS")
	overrideString(&cfg.Notify.ServiceNowTable, "PROVIDAPT_NOTIFY_SERVICENOW_TABLE")
	overrideString(&cfg.License.Path, "PROVIDAPT_LICENSE_PATH")
	overrideString(&cfg.License.SigningKey, "PROVIDAPT_LICENSE_SIGNING_KEY")
	overrideString(&cfg.License.PublicKeyPath, "PROVIDAPT_LICENSE_PUBLIC_KEY_PATH")
	overrideStringSlice(&cfg.License.RevokedIDs, "PROVIDAPT_LICENSE_REVOKED_IDS")
	overrideString(&cfg.License.RevocationURL, "PROVIDAPT_LICENSE_REVOCATION_URL")
	overrideString(&cfg.License.RevocationCache, "PROVIDAPT_LICENSE_REVOCATION_CACHE")
	overrideString(&cfg.License.RevocationSigURL, "PROVIDAPT_LICENSE_REVOCATION_SIG_URL")
	overrideString(&cfg.License.RevocationSigCache, "PROVIDAPT_LICENSE_REVOCATION_SIG_CACHE")
	overrideString(&cfg.Upgrade.DownloadURL, "PROVIDAPT_UPGRADE_DOWNLOAD_URL")
	overrideString(&cfg.Upgrade.PackagePath, "PROVIDAPT_UPGRADE_PACKAGE_PATH")
	overrideString(&cfg.Upgrade.ExpectedSHA256, "PROVIDAPT_UPGRADE_EXPECTED_SHA256")
	overrideString(&cfg.Upgrade.SignaturePath, "PROVIDAPT_UPGRADE_SIGNATURE_PATH")
	overrideString(&cfg.Upgrade.SigningKey, "PROVIDAPT_UPGRADE_SIGNING_KEY")
	overrideString(&cfg.Upgrade.PublicKeyPath, "PROVIDAPT_UPGRADE_PUBLIC_KEY_PATH")
	overrideString(&cfg.Upgrade.RollbackPlan, "PROVIDAPT_UPGRADE_ROLLBACK_PLAN")

	overrideBool(&cfg.Kernel.Verbose, "PROVIDAPT_KERNEL_VERBOSE")
	overrideBool(&cfg.Capture.EnableNet, "PROVIDAPT_CAPTURE_ENABLE_NET")
	overrideBool(&cfg.Capture.EnableFile, "PROVIDAPT_CAPTURE_ENABLE_FILE")
	overrideBool(&cfg.Capture.EnableProc, "PROVIDAPT_CAPTURE_ENABLE_PROC")
	overrideBool(&cfg.Capture.SensitiveDir, "PROVIDAPT_CAPTURE_SENSITIVE_DIR")
	overrideBool(&cfg.Capture.AutoExcludeNoisy, "PROVIDAPT_CAPTURE_AUTO_EXCLUDE_NOISY")
	overrideBool(&cfg.Storage.Encrypt, "PROVIDAPT_STORAGE_ENCRYPT")
	overrideBool(&cfg.TLS.Enable, "PROVIDAPT_TLS_ENABLE")
	overrideBool(&cfg.API.AuthEnabled, "PROVIDAPT_API_AUTH_ENABLED")
	overrideBool(&cfg.Telemetry.EnableTLS, "PROVIDAPT_TELEMETRY_ENABLE_TLS")
	overrideBool(&cfg.SupportBundle.RedactArchives, "PROVIDAPT_SUPPORT_REDACT_ARCHIVES")

	overrideInt(&cfg.Capture.MaxEvents, "PROVIDAPT_CAPTURE_MAX_EVENTS")
	overrideInt(&cfg.API.RateLimitBurst, "PROVIDAPT_API_RATE_LIMIT_BURST")
	overrideInt(&cfg.Notify.MaxAttempts, "PROVIDAPT_NOTIFY_MAX_ATTEMPTS")
	overrideInt(&cfg.SupportBundle.RetainArchives, "PROVIDAPT_SUPPORT_RETAIN_ARCHIVES")
	overrideInt(&cfg.License.GracePeriodDays, "PROVIDAPT_LICENSE_GRACE_PERIOD_DAYS")

	overrideFloat(&cfg.API.RateLimitPerSec, "PROVIDAPT_API_RATE_LIMIT_PER_SEC")
	overrideUint32Slice(&cfg.Capture.ExcludePIDs, "PROVIDAPT_CAPTURE_EXCLUDE_PIDS")
	overrideStringSlice(&cfg.Capture.ExcludeComms, "PROVIDAPT_CAPTURE_EXCLUDE_COMMS")
	overrideStringSlice(&cfg.Capture.IncludeComms, "PROVIDAPT_CAPTURE_INCLUDE_COMMS")
	overrideStringSlice(&cfg.Capture.HotPaths, "PROVIDAPT_CAPTURE_HOT_PATHS")
}

func overrideString(field *string, envKey string) {
	if v, ok := os.LookupEnv(envKey); ok {
		*field = v
	}
}

func overrideStringSlice(field *[]string, envKey string) {
	if v, ok := os.LookupEnv(envKey); ok {
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				out = append(out, trimmed)
			}
		}
		*field = out
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

func overrideUint32Slice(field *[]uint32, envKey string) {
	if v, ok := os.LookupEnv(envKey); ok {
		parts := strings.Split(v, ",")
		out := make([]uint32, 0, len(parts))
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}
			n, err := strconv.ParseUint(trimmed, 10, 32)
			if err != nil {
				continue
			}
			out = append(out, uint32(n))
		}
		*field = out
	}
}

func overrideFloat(field *float64, envKey string) {
	if v, ok := os.LookupEnv(envKey); ok {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			*field = n
		}
	}
}
