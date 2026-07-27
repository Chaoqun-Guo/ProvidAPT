// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package config loads, validates, and overrides ProvidAPT runtime
// configuration from files and environment variables.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

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
		Dir               string `json:"dir" yaml:"dir"`
		Format            string `json:"format" yaml:"format"`
		MaxFileBytes      int64  `json:"max_file_bytes" yaml:"max_file_bytes"`
		RetainFiles       int    `json:"retain_files" yaml:"retain_files"`
		RetainMaxBytes    int64  `json:"retain_max_bytes" yaml:"retain_max_bytes"`
		AlertMaxFileBytes int64  `json:"alert_max_file_bytes" yaml:"alert_max_file_bytes"`
		AlertRetainFiles  int    `json:"alert_retain_files" yaml:"alert_retain_files"`
		AlertRetainBytes  int64  `json:"alert_retain_max_bytes" yaml:"alert_retain_max_bytes"`
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
		GRPC            string              `json:"grpc" yaml:"grpc"`
		REST            string              `json:"rest" yaml:"rest"`
		AuthEnabled     bool                `json:"auth_enabled" yaml:"auth_enabled"`
		AuthKeys        []string            `json:"auth_keys" yaml:"auth_keys"`
		AuthRoles       map[string]string   `json:"auth_roles" yaml:"auth_roles"`
		AuthIdentities  map[string]string   `json:"auth_identities" yaml:"auth_identities"`
		AuthTenants     map[string]string   `json:"auth_tenants" yaml:"auth_tenants"`
		AuthPermissions map[string][]string `json:"auth_permissions" yaml:"auth_permissions"`
		RateLimitPerSec float64             `json:"rate_limit_per_sec" yaml:"rate_limit_per_sec"`
		RateLimitBurst  int                 `json:"rate_limit_burst" yaml:"rate_limit_burst"`
		CORSOrigins     []string            `json:"cors_origins" yaml:"cors_origins"`
	} `json:"api" yaml:"api"`

	ControlPlane struct {
		Mode            string   `json:"mode" yaml:"mode"`
		NodeID          string   `json:"node_id" yaml:"node_id"`
		Role            string   `json:"role" yaml:"role"`
		LeaderID        string   `json:"leader_id" yaml:"leader_id"`
		Peers           []string `json:"peers" yaml:"peers"`
		StateBackend    string   `json:"state_backend" yaml:"state_backend"`
		Heartbeat       string   `json:"heartbeat" yaml:"heartbeat"`
		ElectionTimeout string   `json:"election_timeout" yaml:"election_timeout"`
		FailoverReady   bool     `json:"failover_ready" yaml:"failover_ready"`
	} `json:"control_plane" yaml:"control_plane"`

	SSO struct {
		TrustedHeaderAuth bool   `json:"trusted_header_auth" yaml:"trusted_header_auth"`
		UserHeader        string `json:"user_header" yaml:"user_header"`
		RoleHeader        string `json:"role_header" yaml:"role_header"`
		TenantHeader      string `json:"tenant_header" yaml:"tenant_header"`
	} `json:"sso" yaml:"sso"`

	TLS struct {
		Enable               bool   `json:"enable" yaml:"enable"`
		CertFile             string `json:"cert_file" yaml:"cert_file"`
		KeyFile              string `json:"key_file" yaml:"key_file"`
		CAFile               string `json:"ca_file" yaml:"ca_file"`
		RotationCheck        string `json:"rotation_check" yaml:"rotation_check"`
		RotationRenewBefore  string `json:"rotation_renew_before" yaml:"rotation_renew_before"`
		RotationAuto         bool   `json:"rotation_auto" yaml:"rotation_auto"`
		RotationRestartAfter bool   `json:"rotation_restart_after" yaml:"rotation_restart_after"`
	} `json:"tls" yaml:"tls"`

	Secrets struct {
		Provider string            `json:"provider" yaml:"provider"`
		BaseDir  string            `json:"base_dir" yaml:"base_dir"`
		Vault    map[string]string `json:"vault" yaml:"vault"`
	} `json:"secrets" yaml:"secrets"`

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

	Policy struct {
		Endpoint     string `json:"endpoint" yaml:"endpoint"`
		APIKey       string `json:"api_key" yaml:"api_key"`
		PollInterval string `json:"poll_interval" yaml:"poll_interval"`
		BundleDir    string `json:"bundle_dir" yaml:"bundle_dir"`
		EnableTLS    bool   `json:"enable_tls" yaml:"enable_tls"`
		CAFile       string `json:"ca_file" yaml:"ca_file"`
		Enabled      bool   `json:"enabled" yaml:"enabled"`
	} `json:"policy" yaml:"policy"`

	SupportBundle struct {
		RetainArchives int  `json:"retain_archives" yaml:"retain_archives"`
		RedactArchives bool `json:"redact_archives" yaml:"redact_archives"`
	} `json:"support_bundle" yaml:"support_bundle"`

	Backup struct {
		Enabled         bool   `json:"enabled" yaml:"enabled"`
		Interval        string `json:"interval" yaml:"interval"`
		RetainArchives  int    `json:"retain_archives" yaml:"retain_archives"`
		MinFreeBytes    int64  `json:"min_free_bytes" yaml:"min_free_bytes"`
		AllowActivation bool   `json:"allow_activation" yaml:"allow_activation"`
	} `json:"backup" yaml:"backup"`

	Compliance struct {
		RetentionDays    int      `json:"retention_days" yaml:"retention_days"`
		MaxAuditEntries  int      `json:"max_audit_entries" yaml:"max_audit_entries"`
		ReportDir        string   `json:"report_dir" yaml:"report_dir"`
		ReportInterval   string   `json:"report_interval" yaml:"report_interval"`
		RequireApprovals bool     `json:"require_approvals" yaml:"require_approvals"`
		ApprovalActions  []string `json:"approval_actions" yaml:"approval_actions"`
		ApprovalTTL      string   `json:"approval_ttl" yaml:"approval_ttl"`
	} `json:"compliance" yaml:"compliance"`

	SIEM struct {
		Enabled       bool   `json:"enabled" yaml:"enabled"`
		Provider      string `json:"provider" yaml:"provider"`
		Endpoint      string `json:"endpoint" yaml:"endpoint"`
		Token         string `json:"token" yaml:"token"`
		Index         string `json:"index" yaml:"index"`
		SourceType    string `json:"source_type" yaml:"source_type"`
		Format        string `json:"format" yaml:"format"`
		MinSeverity   string `json:"min_severity" yaml:"min_severity"`
		OutboxDir     string `json:"outbox_dir" yaml:"outbox_dir"`
		FlushInterval string `json:"flush_interval" yaml:"flush_interval"`
	} `json:"siem" yaml:"siem"`

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
		MaxAgents          int      `json:"max_agents" yaml:"max_agents"`
	} `json:"license" yaml:"license"`

	Upgrade struct {
		DownloadURL     string `json:"download_url" yaml:"download_url"`
		PackagePath     string `json:"package_path" yaml:"package_path"`
		ExpectedSHA256  string `json:"expected_sha256" yaml:"expected_sha256"`
		SignaturePath   string `json:"signature_path" yaml:"signature_path"`
		SigningKey      string `json:"signing_key" yaml:"signing_key"`
		PublicKeyPath   string `json:"public_key_path" yaml:"public_key_path"`
		RollbackPlan    string `json:"rollback_plan" yaml:"rollback_plan"`
		ApplyCommand    string `json:"apply_command" yaml:"apply_command"`
		RollbackCommand string `json:"rollback_command" yaml:"rollback_command"`
		CanaryPercent   int    `json:"canary_percent" yaml:"canary_percent"`
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

func validateDurationString(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	duration, err := time.ParseDuration(trimmed)
	if err != nil {
		return err
	}
	if duration <= 0 {
		return fmt.Errorf("must be positive")
	}
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
	c.Output.MaxFileBytes = 16 * 1024 * 1024
	c.Output.RetainFiles = 0
	c.Output.RetainMaxBytes = 4 * 1024 * 1024 * 1024
	c.Output.AlertMaxFileBytes = 8 * 1024 * 1024
	c.Output.AlertRetainFiles = 0
	c.Output.AlertRetainBytes = 256 * 1024 * 1024
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
	c.ControlPlane.Mode = "standalone"
	c.ControlPlane.Role = "leader"
	c.ControlPlane.Heartbeat = "10s"
	c.ControlPlane.ElectionTimeout = "45s"
	c.SSO.UserHeader = "X-Forwarded-User"
	c.SSO.RoleHeader = "X-Forwarded-Role"
	c.SSO.TenantHeader = "X-Forwarded-Tenant"
	c.TLS.RotationCheck = "24h"
	c.TLS.RotationRenewBefore = "720h"
	c.Secrets.Provider = "env"
	c.Notify.MaxAttempts = 3
	c.Notify.RetryBackoff = "250ms"
	c.Telemetry.Interval = "30s"
	c.Policy.PollInterval = "30s"
	c.SupportBundle.RetainArchives = 5
	c.SupportBundle.RedactArchives = true
	c.Backup.Enabled = false
	c.Backup.Interval = "24h"
	c.Backup.RetainArchives = 7
	c.Backup.MinFreeBytes = 1024 * 1024 * 1024
	c.Compliance.RetentionDays = 180
	c.Compliance.MaxAuditEntries = 10000
	c.Compliance.ReportInterval = "24h"
	c.Compliance.ApprovalActions = []string{"policy.publish", "policy.rollback", "upgrade.preflight", "upgrade.apply", "upgrade.rollback", "backup.prepare_cutover"}
	c.Compliance.ApprovalTTL = "24h"
	c.SIEM.Format = "json"
	c.SIEM.MinSeverity = "INFO"
	c.SIEM.FlushInterval = "30s"
	c.License.GracePeriodDays = 0
	c.Upgrade.CanaryPercent = 10
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
			normalizeConfig(cfg)
			resolveSecrets(cfg)
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	if shouldParseTOML(path, data) {
		if err := parseSimpleTOML(data, cfg); err != nil {
			return nil, fmt.Errorf("parse toml config: %w", err)
		}
	} else if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	applyEnvOverrides(cfg)
	normalizeConfig(cfg)
	resolveSecrets(cfg)

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// resolveSecrets replaces secret references such as env:, file:, and vault:
// with resolved values. vault: references are resolved from the configured
// secrets.vault map, which lets production deployments inject Vault material
// through configuration management without hard-coding credentials in source.
func resolveSecrets(cfg *Config) {
	resolver := secretResolver{baseDir: cfg.Secrets.BaseDir, vault: cfg.Secrets.Vault}
	resolver.resolve(&cfg.Notify.SMTPPass, "PROVIDAPT_NOTIFY_SMTP_PASS")
	resolver.resolve(&cfg.Notify.WebhookSecret, "PROVIDAPT_NOTIFY_WEBHOOK_SECRET")
	resolver.resolve(&cfg.Notify.TicketWebhookAuth, "PROVIDAPT_NOTIFY_TICKET_WEBHOOK_AUTH")
	resolver.resolve(&cfg.Notify.JiraAPIToken, "PROVIDAPT_NOTIFY_JIRA_API_TOKEN")
	resolver.resolve(&cfg.Notify.ServiceNowPass, "PROVIDAPT_NOTIFY_SERVICENOW_PASS")
	resolver.resolve(&cfg.Policy.APIKey, "PROVIDAPT_POLICY_API_KEY")
	resolver.resolve(&cfg.License.SigningKey, "PROVIDAPT_LICENSE_SIGNING_KEY")
	resolver.resolve(&cfg.Upgrade.SigningKey, "PROVIDAPT_UPGRADE_SIGNING_KEY")
	resolver.resolve(&cfg.SIEM.Token, "PROVIDAPT_SIEM_TOKEN")
}

func normalizeConfig(cfg *Config) {
	cfg.Capture.IncludeComms = NormalizeComms(cfg.Capture.IncludeComms)
	cfg.Capture.ExcludeComms = NormalizeComms(cfg.Capture.ExcludeComms)
	cfg.TaintSecrets.UntrustedComms = NormalizeComms(cfg.TaintSecrets.UntrustedComms)
	cfg.TaintSecrets.NetworkTools = NormalizeComms(cfg.TaintSecrets.NetworkTools)
}

// NormalizeComm converts a Linux comm or executable path into the comparable
// task comm form used by eBPF: basename, trimmed, lower-case, max 15 bytes.
func NormalizeComm(comm string) string {
	trimmed := strings.TrimSpace(comm)
	if trimmed == "" {
		return ""
	}
	trimmed = filepath.Base(trimmed)
	trimmed = strings.ToLower(trimmed)
	if len(trimmed) > 15 {
		trimmed = trimmed[:15]
	}
	return trimmed
}

// NormalizeComms normalizes a list of command names and removes duplicates.
func NormalizeComms(comms []string) []string {
	out := make([]string, 0, len(comms))
	seen := make(map[string]struct{}, len(comms))
	for _, comm := range comms {
		normalized := NormalizeComm(comm)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

// CommAllowed returns whether an event comm passes an include list.
func CommAllowed(comm string, includeComms []string) bool {
	if len(includeComms) == 0 {
		return true
	}
	normalized := NormalizeComm(comm)
	for _, allowed := range includeComms {
		if NormalizeComm(allowed) == normalized {
			return true
		}
	}
	return false
}

type secretResolver struct {
	baseDir string
	vault   map[string]string
}

func (r secretResolver) resolve(field *string, envKey string) {
	if field == nil {
		return
	}
	resolved := false
	if strings.HasPrefix(*field, "env:") {
		envVar := strings.TrimPrefix(*field, "env:")
		if val, ok := os.LookupEnv(envVar); ok {
			*field = val
			resolved = true
		}
	}
	if !resolved && strings.HasPrefix(*field, "file:") {
		secretPath := strings.TrimPrefix(*field, "file:")
		if r.baseDir != "" && !filepath.IsAbs(secretPath) {
			secretPath = filepath.Join(r.baseDir, secretPath)
		}
		if data, err := os.ReadFile(secretPath); err == nil {
			*field = strings.TrimRight(string(data), "\r\n")
			resolved = true
		}
	}
	if !resolved && strings.HasPrefix(*field, "vault:") {
		key := strings.TrimPrefix(*field, "vault:")
		if val, ok := r.vault[key]; ok {
			*field = val
			resolved = true
		}
	}
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
	if c.Output.MaxFileBytes < 0 {
		return fmt.Errorf("output.max_file_bytes must be non-negative")
	}
	if c.Output.RetainFiles < 0 {
		return fmt.Errorf("output.retain_files must be non-negative")
	}
	if c.Output.RetainMaxBytes < 0 {
		return fmt.Errorf("output.retain_max_bytes must be non-negative")
	}
	if c.Output.AlertMaxFileBytes < 0 {
		return fmt.Errorf("output.alert_max_file_bytes must be non-negative")
	}
	if c.Output.AlertRetainFiles < 0 {
		return fmt.Errorf("output.alert_retain_files must be non-negative")
	}
	if c.Output.AlertRetainBytes < 0 {
		return fmt.Errorf("output.alert_retain_max_bytes must be non-negative")
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
	if mode := strings.ToLower(strings.TrimSpace(c.ControlPlane.Mode)); mode != "" && mode != "standalone" && mode != "active-passive" && mode != "external" {
		return fmt.Errorf("unsupported control_plane.mode %q (use standalone, active-passive, or external)", c.ControlPlane.Mode)
	}
	if role := strings.ToLower(strings.TrimSpace(c.ControlPlane.Role)); role != "" && role != "leader" && role != "follower" && role != "observer" {
		return fmt.Errorf("unsupported control_plane.role %q (use leader, follower, or observer)", c.ControlPlane.Role)
	}
	if strings.TrimSpace(c.ControlPlane.Heartbeat) != "" {
		if err := validateDurationString(c.ControlPlane.Heartbeat); err != nil {
			return fmt.Errorf("control_plane.heartbeat: %w", err)
		}
	}
	if strings.TrimSpace(c.ControlPlane.ElectionTimeout) != "" {
		if err := validateDurationString(c.ControlPlane.ElectionTimeout); err != nil {
			return fmt.Errorf("control_plane.election_timeout: %w", err)
		}
	}
	for key, role := range c.API.AuthRoles {
		role = strings.ToLower(strings.TrimSpace(role))
		if role != "admin" && role != "analyst" && role != "auditor" && len(c.API.AuthPermissions[role]) == 0 {
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
	if strings.TrimSpace(c.Backup.Interval) != "" {
		if err := validateDurationString(c.Backup.Interval); err != nil {
			return fmt.Errorf("backup.interval: %w", err)
		}
	}
	if c.Backup.RetainArchives < 0 {
		return fmt.Errorf("backup.retain_archives must be non-negative")
	}
	if c.Backup.MinFreeBytes < 0 {
		return fmt.Errorf("backup.min_free_bytes must be non-negative")
	}
	if c.Compliance.RetentionDays < 0 {
		return fmt.Errorf("compliance.retention_days must be non-negative")
	}
	if c.Compliance.MaxAuditEntries < 0 {
		return fmt.Errorf("compliance.max_audit_entries must be non-negative")
	}
	if strings.TrimSpace(c.Compliance.ApprovalTTL) != "" {
		if err := validateDurationString(c.Compliance.ApprovalTTL); err != nil {
			return fmt.Errorf("compliance.approval_ttl: %w", err)
		}
	}
	if strings.TrimSpace(c.Compliance.ReportInterval) != "" {
		if err := validateDurationString(c.Compliance.ReportInterval); err != nil {
			return fmt.Errorf("compliance.report_interval: %w", err)
		}
	}
	if strings.TrimSpace(c.TLS.RotationCheck) != "" {
		if err := validateDurationString(c.TLS.RotationCheck); err != nil {
			return fmt.Errorf("tls.rotation_check: %w", err)
		}
	}
	if strings.TrimSpace(c.TLS.RotationRenewBefore) != "" {
		if err := validateDurationString(c.TLS.RotationRenewBefore); err != nil {
			return fmt.Errorf("tls.rotation_renew_before: %w", err)
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.Secrets.Provider)) {
	case "", "env", "file", "vault":
	default:
		return fmt.Errorf("unsupported secrets.provider %q", c.Secrets.Provider)
	}
	switch strings.ToLower(strings.TrimSpace(c.SIEM.Format)) {
	case "", "json", "cef":
	default:
		return fmt.Errorf("unsupported siem.format %q", c.SIEM.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.SIEM.Provider)) {
	case "", "generic", "splunk", "elastic":
	default:
		return fmt.Errorf("unsupported siem.provider %q", c.SIEM.Provider)
	}
	switch strings.ToUpper(strings.TrimSpace(c.SIEM.MinSeverity)) {
	case "", "INFO", "WARNING", "CRITICAL":
	default:
		return fmt.Errorf("unsupported siem.min_severity %q", c.SIEM.MinSeverity)
	}
	if strings.TrimSpace(c.SIEM.FlushInterval) != "" {
		if err := validateDurationString(c.SIEM.FlushInterval); err != nil {
			return fmt.Errorf("siem.flush_interval: %w", err)
		}
	}
	if c.License.GracePeriodDays < 0 {
		return fmt.Errorf("license.grace_period_days must be non-negative")
	}
	if c.License.MaxAgents < 0 {
		return fmt.Errorf("license.max_agents must be non-negative")
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
	if c.Upgrade.CanaryPercent < 0 || c.Upgrade.CanaryPercent > 100 {
		return fmt.Errorf("upgrade.canary_percent must be between 0 and 100")
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
	overrideString(&cfg.ControlPlane.Mode, "PROVIDAPT_CONTROL_PLANE_MODE")
	overrideString(&cfg.ControlPlane.NodeID, "PROVIDAPT_CONTROL_PLANE_NODE_ID")
	overrideString(&cfg.ControlPlane.Role, "PROVIDAPT_CONTROL_PLANE_ROLE")
	overrideString(&cfg.ControlPlane.LeaderID, "PROVIDAPT_CONTROL_PLANE_LEADER_ID")
	overrideString(&cfg.ControlPlane.StateBackend, "PROVIDAPT_CONTROL_PLANE_STATE_BACKEND")
	overrideString(&cfg.ControlPlane.Heartbeat, "PROVIDAPT_CONTROL_PLANE_HEARTBEAT")
	overrideString(&cfg.ControlPlane.ElectionTimeout, "PROVIDAPT_CONTROL_PLANE_ELECTION_TIMEOUT")
	overrideString(&cfg.Secrets.Provider, "PROVIDAPT_SECRETS_PROVIDER")
	overrideString(&cfg.Secrets.BaseDir, "PROVIDAPT_SECRETS_BASE_DIR")
	overrideString(&cfg.SSO.UserHeader, "PROVIDAPT_SSO_USER_HEADER")
	overrideString(&cfg.SSO.RoleHeader, "PROVIDAPT_SSO_ROLE_HEADER")
	overrideString(&cfg.SSO.TenantHeader, "PROVIDAPT_SSO_TENANT_HEADER")
	overrideString(&cfg.TLS.CertFile, "PROVIDAPT_TLS_CERT_FILE")
	overrideString(&cfg.TLS.KeyFile, "PROVIDAPT_TLS_KEY_FILE")
	overrideString(&cfg.TLS.CAFile, "PROVIDAPT_TLS_CA_FILE")
	overrideString(&cfg.TLS.RotationCheck, "PROVIDAPT_TLS_ROTATION_CHECK")
	overrideString(&cfg.TLS.RotationRenewBefore, "PROVIDAPT_TLS_ROTATION_RENEW_BEFORE")
	overrideString(&cfg.Storage.KeyFile, "PROVIDAPT_STORAGE_KEY_FILE")
	overrideString(&cfg.Telemetry.Endpoint, "PROVIDAPT_TELEMETRY_ENDPOINT")
	overrideString(&cfg.Telemetry.Interval, "PROVIDAPT_TELEMETRY_INTERVAL")
	overrideString(&cfg.Telemetry.CertFile, "PROVIDAPT_TELEMETRY_CERT_FILE")
	overrideString(&cfg.Telemetry.KeyFile, "PROVIDAPT_TELEMETRY_KEY_FILE")
	overrideString(&cfg.Telemetry.CAFile, "PROVIDAPT_TELEMETRY_CA_FILE")
	overrideString(&cfg.Telemetry.ServerName, "PROVIDAPT_TELEMETRY_SERVER_NAME")
	overrideString(&cfg.Policy.Endpoint, "PROVIDAPT_POLICY_ENDPOINT")
	overrideString(&cfg.Policy.APIKey, "PROVIDAPT_POLICY_API_KEY")
	overrideString(&cfg.Policy.PollInterval, "PROVIDAPT_POLICY_POLL_INTERVAL")
	overrideString(&cfg.Policy.BundleDir, "PROVIDAPT_POLICY_BUNDLE_DIR")
	overrideString(&cfg.Policy.CAFile, "PROVIDAPT_POLICY_CA_FILE")
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
	overrideString(&cfg.Upgrade.ApplyCommand, "PROVIDAPT_UPGRADE_APPLY_COMMAND")
	overrideString(&cfg.Upgrade.RollbackCommand, "PROVIDAPT_UPGRADE_ROLLBACK_COMMAND")
	overrideString(&cfg.Backup.Interval, "PROVIDAPT_BACKUP_INTERVAL")
	overrideString(&cfg.Compliance.ReportDir, "PROVIDAPT_COMPLIANCE_REPORT_DIR")
	overrideString(&cfg.Compliance.ApprovalTTL, "PROVIDAPT_COMPLIANCE_APPROVAL_TTL")
	overrideString(&cfg.Compliance.ReportInterval, "PROVIDAPT_COMPLIANCE_REPORT_INTERVAL")
	overrideString(&cfg.SIEM.Endpoint, "PROVIDAPT_SIEM_ENDPOINT")
	overrideString(&cfg.SIEM.Provider, "PROVIDAPT_SIEM_PROVIDER")
	overrideString(&cfg.SIEM.Token, "PROVIDAPT_SIEM_TOKEN")
	overrideString(&cfg.SIEM.Index, "PROVIDAPT_SIEM_INDEX")
	overrideString(&cfg.SIEM.SourceType, "PROVIDAPT_SIEM_SOURCE_TYPE")
	overrideString(&cfg.SIEM.Format, "PROVIDAPT_SIEM_FORMAT")
	overrideString(&cfg.SIEM.MinSeverity, "PROVIDAPT_SIEM_MIN_SEVERITY")
	overrideString(&cfg.SIEM.OutboxDir, "PROVIDAPT_SIEM_OUTBOX_DIR")
	overrideString(&cfg.SIEM.FlushInterval, "PROVIDAPT_SIEM_FLUSH_INTERVAL")

	overrideBool(&cfg.Kernel.Verbose, "PROVIDAPT_KERNEL_VERBOSE")
	overrideBool(&cfg.Capture.EnableNet, "PROVIDAPT_CAPTURE_ENABLE_NET")
	overrideBool(&cfg.Capture.EnableFile, "PROVIDAPT_CAPTURE_ENABLE_FILE")
	overrideBool(&cfg.Capture.EnableProc, "PROVIDAPT_CAPTURE_ENABLE_PROC")
	overrideBool(&cfg.Capture.SensitiveDir, "PROVIDAPT_CAPTURE_SENSITIVE_DIR")
	overrideBool(&cfg.Capture.AutoExcludeNoisy, "PROVIDAPT_CAPTURE_AUTO_EXCLUDE_NOISY")
	overrideBool(&cfg.Storage.Encrypt, "PROVIDAPT_STORAGE_ENCRYPT")
	overrideBool(&cfg.TLS.Enable, "PROVIDAPT_TLS_ENABLE")
	overrideBool(&cfg.TLS.RotationAuto, "PROVIDAPT_TLS_ROTATION_AUTO")
	overrideBool(&cfg.TLS.RotationRestartAfter, "PROVIDAPT_TLS_ROTATION_RESTART_AFTER")
	overrideBool(&cfg.API.AuthEnabled, "PROVIDAPT_API_AUTH_ENABLED")
	overrideBool(&cfg.ControlPlane.FailoverReady, "PROVIDAPT_CONTROL_PLANE_FAILOVER_READY")
	overrideBool(&cfg.SSO.TrustedHeaderAuth, "PROVIDAPT_SSO_TRUSTED_HEADER_AUTH")
	overrideBool(&cfg.Telemetry.EnableTLS, "PROVIDAPT_TELEMETRY_ENABLE_TLS")
	overrideBool(&cfg.Policy.Enabled, "PROVIDAPT_POLICY_ENABLED")
	overrideBool(&cfg.Policy.EnableTLS, "PROVIDAPT_POLICY_ENABLE_TLS")
	overrideBool(&cfg.SupportBundle.RedactArchives, "PROVIDAPT_SUPPORT_REDACT_ARCHIVES")
	overrideBool(&cfg.Backup.Enabled, "PROVIDAPT_BACKUP_ENABLED")
	overrideBool(&cfg.Backup.AllowActivation, "PROVIDAPT_BACKUP_ALLOW_ACTIVATION")
	overrideBool(&cfg.Compliance.RequireApprovals, "PROVIDAPT_COMPLIANCE_REQUIRE_APPROVALS")
	overrideBool(&cfg.SIEM.Enabled, "PROVIDAPT_SIEM_ENABLED")

	overrideInt(&cfg.Capture.MaxEvents, "PROVIDAPT_CAPTURE_MAX_EVENTS")
	overrideInt(&cfg.Output.RetainFiles, "PROVIDAPT_OUTPUT_RETAIN_FILES")
	overrideInt(&cfg.Output.AlertRetainFiles, "PROVIDAPT_OUTPUT_ALERT_RETAIN_FILES")
	overrideInt(&cfg.API.RateLimitBurst, "PROVIDAPT_API_RATE_LIMIT_BURST")
	overrideInt(&cfg.Notify.MaxAttempts, "PROVIDAPT_NOTIFY_MAX_ATTEMPTS")
	overrideInt(&cfg.SupportBundle.RetainArchives, "PROVIDAPT_SUPPORT_RETAIN_ARCHIVES")
	overrideInt(&cfg.License.GracePeriodDays, "PROVIDAPT_LICENSE_GRACE_PERIOD_DAYS")
	overrideInt(&cfg.License.MaxAgents, "PROVIDAPT_LICENSE_MAX_AGENTS")
	overrideInt(&cfg.Backup.RetainArchives, "PROVIDAPT_BACKUP_RETAIN_ARCHIVES")
	overrideInt(&cfg.Compliance.RetentionDays, "PROVIDAPT_COMPLIANCE_RETENTION_DAYS")
	overrideInt(&cfg.Compliance.MaxAuditEntries, "PROVIDAPT_COMPLIANCE_MAX_AUDIT_ENTRIES")
	overrideInt(&cfg.Upgrade.CanaryPercent, "PROVIDAPT_UPGRADE_CANARY_PERCENT")
	overrideInt64(&cfg.Backup.MinFreeBytes, "PROVIDAPT_BACKUP_MIN_FREE_BYTES")
	overrideInt64(&cfg.Output.MaxFileBytes, "PROVIDAPT_OUTPUT_MAX_FILE_BYTES")
	overrideInt64(&cfg.Output.RetainMaxBytes, "PROVIDAPT_OUTPUT_RETAIN_MAX_BYTES")
	overrideInt64(&cfg.Output.AlertMaxFileBytes, "PROVIDAPT_OUTPUT_ALERT_MAX_FILE_BYTES")
	overrideInt64(&cfg.Output.AlertRetainBytes, "PROVIDAPT_OUTPUT_ALERT_RETAIN_MAX_BYTES")

	overrideFloat(&cfg.API.RateLimitPerSec, "PROVIDAPT_API_RATE_LIMIT_PER_SEC")
	overrideUint32Slice(&cfg.Capture.ExcludePIDs, "PROVIDAPT_CAPTURE_EXCLUDE_PIDS")
	overrideStringSlice(&cfg.Capture.ExcludeComms, "PROVIDAPT_CAPTURE_EXCLUDE_COMMS")
	overrideStringSlice(&cfg.Capture.IncludeComms, "PROVIDAPT_CAPTURE_INCLUDE_COMMS")
	overrideStringSlice(&cfg.Capture.HotPaths, "PROVIDAPT_CAPTURE_HOT_PATHS")
	overrideStringSlice(&cfg.ControlPlane.Peers, "PROVIDAPT_CONTROL_PLANE_PEERS")
	overrideStringSlice(&cfg.Compliance.ApprovalActions, "PROVIDAPT_COMPLIANCE_APPROVAL_ACTIONS")
}

func shouldParseTOML(path string, data []byte) bool {
	if strings.EqualFold(filepath.Ext(path), ".toml") {
		trimmed := strings.TrimSpace(string(data))
		return strings.HasPrefix(trimmed, "[")
	}
	return false
}

func parseSimpleTOML(data []byte, cfg *Config) error {
	section := ""
	lines := strings.Split(string(data), "\n")
	for lineNo, raw := range lines {
		line := stripTOMLComment(strings.TrimSpace(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("line %d: expected key = value", lineNo+1)
		}
		if section == "" {
			return fmt.Errorf("line %d: key outside section", lineNo+1)
		}
		if err := setTOMLValue(cfg, section, strings.TrimSpace(key), strings.TrimSpace(value)); err != nil {
			return fmt.Errorf("line %d: %w", lineNo+1, err)
		}
	}
	return nil
}

func stripTOMLComment(line string) string {
	inQuote := false
	escaped := false
	for i, r := range line {
		switch {
		case escaped:
			escaped = false
		case r == '\\':
			escaped = true
		case r == '"':
			inQuote = !inQuote
		case r == '#' && !inQuote:
			return strings.TrimSpace(line[:i])
		}
	}
	return line
}

func setTOMLValue(cfg *Config, section, key, raw string) error {
	root := reflect.ValueOf(cfg).Elem()
	sectionValue, ok := fieldByYAMLTag(root, section)
	if !ok {
		return nil
	}
	field, ok := fieldByYAMLTag(sectionValue, key)
	if !ok || !field.CanSet() {
		return nil
	}
	return assignTOMLValue(field, raw)
}

func fieldByYAMLTag(value reflect.Value, tag string) (reflect.Value, bool) {
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return reflect.Value{}, false
	}
	valueType := value.Type()
	for i := 0; i < value.NumField(); i++ {
		field := valueType.Field(i)
		tagName := strings.Split(field.Tag.Get("yaml"), ",")[0]
		if tagName == tag {
			return value.Field(i), true
		}
	}
	return reflect.Value{}, false
}

func assignTOMLValue(field reflect.Value, raw string) error {
	if field.Type() == reflect.TypeOf(Duration{}) {
		var duration Duration
		if err := duration.parse(parseTOMLString(raw)); err != nil {
			return err
		}
		field.Set(reflect.ValueOf(duration))
		return nil
	}
	switch field.Kind() {
	case reflect.String:
		field.SetString(parseTOMLString(raw))
	case reflect.Bool:
		v, err := strconv.ParseBool(strings.ToLower(raw))
		if err != nil {
			return err
		}
		field.SetBool(v)
	case reflect.Int, reflect.Int64:
		n, err := strconv.ParseInt(raw, 10, field.Type().Bits())
		if err != nil {
			return err
		}
		field.SetInt(n)
	case reflect.Float64:
		n, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return err
		}
		field.SetFloat(n)
	case reflect.Slice:
		items, err := parseTOMLArray(raw)
		if err != nil {
			return err
		}
		slice := reflect.MakeSlice(field.Type(), 0, len(items))
		for _, item := range items {
			elem := reflect.New(field.Type().Elem()).Elem()
			switch elem.Kind() {
			case reflect.String:
				elem.SetString(parseTOMLString(item))
			case reflect.Uint32:
				n, err := strconv.ParseUint(item, 10, 32)
				if err != nil {
					return err
				}
				elem.SetUint(n)
			default:
				continue
			}
			slice = reflect.Append(slice, elem)
		}
		field.Set(slice)
	case reflect.Map:
		if field.Type().Key().Kind() != reflect.String || field.Type().Elem().Kind() != reflect.String {
			return nil
		}
		entries, err := parseTOMLInlineMap(raw)
		if err != nil {
			return err
		}
		m := reflect.MakeMap(field.Type())
		for k, v := range entries {
			m.SetMapIndex(reflect.ValueOf(k), reflect.ValueOf(v))
		}
		field.Set(m)
	}
	return nil
}

func parseTOMLString(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		unquoted, err := strconv.Unquote(raw)
		if err == nil {
			return unquoted
		}
		return raw[1 : len(raw)-1]
	}
	return raw
}

func parseTOMLArray(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "[") || !strings.HasSuffix(raw, "]") {
		return nil, fmt.Errorf("expected array")
	}
	body := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]"))
	if body == "" {
		return nil, nil
	}
	return splitTOMLCSV(body), nil
}

func parseTOMLInlineMap(raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "{") || !strings.HasSuffix(raw, "}") {
		return nil, fmt.Errorf("expected inline map")
	}
	body := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(raw, "{"), "}"))
	out := make(map[string]string)
	if body == "" {
		return out, nil
	}
	for _, part := range splitTOMLCSV(body) {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("invalid inline map item %q", part)
		}
		out[parseTOMLString(key)] = parseTOMLString(value)
	}
	return out, nil
}

func splitTOMLCSV(body string) []string {
	var parts []string
	var current strings.Builder
	inQuote := false
	escaped := false
	for _, r := range body {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\':
			current.WriteRune(r)
			escaped = true
		case r == '"':
			current.WriteRune(r)
			inQuote = !inQuote
		case r == ',' && !inQuote:
			parts = append(parts, strings.TrimSpace(current.String()))
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	if strings.TrimSpace(current.String()) != "" {
		parts = append(parts, strings.TrimSpace(current.String()))
	}
	return parts
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

func overrideInt64(field *int64, envKey string) {
	if v, ok := os.LookupEnv(envKey); ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
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
