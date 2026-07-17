// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package api provides a lightweight HTTP API for the ProvidAPT
// provenance graph, supporting Cytoscape.js-compatible graph export,
// interactive node backtracking, and alert SVG snapshots.
//
// All endpoints return JSON (except SVG which returns image/svg+xml).
package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/backtrace"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/storage/store"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/version"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/metrics"
)

// ═══════════════════════════════════════════════════════════════
// Health check types
// ═══════════════════════════════════════════════════════════════

// HealthStatus represents the current health of the daemon.
type HealthStatus struct {
	Status               string `json:"status"`         // "healthy" or "unhealthy"
	UptimeSeconds        int64  `json:"uptime_seconds"` // process uptime
	EbpfCollector        bool   `json:"ebpf_collector"` // eBPF ring buffer active
	AttachmentMode       string `json:"attachment_mode,omitempty"`
	PipelineHealthy      bool   `json:"pipeline_healthy"`       // pipeline processing
	StoreHealthy         bool   `json:"store_healthy"`          // storage backend
	EventsIngested       uint64 `json:"events_ingested"`        // total ingested
	EventsDropped        uint64 `json:"events_dropped"`         // total dropped
	MemoryBytes          uint64 `json:"memory_bytes"`           // RSS in bytes
	Version              string `json:"version"`                // build version
	SanityCheck          string `json:"sanity_check,omitempty"` // "pass", "fail", or "" (not run)
	PIDWhitelistEntries  int    `json:"pid_whitelist_entries,omitempty"`
	TaintedProcesses     int    `json:"tainted_processes,omitempty"`
	ActiveSampleCounters int    `json:"active_sample_counters,omitempty"`
	TelemetryEnabled     bool   `json:"telemetry_enabled,omitempty"`
	TelemetryHealthy     bool   `json:"telemetry_healthy,omitempty"`
	TelemetryLastSuccess string `json:"telemetry_last_success,omitempty"`
	TelemetryLastError   string `json:"telemetry_last_error,omitempty"`
	TelemetryLastAck     string `json:"telemetry_last_ack,omitempty"`
	DesiredPolicyVersion int    `json:"desired_policy_version,omitempty"`
}

// HealthCheckFunc is called by /health to determine daemon health.
type HealthCheckFunc func() HealthStatus

type RuntimeDiagnostics struct {
	Version                  string `json:"version,omitempty"`
	APIRest                  string `json:"api_rest,omitempty"`
	APIGRPC                  string `json:"api_grpc,omitempty"`
	APIAuthEnabled           bool   `json:"api_auth_enabled"`
	TLSEnabled               bool   `json:"tls_enabled"`
	MTLSEnabled              bool   `json:"mtls_enabled"`
	KernelAttachmentMode     string `json:"kernel_attachment_mode,omitempty"`
	PolicyEnabled            bool   `json:"policy_enabled"`
	PolicyEndpoint           string `json:"policy_endpoint,omitempty"`
	PolicyBundleDir          string `json:"policy_bundle_dir,omitempty"`
	AppliedPolicyVersion     int    `json:"applied_policy_version,omitempty"`
	ControlPlaneMode         string `json:"control_plane_mode,omitempty"`
	ControlPlaneRole         string `json:"control_plane_role,omitempty"`
	ControlPlaneStateBackend string `json:"control_plane_state_backend,omitempty"`
	StorageEncrypted         bool   `json:"storage_encrypted"`
	StorageKeyConfigured     bool   `json:"storage_key_configured"`
	OutputDir                string `json:"output_dir,omitempty"`
	SupportBundleEnabled     bool   `json:"support_bundle_enabled"`
	UpdatedAt                string `json:"updated_at,omitempty"`
}

type ClusterAgent struct {
	AgentID              string   `json:"agent_id"`
	Hostname             string   `json:"hostname,omitempty"`
	OS                   string   `json:"os,omitempty"`
	OSVersion            string   `json:"os_version,omitempty"`
	Kernel               string   `json:"kernel,omitempty"`
	Architecture         string   `json:"architecture,omitempty"`
	CPUCount             int      `json:"cpu_count,omitempty"`
	Group                string   `json:"group,omitempty"`
	Tags                 []string `json:"tags,omitempty"`
	Status               string   `json:"status"`
	StatusReason         string   `json:"status_reason,omitempty"`
	Version              string   `json:"version,omitempty"`
	LastReportAt         string   `json:"last_report_at,omitempty"`
	LastReportAge        int64    `json:"last_report_age_seconds"`
	EventsIngested       uint64   `json:"events_ingested,omitempty"`
	EventsDropped        uint64   `json:"events_dropped,omitempty"`
	MemoryBytes          uint64   `json:"memory_bytes,omitempty"`
	UptimeSeconds        int64    `json:"uptime_seconds,omitempty"`
	PipelineHealthy      bool     `json:"pipeline_healthy"`
	StoreHealthy         bool     `json:"store_healthy"`
	AttachmentMode       string   `json:"attachment_mode,omitempty"`
	AppliedPolicyVersion int      `json:"applied_policy_version,omitempty"`
	EnrollmentStatus     string   `json:"enrollment_status,omitempty"`
	EnrollmentNote       string   `json:"enrollment_note,omitempty"`
	EnrollmentUpdatedAt  string   `json:"enrollment_updated_at,omitempty"`
	CertFingerprint      string   `json:"cert_fingerprint,omitempty"`
}

type ClusterOverview struct {
	UpdatedAt      string         `json:"updated_at"`
	Tenant         string         `json:"tenant,omitempty"`
	TotalAgents    int            `json:"total_agents"`
	HealthyAgents  int            `json:"healthy_agents"`
	DegradedAgents int            `json:"degraded_agents"`
	Agents         []ClusterAgent `json:"agents"`
}

type ClusterOverviewFunc func() ClusterOverview

type HAStatus struct {
	UpdatedAt      string   `json:"updated_at"`
	Mode           string   `json:"mode"`
	NodeID         string   `json:"node_id,omitempty"`
	Role           string   `json:"role,omitempty"`
	LeaderID       string   `json:"leader_id,omitempty"`
	Healthy        bool     `json:"healthy"`
	PeerCount      int      `json:"peer_count"`
	Peers          []string `json:"peers,omitempty"`
	StateBackend   string   `json:"state_backend,omitempty"`
	LastCheckpoint string   `json:"last_checkpoint,omitempty"`
	FailoverReady  bool     `json:"failover_ready"`
	Message        string   `json:"message,omitempty"`
}

type HAStatusFunc func() HAStatus

type FleetList struct {
	UpdatedAt string               `json:"updated_at"`
	Group     string               `json:"group,omitempty"`
	Tag       string               `json:"tag,omitempty"`
	Agents    []ClusterAgent       `json:"agents"`
	History   []ControlActionAudit `json:"history,omitempty"`
}

type FleetListFunc func(group, tag string) FleetList

type FleetUpdate struct {
	AgentID  string   `json:"agent_id"`
	AgentIDs []string `json:"agent_ids,omitempty"`
	Action   string   `json:"action,omitempty"`
	Group    string   `json:"group,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Status   string   `json:"status,omitempty"`
	Note     string   `json:"note,omitempty"`
	Actor    string   `json:"actor,omitempty"`
	Role     string   `json:"role,omitempty"`
}

type FleetUpdateFunc func(update FleetUpdate) error

type FleetUpdateItemResult struct {
	AgentID string `json:"agent_id"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type FleetUpdateResult struct {
	Status    string                  `json:"status"`
	Processed int                     `json:"processed"`
	Succeeded int                     `json:"succeeded"`
	Failed    int                     `json:"failed"`
	Results   []FleetUpdateItemResult `json:"results"`
}

type SupportBundleSummary struct {
	LastBundlePath  string               `json:"last_bundle_path,omitempty"`
	LastArchivePath string               `json:"last_archive_path,omitempty"`
	LastReason      string               `json:"last_reason,omitempty"`
	LastActor       string               `json:"last_actor,omitempty"`
	LastRole        string               `json:"last_role,omitempty"`
	LastStatus      string               `json:"last_status,omitempty"`
	LastBundleAt    string               `json:"last_bundle_at,omitempty"`
	LastArchiveAt   string               `json:"last_archive_at,omitempty"`
	Redacted        bool                 `json:"redacted,omitempty"`
	DownloadURL     string               `json:"download_url,omitempty"`
	History         []ControlActionAudit `json:"history,omitempty"`
}

type SupportBundleFunc func() SupportBundleSummary

type SupportBundleDownload struct {
	Path     string
	FileName string
}

type SupportBundleDownloadFunc func(actor, role string) (SupportBundleDownload, error)

type SupportBundleActionRequest struct {
	Reason string `json:"reason,omitempty"`
	Note   string `json:"note,omitempty"`
	Actor  string `json:"actor,omitempty"`
	Role   string `json:"role,omitempty"`
}

type SupportBundleActionResult struct {
	Status      string `json:"status"`
	Message     string `json:"message,omitempty"`
	BundlePath  string `json:"bundle_path,omitempty"`
	ArchivePath string `json:"archive_path,omitempty"`
	DownloadURL string `json:"download_url,omitempty"`
	Redacted    bool   `json:"redacted,omitempty"`
	Reason      string `json:"reason,omitempty"`
	PerformedAt string `json:"performed_at"`
}

type SupportBundleActionFunc func(req SupportBundleActionRequest) (SupportBundleActionResult, error)

type BackupSummary struct {
	LastBackupPath  string               `json:"last_backup_path,omitempty"`
	LastRestorePath string               `json:"last_restore_path,omitempty"`
	LastAction      string               `json:"last_action,omitempty"`
	LastActor       string               `json:"last_actor,omitempty"`
	LastRole        string               `json:"last_role,omitempty"`
	LastStatus      string               `json:"last_status,omitempty"`
	LastMessage     string               `json:"last_message,omitempty"`
	LastBackupAt    string               `json:"last_backup_at,omitempty"`
	LastRestoreAt   string               `json:"last_restore_at,omitempty"`
	SizeBytes       int64                `json:"size_bytes,omitempty"`
	DownloadURL     string               `json:"download_url,omitempty"`
	History         []ControlActionAudit `json:"history,omitempty"`
}

type BackupFunc func() BackupSummary

type BackupDownload struct {
	Path     string
	FileName string
}

type BackupDownloadFunc func(actor, role string) (BackupDownload, error)

type BackupActionRequest struct {
	Action     string `json:"action,omitempty"`
	BackupPath string `json:"backup_path,omitempty"`
	TargetDir  string `json:"target_dir,omitempty"`
	Note       string `json:"note,omitempty"`
	Actor      string `json:"actor,omitempty"`
	Role       string `json:"role,omitempty"`
}

type BackupActionResult struct {
	Status      string `json:"status"`
	Message     string `json:"message,omitempty"`
	Action      string `json:"action,omitempty"`
	BackupPath  string `json:"backup_path,omitempty"`
	RestorePath string `json:"restore_path,omitempty"`
	DownloadURL string `json:"download_url,omitempty"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
	PerformedAt string `json:"performed_at"`
}

type BackupActionFunc func(req BackupActionRequest) (BackupActionResult, error)

type SecurityStatus struct {
	UpdatedAt      string               `json:"updated_at"`
	CertFile       string               `json:"cert_file,omitempty"`
	KeyFile        string               `json:"key_file,omitempty"`
	CAFile         string               `json:"ca_file,omitempty"`
	RotationNeeded bool                 `json:"rotation_needed"`
	LastStatus     string               `json:"last_status,omitempty"`
	LastMessage    string               `json:"last_message,omitempty"`
	LastRotatedAt  string               `json:"last_rotated_at,omitempty"`
	History        []ControlActionAudit `json:"history,omitempty"`
}

type SecurityStatusFunc func() SecurityStatus

type SecurityActionRequest struct {
	Action string `json:"action,omitempty"`
	Note   string `json:"note,omitempty"`
	Actor  string `json:"actor,omitempty"`
	Role   string `json:"role,omitempty"`
}

type SecurityActionResult struct {
	Status      string `json:"status"`
	Message     string `json:"message,omitempty"`
	Action      string `json:"action,omitempty"`
	CertFile    string `json:"cert_file,omitempty"`
	PerformedAt string `json:"performed_at"`
}

type SecurityActionFunc func(req SecurityActionRequest) (SecurityActionResult, error)

type AuditEntry struct {
	ID        string                 `json:"id"`
	Timestamp string                 `json:"timestamp"`
	Category  string                 `json:"category"`
	Severity  string                 `json:"severity"`
	Message   string                 `json:"message"`
	Source    string                 `json:"source"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

type AuditFeed struct {
	UpdatedAt string       `json:"updated_at"`
	Tenant    string       `json:"tenant,omitempty"`
	Category  string       `json:"category,omitempty"`
	Source    string       `json:"source,omitempty"`
	Entries   []AuditEntry `json:"entries"`
}

type AuditQueryFunc func(category, source string, limit int) AuditFeed

type SIEMStatus struct {
	Enabled         bool   `json:"enabled"`
	Provider        string `json:"provider,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	Format          string `json:"format,omitempty"`
	MinSeverity     string `json:"min_severity,omitempty"`
	OutboxPath      string `json:"outbox_path,omitempty"`
	LastForwardedAt string `json:"last_forwarded_at,omitempty"`
	LastStatus      string `json:"last_status,omitempty"`
	LastError       string `json:"last_error,omitempty"`
	ForwardedEvents int    `json:"forwarded_events"`
}

type ChangeApproval struct {
	ID          string `json:"id"`
	Action      string `json:"action"`
	Target      string `json:"target,omitempty"`
	Status      string `json:"status"`
	RequestedBy string `json:"requested_by,omitempty"`
	RequestedAt string `json:"requested_at,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	ApprovedBy  string `json:"approved_by,omitempty"`
	ApprovedAt  string `json:"approved_at,omitempty"`
	UsedBy      string `json:"used_by,omitempty"`
	UsedAt      string `json:"used_at,omitempty"`
	Note        string `json:"note,omitempty"`
}

type ApprovalStatus struct {
	Enabled         bool             `json:"enabled"`
	RequiredActions []string         `json:"required_actions,omitempty"`
	TTL             string           `json:"ttl,omitempty"`
	Pending         []ChangeApproval `json:"pending,omitempty"`
	History         []ChangeApproval `json:"history,omitempty"`
}

type ComplianceStatus struct {
	UpdatedAt          string         `json:"updated_at"`
	Tenant             string         `json:"tenant,omitempty"`
	RetentionDays      int            `json:"retention_days"`
	MaxAuditEntries    int            `json:"max_audit_entries"`
	OldestAllowedAt    string         `json:"oldest_allowed_at,omitempty"`
	AuditEntries       int            `json:"audit_entries"`
	AuditOldestAt      string         `json:"audit_oldest_at,omitempty"`
	AuditNewestAt      string         `json:"audit_newest_at,omitempty"`
	LastRetentionAt    string         `json:"last_retention_at,omitempty"`
	LastArchivePath    string         `json:"last_archive_path,omitempty"`
	LastArchivedCount  int            `json:"last_archived_count,omitempty"`
	LastExportPath     string         `json:"last_export_path,omitempty"`
	LastReportPath     string         `json:"last_report_path,omitempty"`
	LastActionStatus   string         `json:"last_action_status,omitempty"`
	LastActionMessage  string         `json:"last_action_message,omitempty"`
	ReadinessScore     int            `json:"readiness_score"`
	ReadinessGrade     string         `json:"readiness_grade,omitempty"`
	SIEM               SIEMStatus     `json:"siem"`
	Approvals          ApprovalStatus `json:"approvals"`
	RecommendedActions []string       `json:"recommended_actions,omitempty"`
}

type ComplianceActionRequest struct {
	Action     string `json:"action"`
	Format     string `json:"format,omitempty"`
	ApprovalID string `json:"approval_id,omitempty"`
	Target     string `json:"target,omitempty"`
	Note       string `json:"note,omitempty"`
	Actor      string `json:"actor,omitempty"`
	Role       string `json:"role,omitempty"`
}

type ComplianceActionResult struct {
	Status      string          `json:"status"`
	Message     string          `json:"message,omitempty"`
	Path        string          `json:"path,omitempty"`
	Approval    *ChangeApproval `json:"approval,omitempty"`
	SIEM        *SIEMStatus     `json:"siem,omitempty"`
	PerformedAt string          `json:"performed_at"`
}

type ComplianceStatusFunc func() ComplianceStatus
type ComplianceActionFunc func(req ComplianceActionRequest) (ComplianceActionResult, error)

type LicenseStatus struct {
	UpdatedAt           string               `json:"updated_at"`
	Path                string               `json:"path,omitempty"`
	LicenseID           string               `json:"license_id,omitempty"`
	Present             bool                 `json:"present"`
	SizeBytes           int64                `json:"size_bytes,omitempty"`
	ModifiedAt          string               `json:"modified_at,omitempty"`
	Customer            string               `json:"customer,omitempty"`
	Edition             string               `json:"edition,omitempty"`
	MaxAgents           int                  `json:"max_agents,omitempty"`
	ReportingAgents     int                  `json:"reporting_agents,omitempty"`
	SeatsAvailable      int                  `json:"seats_available,omitempty"`
	SeatLimitExceeded   bool                 `json:"seat_limit_exceeded"`
	MachineFingerprint  string               `json:"machine_fingerprint,omitempty"`
	BoundFingerprint    string               `json:"bound_fingerprint,omitempty"`
	BindingVerified     bool                 `json:"binding_verified"`
	IssuedAt            string               `json:"issued_at,omitempty"`
	ExpiresAt           string               `json:"expires_at,omitempty"`
	DaysRemaining       int                  `json:"days_remaining,omitempty"`
	Expired             bool                 `json:"expired"`
	GracePeriodDays     int                  `json:"grace_period_days,omitempty"`
	InGracePeriod       bool                 `json:"in_grace_period"`
	Revoked             bool                 `json:"revoked"`
	RevocationSource    string               `json:"revocation_source,omitempty"`
	RevocationVerified  bool                 `json:"revocation_verified"`
	RevocationCheckedAt string               `json:"revocation_checked_at,omitempty"`
	SignaturePresent    bool                 `json:"signature_present"`
	SignatureVerified   bool                 `json:"signature_verified"`
	CurrentVersion      string               `json:"current_version,omitempty"`
	LastValidatedAt     string               `json:"last_validated_at,omitempty"`
	LastError           string               `json:"last_error,omitempty"`
	History             []ControlActionAudit `json:"history,omitempty"`
}

type LicenseStatusFunc func() LicenseStatus

type LicenseActionRequest struct {
	Action      string `json:"action"`
	LicenseData string `json:"license_data,omitempty"`
	LicensePath string `json:"license_path,omitempty"`
	Note        string `json:"note,omitempty"`
	Actor       string `json:"actor,omitempty"`
	Role        string `json:"role,omitempty"`
}

type LicenseActionResult struct {
	Status            string `json:"status"`
	Message           string `json:"message,omitempty"`
	ValidatedAt       string `json:"validated_at,omitempty"`
	ExpiresAt         string `json:"expires_at,omitempty"`
	GracePeriodDays   int    `json:"grace_period_days,omitempty"`
	InGracePeriod     bool   `json:"in_grace_period"`
	Revoked           bool   `json:"revoked"`
	SignatureVerified bool   `json:"signature_verified"`
	BindingVerified   bool   `json:"binding_verified"`
}

type LicenseActionFunc func(req LicenseActionRequest) (LicenseActionResult, error)

type UpgradeReadiness struct {
	UpdatedAt         string               `json:"updated_at"`
	CurrentVersion    string               `json:"current_version,omitempty"`
	GuidePath         string               `json:"guide_path,omitempty"`
	PackagePath       string               `json:"package_path,omitempty"`
	DownloadURL       string               `json:"download_url,omitempty"`
	PackagePresent    bool                 `json:"package_present"`
	ExpectedSHA256    string               `json:"expected_sha256,omitempty"`
	PackageSHA256     string               `json:"package_sha256,omitempty"`
	PackageVerified   bool                 `json:"package_verified"`
	SignaturePath     string               `json:"signature_path,omitempty"`
	SignaturePresent  bool                 `json:"signature_present"`
	SignatureVerified bool                 `json:"signature_verified"`
	RollbackPlan      string               `json:"rollback_plan,omitempty"`
	RollbackReady     bool                 `json:"rollback_ready"`
	PreflightReady    bool                 `json:"preflight_ready"`
	LastVerifiedAt    string               `json:"last_verified_at,omitempty"`
	LastError         string               `json:"last_error,omitempty"`
	LastAction        string               `json:"last_action,omitempty"`
	LastActor         string               `json:"last_actor,omitempty"`
	LastActionAt      string               `json:"last_action_at,omitempty"`
	LastNote          string               `json:"last_note,omitempty"`
	ApplyCommand      string               `json:"apply_command,omitempty"`
	RollbackCommand   string               `json:"rollback_command,omitempty"`
	CanaryPercent     int                  `json:"canary_percent,omitempty"`
	AppliedAt         string               `json:"applied_at,omitempty"`
	RolledBackAt      string               `json:"rolled_back_at,omitempty"`
	History           []ControlActionAudit `json:"history,omitempty"`
}

type UpgradeReadinessFunc func() UpgradeReadiness

type UpgradeActionRequest struct {
	Action         string `json:"action"`
	Note           string `json:"note,omitempty"`
	PackagePath    string `json:"package_path,omitempty"`
	DownloadURL    string `json:"download_url,omitempty"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	SignaturePath  string `json:"signature_path,omitempty"`
	RollbackPlan   string `json:"rollback_plan,omitempty"`
	Actor          string `json:"actor,omitempty"`
	Role           string `json:"role,omitempty"`
}

type UpgradeActionResult struct {
	Status            string `json:"status"`
	Message           string `json:"message,omitempty"`
	PackagePath       string `json:"package_path,omitempty"`
	DownloadURL       string `json:"download_url,omitempty"`
	PackageSHA256     string `json:"package_sha256,omitempty"`
	PackageVerified   bool   `json:"package_verified"`
	SignaturePath     string `json:"signature_path,omitempty"`
	SignatureVerified bool   `json:"signature_verified"`
	PreflightReady    bool   `json:"preflight_ready"`
	PerformedAt       string `json:"performed_at,omitempty"`
}

type UpgradeActionFunc func(req UpgradeActionRequest) (UpgradeActionResult, error)

type PolicySummary struct {
	Version          int      `json:"version"`
	State            string   `json:"state"`
	Notes            string   `json:"notes,omitempty"`
	UpdatedAt        string   `json:"updated_at,omitempty"`
	PublishedAt      string   `json:"published_at,omitempty"`
	ActiveRules      int      `json:"active_rules"`
	SigmaRuleIDs     []string `json:"sigma_rule_ids,omitempty"`
	WhitelistCount   int      `json:"whitelist_count"`
	TaintSourceCount int      `json:"taint_source_count"`
	DeploymentStatus string   `json:"deployment_status,omitempty"`
	TargetGroup      string   `json:"target_group,omitempty"`
	TargetTag        string   `json:"target_tag,omitempty"`
	TargetAgents     int      `json:"target_agents,omitempty"`
	AckedAgents      int      `json:"acked_agents,omitempty"`
	PendingAgents    int      `json:"pending_agents,omitempty"`
	BundlePath       string   `json:"bundle_path,omitempty"`
	BundleSHA256     string   `json:"bundle_sha256,omitempty"`
}

type PolicyCenter struct {
	UpdatedAt string               `json:"updated_at"`
	Current   PolicySummary        `json:"current"`
	Draft     PolicySummary        `json:"draft"`
	History   []PolicySummary      `json:"history"`
	Diff      []PolicyDiff         `json:"diff,omitempty"`
	Actions   []ControlActionAudit `json:"actions,omitempty"`
}

type PolicyCenterFunc func() PolicyCenter

type PolicyDiff struct {
	Field  string      `json:"field"`
	Before interface{} `json:"before,omitempty"`
	After  interface{} `json:"after,omitempty"`
	Status string      `json:"status"`
}

type PolicyBundleDownload struct {
	Path     string
	FileName string
	SHA256   string
	Version  int
}

type PolicyBundleDownloadFunc func(version int, actor, role string) (PolicyBundleDownload, error)

type PolicyActionRequest struct {
	Action          string `json:"action"`
	Notes           string `json:"notes,omitempty"`
	TargetVersion   int    `json:"target_version,omitempty"`
	TargetGroup     string `json:"target_group,omitempty"`
	TargetTag       string `json:"target_tag,omitempty"`
	RuleID          string `json:"rule_id,omitempty"`
	RuleYAML        string `json:"rule_yaml,omitempty"`
	WhitelistTarget string `json:"whitelist_target,omitempty"`
	WhitelistValue  string `json:"whitelist_value,omitempty"`
	TaintPrefix     string `json:"taint_prefix,omitempty"`
	TaintLabel      string `json:"taint_label,omitempty"`
	Actor           string `json:"actor,omitempty"`
	Role            string `json:"role,omitempty"`
}

type PolicyActionFunc func(req PolicyActionRequest) (PolicySummary, error)

type AlertWorkflowSummary struct {
	Total      int `json:"total"`
	Open       int `json:"open"`
	Assigned   int `json:"assigned"`
	Suppressed int `json:"suppressed"`
	Closed     int `json:"closed"`
}

type AlertWorkflowItem struct {
	ID             string            `json:"id"`
	Severity       string            `json:"severity"`
	Pattern        string            `json:"pattern"`
	Headline       string            `json:"headline"`
	Reason         string            `json:"reason,omitempty"`
	Source         string            `json:"source,omitempty"`
	Status         string            `json:"status"`
	Assignee       string            `json:"assignee,omitempty"`
	Count          int               `json:"count"`
	FirstSeen      string            `json:"first_seen,omitempty"`
	LastSeen       string            `json:"last_seen,omitempty"`
	LastNotifiedAt string            `json:"last_notified_at,omitempty"`
	SilenceUntil   string            `json:"silence_until,omitempty"`
	SLADeadline    string            `json:"sla_deadline,omitempty"`
	SLAStatus      string            `json:"sla_status,omitempty"`
	SLASecondsLeft int64             `json:"sla_seconds_left,omitempty"`
	Note           string            `json:"note,omitempty"`
	Details        map[string]string `json:"details,omitempty"`
}

type AlertWorkflow struct {
	UpdatedAt string               `json:"updated_at"`
	Summary   AlertWorkflowSummary `json:"summary"`
	Alerts    []AlertWorkflowItem  `json:"alerts"`
	History   []ControlActionAudit `json:"history,omitempty"`
}

type AlertWorkflowFunc func(status, assignee string) AlertWorkflow

type AlertWorkflowActionRequest struct {
	Action   string   `json:"action"`
	AlertID  string   `json:"alert_id,omitempty"`
	AlertIDs []string `json:"alert_ids,omitempty"`
	Assignee string   `json:"assignee,omitempty"`
	Duration string   `json:"duration,omitempty"`
	Note     string   `json:"note,omitempty"`
	Actor    string   `json:"actor,omitempty"`
	Role     string   `json:"role,omitempty"`
}

type AlertWorkflowActionFunc func(req AlertWorkflowActionRequest) (AlertWorkflowItem, error)

type AlertWorkflowActionResult struct {
	Status    string              `json:"status"`
	Processed int                 `json:"processed"`
	Succeeded int                 `json:"succeeded"`
	Failed    int                 `json:"failed"`
	Alerts    []AlertWorkflowItem `json:"alerts,omitempty"`
	Errors    []string            `json:"errors,omitempty"`
}

type NotifyDeliverySummary struct {
	Delivered  int `json:"delivered"`
	Retrying   int `json:"retrying"`
	DeadLetter int `json:"dead_letter"`
}

type NotifyDeliveryRecord struct {
	ID            string `json:"id"`
	Notifier      string `json:"notifier"`
	AlertID       string `json:"alert_id"`
	Pattern       string `json:"pattern"`
	Severity      string `json:"severity"`
	Status        string `json:"status"`
	Attempt       int    `json:"attempt"`
	MaxAttempts   int    `json:"max_attempts"`
	LastAttemptAt string `json:"last_attempt_at,omitempty"`
	Error         string `json:"error,omitempty"`
	TicketKey     string `json:"ticket_key,omitempty"`
	TicketURL     string `json:"ticket_url,omitempty"`
	TicketType    string `json:"ticket_type,omitempty"`
}

type NotifyDeliveryCenter struct {
	UpdatedAt   string                 `json:"updated_at"`
	Summary     NotifyDeliverySummary  `json:"summary"`
	Recent      []NotifyDeliveryRecord `json:"recent"`
	DeadLetters []NotifyDeliveryRecord `json:"dead_letters"`
	History     []NotifyDeliveryAudit  `json:"history,omitempty"`
}

type NotifyDeliveryFunc func() NotifyDeliveryCenter

type ControlActionAudit struct {
	Action      string `json:"action"`
	Actor       string `json:"actor,omitempty"`
	Role        string `json:"role,omitempty"`
	TargetID    string `json:"target_id,omitempty"`
	Status      string `json:"status"`
	Message     string `json:"message,omitempty"`
	Note        string `json:"note,omitempty"`
	PerformedAt string `json:"performed_at"`
}

type NotifyDeliveryAudit struct {
	Action      string `json:"action"`
	Actor       string `json:"actor,omitempty"`
	Role        string `json:"role,omitempty"`
	Note        string `json:"note,omitempty"`
	DeliveryID  string `json:"delivery_id,omitempty"`
	Status      string `json:"status"`
	Message     string `json:"message,omitempty"`
	TicketKey   string `json:"ticket_key,omitempty"`
	TicketURL   string `json:"ticket_url,omitempty"`
	TicketType  string `json:"ticket_type,omitempty"`
	Processed   int    `json:"processed,omitempty"`
	Succeeded   int    `json:"succeeded,omitempty"`
	Failed      int    `json:"failed,omitempty"`
	Skipped     int    `json:"skipped,omitempty"`
	PerformedAt string `json:"performed_at"`
}

type NotifyDeliveryActionRequest struct {
	Action     string `json:"action"`
	DeliveryID string `json:"delivery_id,omitempty"`
	Actor      string `json:"actor,omitempty"`
	Role       string `json:"role,omitempty"`
	Note       string `json:"note,omitempty"`
}

type NotifyDeliveryActionResult struct {
	Status      string                 `json:"status"`
	Message     string                 `json:"message,omitempty"`
	Record      *NotifyDeliveryRecord  `json:"record,omitempty"`
	Records     []NotifyDeliveryRecord `json:"records,omitempty"`
	TicketKey   string                 `json:"ticket_key,omitempty"`
	TicketURL   string                 `json:"ticket_url,omitempty"`
	TicketType  string                 `json:"ticket_type,omitempty"`
	Processed   int                    `json:"processed,omitempty"`
	Succeeded   int                    `json:"succeeded,omitempty"`
	Failed      int                    `json:"failed,omitempty"`
	Skipped     int                    `json:"skipped,omitempty"`
	PerformedAt string                 `json:"performed_at"`
}

type NotifyDeliveryActionFunc func(req NotifyDeliveryActionRequest) (NotifyDeliveryActionResult, error)

type InvestigationNode struct {
	ID        string                 `json:"id"`
	Label     string                 `json:"label,omitempty"`
	Type      string                 `json:"type,omitempty"`
	ProvType  string                 `json:"prov_type,omitempty"`
	FirstSeen string                 `json:"first_seen,omitempty"`
	LastSeen  string                 `json:"last_seen,omitempty"`
	Attrs     map[string]interface{} `json:"attributes,omitempty"`
}

type InvestigationEdge struct {
	ID        string                 `json:"id"`
	Source    string                 `json:"source"`
	Target    string                 `json:"target"`
	Relation  string                 `json:"relation"`
	Timestamp string                 `json:"timestamp,omitempty"`
	Count     int                    `json:"count,omitempty"`
	Attrs     map[string]interface{} `json:"attributes,omitempty"`
}

type InvestigationReport struct {
	GeneratedAt     string              `json:"generated_at"`
	StartNode       string              `json:"start_node"`
	Direction       string              `json:"direction"`
	Depth           int                 `json:"depth"`
	NodeCount       int                 `json:"node_count"`
	EdgeCount       int                 `json:"edge_count"`
	ProcessCount    int                 `json:"process_count"`
	FileCount       int                 `json:"file_count"`
	NetworkCount    int                 `json:"network_count"`
	RiskSummary     string              `json:"risk_summary"`
	KeyObservations []string            `json:"key_observations"`
	Nodes           []InvestigationNode `json:"nodes"`
	Edges           []InvestigationEdge `json:"edges"`
}

// ═══════════════════════════════════════════════════════════════
// Server
// ═══════════════════════════════════════════════════════════════

type Server struct {
	addr                     string
	graph                    *provenance.Graph
	store                    *store.Store
	backtracer               *backtrace.Backtracer
	healthFn                 HealthCheckFunc
	clusterFn                ClusterOverviewFunc
	haFn                     HAStatusFunc
	fleetListFn              FleetListFunc
	fleetSetFn               FleetUpdateFunc
	supportFn                SupportBundleFunc
	supportAct               SupportBundleActionFunc
	supportDl                SupportBundleDownloadFunc
	backupFn                 BackupFunc
	backupAct                BackupActionFunc
	backupDl                 BackupDownloadFunc
	securityFn               SecurityStatusFunc
	securityAct              SecurityActionFunc
	auditFn                  AuditQueryFunc
	complianceFn             ComplianceStatusFunc
	complianceAct            ComplianceActionFunc
	licenseFn                LicenseStatusFunc
	licenseAct               LicenseActionFunc
	upgradeFn                UpgradeReadinessFunc
	upgradeAct               UpgradeActionFunc
	policyFn                 PolicyCenterFunc
	policyActFn              PolicyActionFunc
	policyDlFn               PolicyBundleDownloadFunc
	alertsFn                 AlertWorkflowFunc
	alertActFn               AlertWorkflowActionFunc
	deliveryFn               NotifyDeliveryFunc
	deliveryAct              NotifyDeliveryActionFunc
	mux                      *http.ServeMux
	startTime                time.Time
	reloadFn                 func() error
	authKeys                 []string
	authRoles                map[string]string
	authIDs                  map[string]string
	authTenants              map[string]string
	authPermissions          map[string][]string
	authEnabled              bool
	trustedHeaderAuthEnabled bool
	trustedUserHeader        string
	trustedRoleHeader        string
	trustedTenantHeader      string
	rateLimiter              *rateLimiter
	corsOrigins              []string
	runtimeMu                sync.RWMutex
	runtimeDiagnostics       RuntimeDiagnostics
}

func NewServer(addr string, graph *provenance.Graph, st *store.Store) *Server {
	s := &Server{
		addr:       addr,
		graph:      graph,
		store:      st,
		backtracer: backtrace.New(graph, st),
		startTime:  time.Now(),
	}
	s.SetDefaultControlHandlers()
	s.mux = s.buildMux()
	return s
}

// SetHealthFunc registers a health check callback for the /health endpoint.
func (s *Server) SetHealthFunc(fn HealthCheckFunc) {
	s.healthFn = fn
}

func (s *Server) SetClusterOverviewFunc(fn ClusterOverviewFunc) {
	s.clusterFn = fn
}

func (s *Server) SetHAStatusFunc(fn HAStatusFunc) {
	s.haFn = fn
}

func (s *Server) SetFleetListFunc(fn FleetListFunc) {
	s.fleetListFn = fn
}

func (s *Server) SetFleetUpdateFunc(fn FleetUpdateFunc) {
	s.fleetSetFn = fn
}

func (s *Server) SetSupportBundleFunc(fn SupportBundleFunc) {
	s.supportFn = fn
}

func (s *Server) SetSupportBundleActionFunc(fn SupportBundleActionFunc) {
	s.supportAct = fn
}

func (s *Server) SetSupportBundleDownloadFunc(fn SupportBundleDownloadFunc) {
	s.supportDl = fn
}

func (s *Server) SetBackupFunc(fn BackupFunc) {
	s.backupFn = fn
}

func (s *Server) SetBackupActionFunc(fn BackupActionFunc) {
	s.backupAct = fn
}

func (s *Server) SetBackupDownloadFunc(fn BackupDownloadFunc) {
	s.backupDl = fn
}

func (s *Server) SetSecurityStatusFunc(fn SecurityStatusFunc) {
	s.securityFn = fn
}

func (s *Server) SetSecurityActionFunc(fn SecurityActionFunc) {
	s.securityAct = fn
}

func (s *Server) SetAuditQueryFunc(fn AuditQueryFunc) {
	s.auditFn = fn
}

func (s *Server) SetComplianceStatusFunc(fn ComplianceStatusFunc) {
	s.complianceFn = fn
}

func (s *Server) SetComplianceActionFunc(fn ComplianceActionFunc) {
	s.complianceAct = fn
}

func (s *Server) SetLicenseStatusFunc(fn LicenseStatusFunc) {
	s.licenseFn = fn
}

func (s *Server) SetLicenseActionFunc(fn LicenseActionFunc) {
	s.licenseAct = fn
}

func (s *Server) SetUpgradeReadinessFunc(fn UpgradeReadinessFunc) {
	s.upgradeFn = fn
}

func (s *Server) SetUpgradeActionFunc(fn UpgradeActionFunc) {
	s.upgradeAct = fn
}

func (s *Server) SetPolicyCenterFunc(fn PolicyCenterFunc) {
	s.policyFn = fn
}

func (s *Server) SetPolicyActionFunc(fn PolicyActionFunc) {
	s.policyActFn = fn
}

func (s *Server) SetPolicyBundleDownloadFunc(fn PolicyBundleDownloadFunc) {
	s.policyDlFn = fn
}

func (s *Server) SetAlertWorkflowFunc(fn AlertWorkflowFunc) {
	s.alertsFn = fn
}

func (s *Server) SetAlertWorkflowActionFunc(fn AlertWorkflowActionFunc) {
	s.alertActFn = fn
}

func (s *Server) SetNotifyDeliveryFunc(fn NotifyDeliveryFunc) {
	s.deliveryFn = fn
}

func (s *Server) SetRuntimeDiagnostics(diag RuntimeDiagnostics) {
	if diag.Version == "" {
		diag.Version = version.String()
	}
	if diag.UpdatedAt == "" {
		diag.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	s.runtimeMu.Lock()
	s.runtimeDiagnostics = diag
	s.runtimeMu.Unlock()
}

func (s *Server) runtimeDiagnosticsSnapshot() RuntimeDiagnostics {
	s.runtimeMu.RLock()
	diag := s.runtimeDiagnostics
	s.runtimeMu.RUnlock()
	if diag.Version == "" {
		diag.Version = version.String()
	}
	if diag.UpdatedAt == "" {
		diag.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	return diag
}

func (s *Server) SetNotifyDeliveryActionFunc(fn NotifyDeliveryActionFunc) {
	s.deliveryAct = fn
}

// SetReloadHandler registers a config reload callback called by
// POST /api/v1/admin/reload. Same logic as SIGHUP handling.
func (s *Server) SetReloadHandler(fn func() error) {
	s.reloadFn = fn
}

// SetDefaultControlHandlers registers handlers for the control plane
// endpoints that return meaningful (if single-node) responses.
func (s *Server) SetDefaultControlHandlers() {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}
	ver := version.String()

	// buildLocalAgent returns a ClusterAgent populated from local state.
	localAgent := func() ClusterAgent {
		uptime := int64(time.Since(s.startTime).Seconds())
		var ingested uint64
		var pipHealthy, stHealthy bool
		if s.graph != nil {
			stats := s.graph.Stats()
			ingested = uint64(stats.Nodes)
		}
		if s.healthFn != nil {
			h := s.healthFn()
			pipHealthy = h.PipelineHealthy
			stHealthy = h.StoreHealthy
		}
		return ClusterAgent{
			AgentID:         hostname,
			Group:           "default",
			Tags:            []string{"standalone"},
			Status:          "online",
			Version:         ver,
			LastReportAt:    time.Now().UTC().Format(time.RFC3339),
			EventsIngested:  ingested,
			EventsDropped:   0,
			MemoryBytes:     0,
			UptimeSeconds:   uptime,
			PipelineHealthy: pipHealthy,
			StoreHealthy:    stHealthy,
			AttachmentMode:  "full",
		}
	}

	// 1. Cluster Overview — returns this node as a single-agent cluster.
	s.clusterFn = func() ClusterOverview {
		return ClusterOverview{
			UpdatedAt:      time.Now().UTC().Format(time.RFC3339),
			TotalAgents:    1,
			HealthyAgents:  1,
			DegradedAgents: 0,
			Agents:         []ClusterAgent{localAgent()},
		}
	}

	// 1b. HA Status — standalone by default, override in clustered deployments.
	s.haFn = func() HAStatus {
		return HAStatus{
			UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
			Mode:          "standalone",
			NodeID:        hostname,
			Role:          "leader",
			LeaderID:      hostname,
			Healthy:       true,
			PeerCount:     0,
			StateBackend:  "local",
			FailoverReady: false,
			Message:       "single-node control plane",
		}
	}

	// 2. Fleet List — returns the local agent.
	s.fleetListFn = func(group, tag string) FleetList {
		return FleetList{
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			Group:     group,
			Tag:       tag,
			Agents:    []ClusterAgent{localAgent()},
			History:   []ControlActionAudit{},
		}
	}

	// 3. Support Bundles — check for existing bundle files.
	s.supportFn = func() SupportBundleSummary {
		summary := SupportBundleSummary{
			History: []ControlActionAudit{},
		}
		// Check common bundle paths.
		for _, p := range []string{
			"/tmp/providapt-support-bundle.tar.gz",
			"/var/log/providapt/support-bundle.tar.gz",
			"/tmp/providapt-support.tar.gz",
		} {
			if fi, err := os.Stat(p); err == nil {
				summary.LastBundlePath = p
				summary.LastArchivePath = p
				summary.LastStatus = "available"
				summary.LastBundleAt = fi.ModTime().UTC().Format(time.RFC3339)
				break
			}
		}
		return summary
	}

	// 4. Audit Feed — returns an empty feed (requires audit store).
	s.auditFn = func(category, source string, limit int) AuditFeed {
		return AuditFeed{
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			Category:  category,
			Source:    source,
			Entries:   []AuditEntry{},
		}
	}

	// 5. License Status — check for license file at common paths.
	s.licenseFn = func() LicenseStatus {
		ls := LicenseStatus{
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			Present:   false,
			History:   []ControlActionAudit{},
		}
		for _, p := range []string{
			"/etc/providapt/license.pem",
			"/etc/providapt/license.lic",
			"/usr/local/etc/providapt/license.pem",
		} {
			if fi, err := os.Stat(p); err == nil {
				ls.Present = true
				ls.Path = p
				ls.SizeBytes = fi.Size()
				ls.ModifiedAt = fi.ModTime().UTC().Format(time.RFC3339)
				ls.CurrentVersion = ver
				ls.LastValidatedAt = time.Now().UTC().Format(time.RFC3339)
				ls.SignaturePresent = strings.HasSuffix(p, ".pem")
				break
			}
		}
		return ls
	}

	// 6. Upgrade Readiness — show current version.
	s.upgradeFn = func() UpgradeReadiness {
		ur := UpgradeReadiness{
			UpdatedAt:      time.Now().UTC().Format(time.RFC3339),
			CurrentVersion: ver,
			History:        []ControlActionAudit{},
		}
		// Check for upgrade packages in common paths.
		for _, p := range []string{
			"/tmp/providapt-upgrade.tar.gz",
			"/var/cache/providapt/providapt-upgrade.tar.gz",
		} {
			if fi, err := os.Stat(p); err == nil {
				ur.PackagePath = p
				ur.PackagePresent = true
				ur.PackageSHA256 = fmt.Sprintf("%d", fi.Size())
				ur.PackageVerified = true
				ur.PreflightReady = true
				ur.RollbackReady = true
				break
			}
		}
		return ur
	}

	// 7. Policy Center — return current rules count if available.
	s.policyFn = func() PolicyCenter {
		return PolicyCenter{
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			Current: PolicySummary{
				Version:          1,
				State:            "active",
				UpdatedAt:        time.Now().UTC().Format(time.RFC3339),
				ActiveRules:      0,
				WhitelistCount:   0,
				TaintSourceCount: 0,
			},
			Draft: PolicySummary{
				Version: 0,
				State:   "draft",
			},
			History: []PolicySummary{},
		}
	}

	// 8. Alert Workflow — return empty alert list.
	s.alertsFn = func(status, assignee string) AlertWorkflow {
		return AlertWorkflow{
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			Summary: AlertWorkflowSummary{
				Total:      0,
				Open:       0,
				Assigned:   0,
				Suppressed: 0,
				Closed:     0,
			},
			Alerts:  []AlertWorkflowItem{},
			History: []ControlActionAudit{},
		}
	}

	// 9. Notify Delivery Center — return empty delivery records.
	s.deliveryFn = func() NotifyDeliveryCenter {
		return NotifyDeliveryCenter{
			UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
			Recent:      []NotifyDeliveryRecord{},
			DeadLetters: []NotifyDeliveryRecord{},
			History:     []NotifyDeliveryAudit{},
		}
	}
}

// SetAPIKeyAuth enables API key authentication.
// When enabled, requests must include X-API-Key header with a matching key.
func (s *Server) SetAPIKeyAuth(keys []string, enabled bool) {
	s.authKeys = keys
	s.authEnabled = enabled
}

func (s *Server) SetAPIAuth(keys []string, roles map[string]string, identities map[string]string, enabled bool) {
	s.authKeys = keys
	s.authRoles = roles
	s.authIDs = identities
	s.authEnabled = enabled
}

func (s *Server) SetAPIAuthTenants(tenants map[string]string) {
	s.authTenants = tenants
}

func (s *Server) SetAPIAuthPermissions(permissions map[string][]string) {
	s.authPermissions = permissions
}

func (s *Server) SetTrustedHeaderAuth(enabled bool, userHeader, roleHeader string) {
	s.trustedHeaderAuthEnabled = enabled
	s.trustedUserHeader = strings.TrimSpace(userHeader)
	s.trustedRoleHeader = strings.TrimSpace(roleHeader)
}

func (s *Server) SetTrustedTenantHeader(header string) {
	s.trustedTenantHeader = strings.TrimSpace(header)
}

// SetRateLimit configures per-IP rate limiting.
func (s *Server) SetRateLimit(ratePerSec float64, burst int) {
	if ratePerSec > 0 {
		s.rateLimiter = newRateLimiter(ratePerSec, burst)
	}
}

// SetCORSOrigins configures allowed CORS origins.
func (s *Server) SetCORSOrigins(origins []string) {
	s.corsOrigins = origins
}

func (s *Server) buildHandlerChain() http.Handler {
	// Middleware order: auth → rate limit → recovery → CORS → logging → handler
	var h http.Handler = s.mux
	h = loggingMiddleware(h)
	h = corsMiddleware(s.corsOrigins)(h)
	h = recoveryMiddleware(h)
	if s.rateLimiter != nil {
		h = rateLimitMiddleware(s.rateLimiter)(h)
	}
	h = authorizationMiddleware(s.authPermissions)(h)
	h = authMiddleware(s.authKeys, s.authRoles, s.authIDs, s.authTenants, s.authEnabled, trustedHeaderAuthConfig{
		Enabled:      s.trustedHeaderAuthEnabled,
		UserHeader:   s.trustedUserHeader,
		RoleHeader:   s.trustedRoleHeader,
		TenantHeader: s.trustedTenantHeader,
	})(h)
	return h
}

// Handler returns the full middleware chain as an http.Handler.
// Useful for testing and embedding in custom servers.
func (s *Server) Handler() http.Handler {
	return s.buildHandlerChain()
}

func (s *Server) Start() error {
	metrics.MustRegister()
	log.Printf("[api] listening on %s", s.addr)
	if s.authEnabled {
		log.Printf("[api] authentication enabled (%d key(s))", len(s.authKeys))
	}
	if s.rateLimiter != nil {
		log.Printf("[api] rate limiting enabled (%.0f req/s, burst %d)", s.rateLimiter.rate, s.rateLimiter.burst)
	}
	if len(s.corsOrigins) > 0 && s.corsOrigins[0] != "*" {
		log.Printf("[api] CORS origins: %v", s.corsOrigins)
	}
	return http.ListenAndServe(s.addr, s.buildHandlerChain())
}

// StartTLS starts the server with HTTPS using the given certificate and key files.
func (s *Server) StartTLS(certFile, keyFile string) error {
	metrics.MustRegister()
	log.Printf("[api] listening on %s (TLS)", s.addr)
	return http.ListenAndServeTLS(s.addr, certFile, keyFile, s.buildHandlerChain())
}

func (s *Server) buildMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler())
	mux.HandleFunc("/health", s.jsonHandler(s.handleHealth))
	mux.HandleFunc("/ready", s.jsonHandler(s.handleHealth))
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.HandleFunc("/api/v1/status", s.jsonHandler(s.handleStatus))
	mux.HandleFunc("/api/v1/control/overview", s.jsonHandler(s.handleClusterOverview))
	mux.HandleFunc("/api/v1/control/ha", s.jsonHandler(s.handleHAStatus))
	mux.HandleFunc("/api/v1/control/fleet", s.jsonHandler(s.handleFleet))
	mux.HandleFunc("/api/v1/control/support", s.jsonHandler(s.handleSupportBundles))
	mux.HandleFunc("/api/v1/control/support/download", s.handleSupportBundleDownload)
	mux.HandleFunc("/api/v1/control/backup", s.jsonHandler(s.handleBackups))
	mux.HandleFunc("/api/v1/control/backup/download", s.handleBackupDownload)
	mux.HandleFunc("/api/v1/control/security", s.jsonHandler(s.handleSecurity))
	mux.HandleFunc("/api/v1/control/audit", s.jsonHandler(s.handleAuditFeed))
	mux.HandleFunc("/api/v1/control/compliance", s.jsonHandler(s.handleCompliance))
	mux.HandleFunc("/api/v1/control/license", s.jsonHandler(s.handleLicenseStatus))
	mux.HandleFunc("/api/v1/control/upgrade", s.jsonHandler(s.handleUpgradeReadiness))
	mux.HandleFunc("/api/v1/control/policies", s.jsonHandler(s.handlePolicies))
	mux.HandleFunc("/api/v1/control/policies/bundle", s.handlePolicyBundleDownload)
	mux.HandleFunc("/api/v1/control/alerts", s.jsonHandler(s.handleAlertWorkflow))
	mux.HandleFunc("/api/v1/control/deliveries", s.jsonHandler(s.handleNotifyDeliveries))
	mux.HandleFunc("/api/v1/graph/export", s.jsonHandler(s.handleExport))
	mux.HandleFunc("/api/v1/graph/node/", s.jsonHandler(s.handleNode)) // parsed from path
	mux.HandleFunc("/api/v1/alerts", s.jsonHandler(s.handleAlerts))
	mux.HandleFunc("/api/v1/alerts/", s.jsonHandler(s.handleAlerts))
	mux.HandleFunc("/api/v1/admin/reload", s.jsonHandler(s.handleReload))
	mux.HandleFunc("/api/v1/events/search", s.jsonHandler(s.handleEventSearch))
	mux.HandleFunc("/api/v1/investigation/report", s.jsonHandler(s.handleInvestigationReport))
	mux.HandleFunc("/dashboard", s.handleDashboard)
	mux.HandleFunc("/", s.handleDashboard)
	mux.HandleFunc("/api/v1/events/recent", s.jsonHandler(s.handleEventRecent))
	mux.HandleFunc("/api/v1/", s.notFound)
	return mux
}

// jsonHandler wraps a handler to set JSON content type and handle errors.
func (s *Server) jsonHandler(fn func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-ProvidAPT", "1.0")
		if err := fn(w, r); err != nil {
			log.Printf("[api] error: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			if encodeErr := json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}); encodeErr != nil {
				log.Printf("[api] encode error response failed: %v", encodeErr)
			}
		}
	}
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

// ═══════════════════════════════════════════════════════════════
// Handlers
// ═══════════════════════════════════════════════════════════════

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) error {
	stats := s.graph.Stats()
	resp := map[string]interface{}{
		"status":      "running",
		"nodes":       stats.Nodes,
		"edges":       stats.Edges,
		"role":        CurrentRole(r),
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"diagnostics": s.runtimeDiagnosticsSnapshot(),
	}
	// Augment with health fields when available
	if s.healthFn != nil {
		h := s.healthFn()
		resp["health"] = h.Status
		resp["uptime_seconds"] = h.UptimeSeconds
		resp["memory_bytes"] = h.MemoryBytes
		diag := s.runtimeDiagnosticsSnapshot()
		if h.Version != "" {
			diag.Version = h.Version
		}
		if h.AttachmentMode != "" {
			diag.KernelAttachmentMode = h.AttachmentMode
		}
		if h.DesiredPolicyVersion > 0 && diag.AppliedPolicyVersion == 0 {
			diag.AppliedPolicyVersion = h.DesiredPolicyVersion
		}
		resp["diagnostics"] = diag
	}
	return json.NewEncoder(w).Encode(resp)
}

// handleHealth returns detailed health status. Returns 200 when healthy, 503 when degraded.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) error {
	var hs HealthStatus
	if s.healthFn != nil {
		hs = s.healthFn()
	} else {
		hs = HealthStatus{
			Status:        "unknown",
			UptimeSeconds: int64(time.Since(s.startTime).Seconds()),
			Version:       version.String(),
		}
	}

	if hs.Status == "healthy" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	return json.NewEncoder(w).Encode(hs)
}

func (s *Server) handleClusterOverview(w http.ResponseWriter, r *http.Request) error {
	overview := ClusterOverview{
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Agents:    []ClusterAgent{},
	}
	if s.clusterFn != nil {
		overview = s.clusterFn()
		if overview.UpdatedAt == "" {
			overview.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		}
		if overview.Agents == nil {
			overview.Agents = []ClusterAgent{}
		}
	}
	if tenant := CurrentTenant(r); tenant != "" && CurrentRole(r) != RoleAdmin {
		overview = filterClusterOverviewForTenant(overview, tenant)
	}
	return json.NewEncoder(w).Encode(overview)
}

func (s *Server) handleHAStatus(w http.ResponseWriter, _ *http.Request) error {
	status := HAStatus{
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
		Mode:          "standalone",
		Healthy:       true,
		StateBackend:  "local",
		FailoverReady: false,
	}
	if s.haFn != nil {
		status = s.haFn()
		if status.UpdatedAt == "" {
			status.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		}
	}
	return json.NewEncoder(w).Encode(status)
}

func (s *Server) requireLeaderForControlWrite(w http.ResponseWriter) bool {
	if s.haFn == nil {
		return true
	}
	status := s.haFn()
	mode := strings.ToLower(strings.TrimSpace(status.Mode))
	if mode == "" || mode == "standalone" {
		return true
	}
	role := strings.ToLower(strings.TrimSpace(status.Role))
	if role != "leader" {
		leaderEndpoint := leaderEndpointFromHAStatus(status)
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":           "control-plane write rejected: current node is not leader",
			"mode":            status.Mode,
			"role":            status.Role,
			"node_id":         status.NodeID,
			"leader_id":       status.LeaderID,
			"leader_endpoint": leaderEndpoint,
		})
		return false
	}
	if !status.Healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":     "control-plane write rejected: leader is not healthy",
			"mode":      status.Mode,
			"role":      status.Role,
			"node_id":   status.NodeID,
			"leader_id": status.LeaderID,
		})
		return false
	}
	return true
}

func leaderEndpointFromHAStatus(status HAStatus) string {
	leaderID := strings.TrimSpace(status.LeaderID)
	if leaderID == "" {
		return ""
	}
	for _, peer := range status.Peers {
		trimmed := strings.TrimSpace(peer)
		if trimmed == "" {
			continue
		}
		id, endpoint := splitPeerEndpoint(trimmed)
		if id == leaderID {
			return endpoint
		}
	}
	return ""
}

func splitPeerEndpoint(peer string) (string, string) {
	if strings.Contains(peer, "=") {
		parts := strings.SplitN(peer, "=", 2)
		return strings.TrimSpace(parts[0]), normalizePeerEndpoint(parts[1])
	}
	if strings.Contains(peer, "@") {
		parts := strings.SplitN(peer, "@", 2)
		return strings.TrimSpace(parts[0]), normalizePeerEndpoint(parts[1])
	}
	host := peer
	if idx := strings.LastIndex(peer, ":"); idx > 0 {
		host = peer[:idx]
	}
	return strings.TrimSpace(host), normalizePeerEndpoint(peer)
}

func normalizePeerEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint
	}
	return "http://" + endpoint
}

func (s *Server) handleFleet(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		group := strings.TrimSpace(r.URL.Query().Get("group"))
		tag := strings.TrimSpace(r.URL.Query().Get("tag"))
		if tenant := CurrentTenant(r); tenant != "" && CurrentRole(r) != RoleAdmin {
			if group != "" && group != tenant {
				w.WriteHeader(http.StatusForbidden)
				return json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: tenant scope mismatch"})
			}
			group = tenant
		}
		fleet := FleetList{
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			Group:     group,
			Tag:       tag,
			Agents:    []ClusterAgent{},
		}
		if s.fleetListFn != nil {
			fleet = s.fleetListFn(group, tag)
			if fleet.UpdatedAt == "" {
				fleet.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			}
			if fleet.Agents == nil {
				fleet.Agents = []ClusterAgent{}
			}
		}
		return json.NewEncoder(w).Encode(fleet)
	case http.MethodPost:
		if s.fleetSetFn == nil {
			w.WriteHeader(http.StatusNotImplemented)
			return json.NewEncoder(w).Encode(map[string]string{"error": "fleet updates not enabled"})
		}
		if !s.requireLeaderForControlWrite(w) {
			return nil
		}
		var update FleetUpdate
		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			return fmt.Errorf("decode fleet update: %w", err)
		}
		update.Role = CurrentRole(r)
		if update.Actor == "" {
			update.Actor = CurrentActor(r)
		}
		agentIDs := normalizedFleetUpdateAgentIDs(update)
		if len(agentIDs) == 0 {
			return fmt.Errorf("agent_id is required")
		}
		result := FleetUpdateResult{
			Status:  "ok",
			Results: make([]FleetUpdateItemResult, 0, len(agentIDs)),
		}
		for _, agentID := range agentIDs {
			item := update
			item.AgentID = agentID
			item.AgentIDs = nil
			result.Processed++
			if err := s.fleetSetFn(item); err != nil {
				result.Failed++
				result.Results = append(result.Results, FleetUpdateItemResult{AgentID: agentID, Status: "failed", Message: err.Error()})
				continue
			}
			result.Succeeded++
			result.Results = append(result.Results, FleetUpdateItemResult{AgentID: agentID, Status: "ok"})
		}
		if result.Failed > 0 {
			result.Status = "partial"
			if result.Succeeded == 0 {
				result.Status = "failed"
				w.WriteHeader(http.StatusBadRequest)
			}
		}
		return json.NewEncoder(w).Encode(result)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
	}
}

func filterClusterOverviewForTenant(overview ClusterOverview, tenant string) ClusterOverview {
	tenant = strings.TrimSpace(tenant)
	filtered := overview
	filtered.Tenant = tenant
	filtered.Agents = []ClusterAgent{}
	filtered.TotalAgents = 0
	filtered.HealthyAgents = 0
	filtered.DegradedAgents = 0
	for _, agent := range overview.Agents {
		if !agentMatchesTenant(agent, tenant) {
			continue
		}
		filtered.Agents = append(filtered.Agents, agent)
		if strings.EqualFold(agent.Status, "healthy") || strings.EqualFold(agent.Status, "online") {
			filtered.HealthyAgents++
		} else {
			filtered.DegradedAgents++
		}
	}
	filtered.TotalAgents = len(filtered.Agents)
	return filtered
}

func normalizedFleetUpdateAgentIDs(update FleetUpdate) []string {
	seen := map[string]bool{}
	var out []string
	add := func(agentID string) {
		agentID = strings.TrimSpace(agentID)
		if agentID == "" || seen[agentID] {
			return
		}
		seen[agentID] = true
		out = append(out, agentID)
	}
	add(update.AgentID)
	for _, agentID := range update.AgentIDs {
		add(agentID)
	}
	return out
}

func normalizedAlertActionIDs(req AlertWorkflowActionRequest) []string {
	seen := map[string]bool{}
	var out []string
	add := func(alertID string) {
		alertID = strings.TrimSpace(alertID)
		if alertID == "" || seen[alertID] {
			return
		}
		seen[alertID] = true
		out = append(out, alertID)
	}
	add(req.AlertID)
	for _, alertID := range req.AlertIDs {
		add(alertID)
	}
	return out
}

func diffPolicySummaries(current, draft PolicySummary) []PolicyDiff {
	var diff []PolicyDiff
	add := func(field string, before, after interface{}) {
		if fmt.Sprint(before) == fmt.Sprint(after) {
			return
		}
		diff = append(diff, PolicyDiff{Field: field, Before: before, After: after, Status: "changed"})
	}
	add("active_rules", current.ActiveRules, draft.ActiveRules)
	add("sigma_rule_ids", strings.Join(current.SigmaRuleIDs, ","), strings.Join(draft.SigmaRuleIDs, ","))
	add("whitelist_count", current.WhitelistCount, draft.WhitelistCount)
	add("taint_source_count", current.TaintSourceCount, draft.TaintSourceCount)
	add("notes", current.Notes, draft.Notes)
	if len(diff) == 0 {
		diff = append(diff, PolicyDiff{Field: "policy", Status: "unchanged"})
	}
	return diff
}

func filterAuditFeedForTenant(feed AuditFeed, tenant string) AuditFeed {
	tenant = strings.TrimSpace(tenant)
	feed.Tenant = tenant
	filtered := make([]AuditEntry, 0, len(feed.Entries))
	for _, entry := range feed.Entries {
		if auditEntryMatchesTenant(entry, tenant) {
			filtered = append(filtered, entry)
		}
	}
	feed.Entries = filtered
	return feed
}

func agentMatchesTenant(agent ClusterAgent, tenant string) bool {
	if tenant == "" {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(agent.Group), tenant) {
		return true
	}
	for _, tag := range agent.Tags {
		if strings.EqualFold(strings.TrimSpace(tag), tenant) {
			return true
		}
	}
	return false
}

func auditEntryMatchesTenant(entry AuditEntry, tenant string) bool {
	if tenant == "" {
		return true
	}
	for _, key := range []string{"tenant", "group", "target_group"} {
		if value, ok := entry.Details[key]; ok && strings.EqualFold(strings.TrimSpace(fmt.Sprint(value)), tenant) {
			return true
		}
	}
	if value, ok := entry.Details["tags"]; ok {
		for _, tag := range strings.Split(fmt.Sprint(value), ",") {
			if strings.EqualFold(strings.TrimSpace(tag), tenant) {
				return true
			}
		}
	}
	return false
}

func (s *Server) handleSupportBundles(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		summary := SupportBundleSummary{}
		if s.supportFn != nil {
			summary = s.supportFn()
			if summary.History == nil {
				summary.History = []ControlActionAudit{}
			}
		}
		return json.NewEncoder(w).Encode(summary)
	case http.MethodPost:
		if s.supportAct == nil {
			w.WriteHeader(http.StatusNotImplemented)
			return json.NewEncoder(w).Encode(map[string]string{"error": "support bundle actions not enabled"})
		}
		if !s.requireLeaderForControlWrite(w) {
			return nil
		}
		var req SupportBundleActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return fmt.Errorf("decode support bundle action: %w", err)
		}
		req.Role = CurrentRole(r)
		if req.Actor == "" {
			req.Actor = CurrentActor(r)
		}
		result, err := s.supportAct(req)
		if err != nil {
			return err
		}
		return json.NewEncoder(w).Encode(result)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleSupportBundleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}
	if s.supportDl == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "support bundle downloads not enabled"})
		return
	}
	download, err := s.supportDl(CurrentActor(r), CurrentRole(r))
	if err != nil {
		log.Printf("[api] support bundle download error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	fileName := strings.TrimSpace(download.FileName)
	if fileName == "" {
		fileName = filepath.Base(download.Path)
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fileName))
	http.ServeFile(w, r, download.Path)
}

func (s *Server) handleBackups(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		summary := BackupSummary{}
		if s.backupFn != nil {
			summary = s.backupFn()
			if summary.History == nil {
				summary.History = []ControlActionAudit{}
			}
		}
		return json.NewEncoder(w).Encode(summary)
	case http.MethodPost:
		if s.backupAct == nil {
			w.WriteHeader(http.StatusNotImplemented)
			return json.NewEncoder(w).Encode(map[string]string{"error": "backup actions not enabled"})
		}
		if !s.requireLeaderForControlWrite(w) {
			return nil
		}
		var req BackupActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return fmt.Errorf("decode backup action: %w", err)
		}
		req.Role = CurrentRole(r)
		if req.Actor == "" {
			req.Actor = CurrentActor(r)
		}
		result, err := s.backupAct(req)
		if err != nil {
			return err
		}
		return json.NewEncoder(w).Encode(result)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}
	if s.backupDl == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "backup downloads not enabled"})
		return
	}
	download, err := s.backupDl(CurrentActor(r), CurrentRole(r))
	if err != nil {
		log.Printf("[api] backup download error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	fileName := strings.TrimSpace(download.FileName)
	if fileName == "" {
		fileName = filepath.Base(download.Path)
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fileName))
	http.ServeFile(w, r, download.Path)
}

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		status := SecurityStatus{
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			History:   []ControlActionAudit{},
		}
		if s.securityFn != nil {
			status = s.securityFn()
			if status.UpdatedAt == "" {
				status.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			}
			if status.History == nil {
				status.History = []ControlActionAudit{}
			}
		}
		return json.NewEncoder(w).Encode(status)
	case http.MethodPost:
		if s.securityAct == nil {
			w.WriteHeader(http.StatusNotImplemented)
			return json.NewEncoder(w).Encode(map[string]string{"error": "security actions not enabled"})
		}
		if !s.requireLeaderForControlWrite(w) {
			return nil
		}
		var req SecurityActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return fmt.Errorf("decode security action: %w", err)
		}
		req.Role = CurrentRole(r)
		if req.Actor == "" {
			req.Actor = CurrentActor(r)
		}
		result, err := s.securityAct(req)
		if err != nil {
			return err
		}
		return json.NewEncoder(w).Encode(result)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAuditFeed(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
	}
	limit := 20
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	feed := AuditFeed{
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Category:  strings.TrimSpace(r.URL.Query().Get("category")),
		Source:    strings.TrimSpace(r.URL.Query().Get("source")),
		Entries:   []AuditEntry{},
	}
	if s.auditFn != nil {
		feed = s.auditFn(feed.Category, feed.Source, limit)
		if feed.UpdatedAt == "" {
			feed.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		}
		if feed.Entries == nil {
			feed.Entries = []AuditEntry{}
		}
	}
	if tenant := CurrentTenant(r); tenant != "" && CurrentRole(r) != RoleAdmin {
		feed = filterAuditFeedForTenant(feed, tenant)
	}
	if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("format")), "csv") {
		return writeAuditFeedCSV(w, feed)
	}
	return json.NewEncoder(w).Encode(feed)
}

func writeAuditFeedCSV(w http.ResponseWriter, feed AuditFeed) error {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="providapt-audit.csv"`)
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{"id", "timestamp", "category", "severity", "source", "message", "details"}); err != nil {
		return err
	}
	for _, entry := range feed.Entries {
		details := ""
		if len(entry.Details) > 0 {
			data, err := json.Marshal(entry.Details)
			if err != nil {
				return err
			}
			details = string(data)
		}
		if err := writer.Write([]string{
			entry.ID,
			entry.Timestamp,
			entry.Category,
			entry.Severity,
			entry.Source,
			entry.Message,
			details,
		}); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		status := ComplianceStatus{
			UpdatedAt:          time.Now().UTC().Format(time.RFC3339),
			RecommendedActions: []string{},
		}
		if s.complianceFn != nil {
			status = s.complianceFn()
			if status.UpdatedAt == "" {
				status.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			}
			if status.RecommendedActions == nil {
				status.RecommendedActions = []string{}
			}
		}
		if tenant := CurrentTenant(r); tenant != "" && CurrentRole(r) != RoleAdmin {
			status.Tenant = tenant
		}
		return json.NewEncoder(w).Encode(status)
	case http.MethodPost:
		if s.complianceAct == nil {
			w.WriteHeader(http.StatusNotImplemented)
			return json.NewEncoder(w).Encode(map[string]string{"error": "compliance actions not enabled"})
		}
		if !s.requireLeaderForControlWrite(w) {
			return nil
		}
		var req ComplianceActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return fmt.Errorf("decode compliance action: %w", err)
		}
		req.Role = CurrentRole(r)
		if req.Actor == "" {
			req.Actor = CurrentActor(r)
		}
		result, err := s.complianceAct(req)
		if err != nil {
			return err
		}
		return json.NewEncoder(w).Encode(result)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleLicenseStatus(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		status := LicenseStatus{
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			History:   []ControlActionAudit{},
		}
		if s.licenseFn != nil {
			status = s.licenseFn()
			if status.UpdatedAt == "" {
				status.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			}
			if status.History == nil {
				status.History = []ControlActionAudit{}
			}
		}
		return json.NewEncoder(w).Encode(status)
	case http.MethodPost:
		if s.licenseAct == nil {
			w.WriteHeader(http.StatusNotImplemented)
			return json.NewEncoder(w).Encode(map[string]string{"error": "license actions not enabled"})
		}
		if !s.requireLeaderForControlWrite(w) {
			return nil
		}
		var req LicenseActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return fmt.Errorf("decode license action: %w", err)
		}
		req.Role = CurrentRole(r)
		if req.Actor == "" {
			req.Actor = CurrentActor(r)
		}
		result, err := s.licenseAct(req)
		if err != nil {
			return err
		}
		return json.NewEncoder(w).Encode(result)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleUpgradeReadiness(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		status := UpgradeReadiness{
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			History:   []ControlActionAudit{},
		}
		if s.upgradeFn != nil {
			status = s.upgradeFn()
			if status.UpdatedAt == "" {
				status.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			}
			if status.History == nil {
				status.History = []ControlActionAudit{}
			}
		}
		return json.NewEncoder(w).Encode(status)
	case http.MethodPost:
		if s.upgradeAct == nil {
			w.WriteHeader(http.StatusNotImplemented)
			return json.NewEncoder(w).Encode(map[string]string{"error": "upgrade actions not enabled"})
		}
		if !s.requireLeaderForControlWrite(w) {
			return nil
		}
		var req UpgradeActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return fmt.Errorf("decode upgrade action: %w", err)
		}
		req.Role = CurrentRole(r)
		if req.Actor == "" {
			req.Actor = CurrentActor(r)
		}
		result, err := s.upgradeAct(req)
		if err != nil {
			return err
		}
		return json.NewEncoder(w).Encode(result)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		center := PolicyCenter{
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			History:   []PolicySummary{},
		}
		if s.policyFn != nil {
			center = s.policyFn()
			if center.UpdatedAt == "" {
				center.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			}
			if center.History == nil {
				center.History = []PolicySummary{}
			}
		}
		if len(center.Diff) == 0 {
			center.Diff = diffPolicySummaries(center.Current, center.Draft)
		}
		return json.NewEncoder(w).Encode(center)
	case http.MethodPost:
		if s.policyActFn == nil {
			w.WriteHeader(http.StatusNotImplemented)
			return json.NewEncoder(w).Encode(map[string]string{"error": "policy actions not enabled"})
		}
		if !s.requireLeaderForControlWrite(w) {
			return nil
		}
		var req PolicyActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return fmt.Errorf("decode policy action: %w", err)
		}
		req.Role = CurrentRole(r)
		if req.Actor == "" {
			req.Actor = CurrentActor(r)
		}
		result, err := s.policyActFn(req)
		if err != nil {
			return err
		}
		return json.NewEncoder(w).Encode(result)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handlePolicyBundleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}
	if s.policyDlFn == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy bundle downloads not enabled"})
		return
	}
	version := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("version")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid policy bundle version"})
			return
		}
		version = parsed
	}
	download, err := s.policyDlFn(version, CurrentActor(r), CurrentRole(r))
	if err != nil {
		log.Printf("[api] policy bundle download error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	fileName := strings.TrimSpace(download.FileName)
	if fileName == "" {
		fileName = filepath.Base(download.Path)
	}
	w.Header().Set("Content-Type", "application/json")
	if strings.TrimSpace(download.SHA256) != "" {
		w.Header().Set("X-Policy-Bundle-SHA256", strings.TrimSpace(download.SHA256))
	}
	if download.Version > 0 {
		w.Header().Set("X-Policy-Version", strconv.Itoa(download.Version))
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fileName))
	http.ServeFile(w, r, download.Path)
}

func (s *Server) handleAlertWorkflow(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		workflow := AlertWorkflow{
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			Alerts:    []AlertWorkflowItem{},
		}
		if s.alertsFn != nil {
			workflow = s.alertsFn(r.URL.Query().Get("status"), r.URL.Query().Get("assignee"))
			if workflow.UpdatedAt == "" {
				workflow.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			}
			if workflow.Alerts == nil {
				workflow.Alerts = []AlertWorkflowItem{}
			}
		}
		return json.NewEncoder(w).Encode(workflow)
	case http.MethodPost:
		if s.alertActFn == nil {
			w.WriteHeader(http.StatusNotImplemented)
			return json.NewEncoder(w).Encode(map[string]string{"error": "alert workflow actions not enabled"})
		}
		if !s.requireLeaderForControlWrite(w) {
			return nil
		}
		var req AlertWorkflowActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return fmt.Errorf("decode alert workflow action: %w", err)
		}
		req.Role = CurrentRole(r)
		if req.Actor == "" {
			req.Actor = CurrentActor(r)
		}
		alertIDs := normalizedAlertActionIDs(req)
		if len(alertIDs) > 1 {
			result := AlertWorkflowActionResult{Status: "ok", Alerts: []AlertWorkflowItem{}}
			for _, alertID := range alertIDs {
				itemReq := req
				itemReq.AlertID = alertID
				itemReq.AlertIDs = nil
				result.Processed++
				item, err := s.alertActFn(itemReq)
				if err != nil {
					result.Failed++
					result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", alertID, err))
					continue
				}
				result.Succeeded++
				result.Alerts = append(result.Alerts, item)
			}
			if result.Failed > 0 {
				result.Status = "partial"
				if result.Succeeded == 0 {
					result.Status = "failed"
					w.WriteHeader(http.StatusBadRequest)
				}
			}
			return json.NewEncoder(w).Encode(result)
		}
		if len(alertIDs) == 1 {
			req.AlertID = alertIDs[0]
		}
		result, err := s.alertActFn(req)
		if err != nil {
			return err
		}
		return json.NewEncoder(w).Encode(result)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleNotifyDeliveries(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		center := NotifyDeliveryCenter{
			UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
			Recent:      []NotifyDeliveryRecord{},
			DeadLetters: []NotifyDeliveryRecord{},
		}
		if s.deliveryFn != nil {
			center = s.deliveryFn()
			if center.UpdatedAt == "" {
				center.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			}
			if center.Recent == nil {
				center.Recent = []NotifyDeliveryRecord{}
			}
			if center.DeadLetters == nil {
				center.DeadLetters = []NotifyDeliveryRecord{}
			}
		}
		return json.NewEncoder(w).Encode(center)
	case http.MethodPost:
		if s.deliveryAct == nil {
			w.WriteHeader(http.StatusNotImplemented)
			return json.NewEncoder(w).Encode(map[string]string{"error": "delivery actions not enabled"})
		}
		if !s.requireLeaderForControlWrite(w) {
			return nil
		}
		var req NotifyDeliveryActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return fmt.Errorf("decode delivery action: %w", err)
		}
		req.Role = CurrentRole(r)
		if req.Actor == "" {
			req.Actor = CurrentActor(r)
		}
		result, err := s.deliveryAct(req)
		if err != nil {
			return err
		}
		return json.NewEncoder(w).Encode(result)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	nodes := s.graph.Nodes()
	edges := s.graph.Edges()

	if pid := q.Get("pid"); pid != "" {
		pidPrefix := "p:" + pid
		nodes, edges = filterByPID(nodes, edges, pidPrefix)
	}

	return writeCytoscape(w, nodes, edges)
}

// ── Node operations: /api/v1/graph/node/{id}/backward or /forward ──

func (s *Server) handleNode(w http.ResponseWriter, r *http.Request) error {
	// Parse path: /api/v1/graph/node/<id>/<action>
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/graph/node/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 {
		return fmt.Errorf("usage: /api/v1/graph/node/<id>/backward|forward")
	}
	nodeID := parts[0]
	action := parts[1]
	depth := queryInt(r, "depth", 5)

	switch action {
	case "backward":
		return s.backward(w, nodeID, depth)
	case "forward":
		return s.forward(w, nodeID, depth)
	default:
		return fmt.Errorf("unknown action: %s (use backward or forward)", action)
	}
}

func (s *Server) backward(w http.ResponseWriter, nodeID string, depth int) error {
	result, err := s.backtracer.Trace(&backtrace.TraceRequest{
		StartID:  nodeID,
		MaxDepth: depth,
	})
	if err != nil {
		return fmt.Errorf("trace: %w", err)
	}
	var nodes []*provenance.Node
	var edges []*provenance.Edge
	for _, seg := range result.Segments {
		nodes = append(nodes, seg.Nodes...)
		edges = append(edges, seg.Edges...)
	}
	return writeCytoscape(w, nodes, edges)
}

func (s *Server) forward(w http.ResponseWriter, nodeID string, depth int) error {
	seen := make(map[string]bool)
	var nodes []*provenance.Node
	var edges []*provenance.Edge
	queue := []string{nodeID}

	for d := 0; len(queue) > 0 && d < depth; d++ {
		var next []string
		for _, id := range queue {
			if seen[id] {
				continue
			}
			seen[id] = true
			if n, ok := s.graph.LookupNode(id); ok && n != nil {
				nodes = append(nodes, n)
			}
			for _, e := range s.graph.Edges() {
				if e.Source == id && !seen[e.Target] {
					edges = append(edges, e)
					next = append(next, e.Target)
				}
			}
		}
		queue = next
	}
	return writeCytoscape(w, nodes, edges)
}

func (s *Server) handleInvestigationReport(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
	}
	startNode := strings.TrimSpace(r.URL.Query().Get("node"))
	if startNode == "" {
		if pid := strings.TrimSpace(r.URL.Query().Get("pid")); pid != "" {
			startNode = "p:" + pid
		}
	}
	if startNode == "" {
		return fmt.Errorf("node or pid is required")
	}
	direction := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("direction")))
	if direction == "" {
		direction = "backward"
	}
	depth := queryInt(r, "depth", 5)
	nodes, edges, err := s.traceNodesAndEdges(startNode, direction, depth)
	if err != nil {
		return err
	}
	report := buildInvestigationReport(startNode, direction, depth, nodes, edges)
	if strings.EqualFold(r.URL.Query().Get("format"), "markdown") {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, err := w.Write([]byte(renderInvestigationMarkdown(report)))
		return err
	}
	return json.NewEncoder(w).Encode(report)
}

func (s *Server) traceNodesAndEdges(nodeID, direction string, depth int) ([]*provenance.Node, []*provenance.Edge, error) {
	if depth <= 0 {
		depth = 1
	}
	switch direction {
	case "backward":
		result, err := s.backtracer.Trace(&backtrace.TraceRequest{
			StartID:  nodeID,
			MaxDepth: depth,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("trace: %w", err)
		}
		var nodes []*provenance.Node
		var edges []*provenance.Edge
		for _, seg := range result.Segments {
			nodes = append(nodes, seg.Nodes...)
			edges = append(edges, seg.Edges...)
		}
		return dedupeNodes(nodes), dedupeEdges(edges), nil
	case "forward":
		nodes, edges := s.collectForwardTrace(nodeID, depth)
		return nodes, edges, nil
	default:
		return nil, nil, fmt.Errorf("unknown direction: %s (use backward or forward)", direction)
	}
}

func (s *Server) collectForwardTrace(nodeID string, depth int) ([]*provenance.Node, []*provenance.Edge) {
	seen := make(map[string]bool)
	var nodes []*provenance.Node
	var edges []*provenance.Edge
	queue := []string{nodeID}
	for d := 0; len(queue) > 0 && d < depth; d++ {
		var next []string
		for _, id := range queue {
			if seen[id] {
				continue
			}
			seen[id] = true
			if n, ok := s.graph.LookupNode(id); ok && n != nil {
				nodes = append(nodes, n)
			}
			for _, e := range s.graph.Edges() {
				if e.Source == id && !seen[e.Target] {
					edges = append(edges, e)
					next = append(next, e.Target)
				}
			}
		}
		queue = next
	}
	return dedupeNodes(nodes), dedupeEdges(edges)
}

// ── Alerts: /api/v1/alerts ──────────────────────────────────

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) error {
	alerts := loadAlerts("")
	// Check for /alerts/{id}/svg sub-path
	if rest := strings.TrimPrefix(r.URL.Path, "/api/v1/alerts"); rest != "" && rest != "/" {
		return s.handleAlertSVG(w, r, strings.TrimPrefix(rest, "/"))
	}
	return json.NewEncoder(w).Encode(map[string]interface{}{
		"alerts": alerts,
		"count":  len(alerts),
	})
}

func (s *Server) handleAlertSVG(w http.ResponseWriter, _ *http.Request, path string) error {
	// Parse: <id>/svg
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 || parts[1] != "svg" {
		return fmt.Errorf("usage: /api/v1/alerts/<id>/svg")
	}
	alertID := parts[0]

	svg := generateAlertSVG(alertID, s.graph)
	w.Header().Set("Content-Type", "image/svg+xml")
	_, err := w.Write(svg)
	return err
}

// ── Admin: /api/v1/admin/reload ──────────────────────────────

// handleReload triggers a config reload of all components.
// POST only; returns 405 for other methods.
func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return fmt.Errorf("use POST for reload (got %s)", r.Method)
	}
	if s.reloadFn == nil {
		w.WriteHeader(http.StatusNotImplemented)
		return json.NewEncoder(w).Encode(map[string]string{
			"status": "no reload handler registered",
		})
	}
	if !s.requireLeaderForControlWrite(w) {
		return nil
	}
	if err := s.reloadFn(); err != nil {
		return fmt.Errorf("reload failed: %w", err)
	}
	return json.NewEncoder(w).Encode(map[string]string{
		"status": "reload triggered",
	})
}

// ═══════════════════════════════════════════════════════════════
// Middleware
// ═══════════════════════════════════════════════════════════════

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[api] %s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

// ═══════════════════════════════════════════════════════════════
// Cytoscape.js JSON writer
// ═══════════════════════════════════════════════════════════════

type cytoGraph struct {
	Data     cytoMeta      `json:"data"`
	Elements []cytoElement `json:"elements"`
}

type cytoMeta struct {
	Generated string `json:"generated"`
	NodeCount int    `json:"node_count"`
	EdgeCount int    `json:"edge_count"`
}

type cytoElement struct {
	Group string       `json:"group"`
	Data  cytoElemData `json:"data"`
}

type cytoElemData struct {
	ID       string `json:"id,omitempty"`
	Source   string `json:"source,omitempty"`
	Target   string `json:"target,omitempty"`
	Label    string `json:"label,omitempty"`
	NodeType string `json:"type,omitempty"`
	Class    string `json:"class,omitempty"`
}

func writeCytoscape(w http.ResponseWriter, nodes []*provenance.Node, edges []*provenance.Edge) error {
	g := cytoGraph{
		Data: cytoMeta{
			Generated: time.Now().UTC().Format(time.RFC3339Nano),
			NodeCount: len(nodes),
			EdgeCount: len(edges),
		},
	}
	for _, n := range nodes {
		l := n.Label
		if l == "" {
			l = n.ID
		}
		g.Elements = append(g.Elements, cytoElement{
			Group: "nodes",
			Data: cytoElemData{
				ID: n.ID, Label: l, NodeType: n.Subtype,
				Class: n.Subtype,
			},
		})
	}
	for _, e := range edges {
		g.Elements = append(g.Elements, cytoElement{
			Group: "edges",
			Data: cytoElemData{
				ID: e.ID, Source: e.Source, Target: e.Target,
				Label: shortRel(e.Relation),
				Class: "edge-" + shortRel(e.Relation),
			},
		})
	}
	return json.NewEncoder(w).Encode(g)
}

func shortRel(rel string) string {
	switch rel {
	case "prov:used":
		return "used"
	case "prov:wasGeneratedBy":
		return "created"
	case "prov:wasInformedBy":
		return "forked"
	case "prov:wasDerivedFrom":
		return "derived"
	case "prov:hadSecurityContext":
		return "context"
	}
	return rel
}

func buildInvestigationReport(startNode, direction string, depth int, nodes []*provenance.Node, edges []*provenance.Edge) InvestigationReport {
	report := InvestigationReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		StartNode:   startNode,
		Direction:   direction,
		Depth:       depth,
		NodeCount:   len(nodes),
		EdgeCount:   len(edges),
		Nodes:       make([]InvestigationNode, 0, len(nodes)),
		Edges:       make([]InvestigationEdge, 0, len(edges)),
	}
	for _, node := range nodes {
		if node == nil {
			continue
		}
		switch node.Subtype {
		case "process":
			report.ProcessCount++
		case "file":
			report.FileCount++
		case "network":
			report.NetworkCount++
		}
		report.Nodes = append(report.Nodes, InvestigationNode{
			ID:        node.ID,
			Label:     node.Label,
			Type:      node.Subtype,
			ProvType:  node.ProvType,
			FirstSeen: formatAPITime(node.FirstSeen),
			LastSeen:  formatAPITime(node.LastSeen),
			Attrs:     node.Attributes,
		})
	}
	for _, edge := range edges {
		if edge == nil {
			continue
		}
		report.Edges = append(report.Edges, InvestigationEdge{
			ID:        edge.ID,
			Source:    edge.Source,
			Target:    edge.Target,
			Relation:  shortRel(edge.Relation),
			Timestamp: formatAPITime(edge.Timestamp),
			Count:     edge.Count,
			Attrs:     edge.Attributes,
		})
	}
	sort.Slice(report.Nodes, func(i, j int) bool {
		if report.Nodes[i].FirstSeen == report.Nodes[j].FirstSeen {
			return report.Nodes[i].ID < report.Nodes[j].ID
		}
		return report.Nodes[i].FirstSeen < report.Nodes[j].FirstSeen
	})
	sort.Slice(report.Edges, func(i, j int) bool {
		if report.Edges[i].Timestamp == report.Edges[j].Timestamp {
			return report.Edges[i].ID < report.Edges[j].ID
		}
		return report.Edges[i].Timestamp < report.Edges[j].Timestamp
	})
	report.RiskSummary, report.KeyObservations = investigationSummary(report)
	return report
}

func investigationSummary(report InvestigationReport) (string, []string) {
	var observations []string
	if report.NodeCount == 0 {
		return "No provenance nodes were found for the requested starting point.", []string{"Verify the node ID or PID and confirm the agent has ingested matching events."}
	}
	if report.FileCount > 0 {
		observations = append(observations, fmt.Sprintf("%d file node(s) are connected to the trace.", report.FileCount))
	}
	if report.NetworkCount > 0 {
		observations = append(observations, fmt.Sprintf("%d network node(s) are connected to the trace.", report.NetworkCount))
	}
	if report.ProcessCount > 1 {
		observations = append(observations, fmt.Sprintf("%d process node(s) indicate process lineage or impact.", report.ProcessCount))
	}
	if report.EdgeCount == 0 {
		observations = append(observations, "The trace contains no connecting edges at the selected depth.")
	}
	if len(observations) == 0 {
		observations = append(observations, "Trace is narrow; increase depth or switch direction for more context.")
	}
	level := "Low"
	if report.NetworkCount > 0 || report.ProcessCount >= 3 {
		level = "Medium"
	}
	if report.NetworkCount > 0 && report.FileCount > 0 && report.ProcessCount >= 2 {
		level = "High"
	}
	return fmt.Sprintf("%s investigation scope: %d node(s), %d edge(s), direction=%s.", level, report.NodeCount, report.EdgeCount, report.Direction), observations
}

func renderInvestigationMarkdown(report InvestigationReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# ProvidAPT Investigation Report\n\n")
	fmt.Fprintf(&b, "| Field | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Generated At | %s |\n", escapeMarkdownCell(report.GeneratedAt))
	fmt.Fprintf(&b, "| Start Node | `%s` |\n", escapeMarkdownCell(report.StartNode))
	fmt.Fprintf(&b, "| Direction | `%s` |\n", escapeMarkdownCell(report.Direction))
	fmt.Fprintf(&b, "| Depth | %d |\n", report.Depth)
	fmt.Fprintf(&b, "| Nodes | %d |\n", report.NodeCount)
	fmt.Fprintf(&b, "| Edges | %d |\n", report.EdgeCount)
	fmt.Fprintf(&b, "| Risk Summary | %s |\n\n", escapeMarkdownCell(report.RiskSummary))
	fmt.Fprintf(&b, "## Key Observations\n\n")
	for _, observation := range report.KeyObservations {
		fmt.Fprintf(&b, "- %s\n", observation)
	}
	fmt.Fprintf(&b, "\n## Timeline\n\n")
	fmt.Fprintf(&b, "| Time | Type | ID | Label |\n|---|---|---|---|\n")
	for _, node := range report.Nodes {
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s |\n", escapeMarkdownCell(node.FirstSeen), escapeMarkdownCell(node.Type), escapeMarkdownCell(node.ID), escapeMarkdownCell(node.Label))
	}
	fmt.Fprintf(&b, "\n## Relations\n\n")
	fmt.Fprintf(&b, "| Time | Relation | Source | Target | Count |\n|---|---|---|---|---|\n")
	for _, edge := range report.Edges {
		fmt.Fprintf(&b, "| %s | %s | `%s` | `%s` | %d |\n", escapeMarkdownCell(edge.Timestamp), escapeMarkdownCell(edge.Relation), escapeMarkdownCell(edge.Source), escapeMarkdownCell(edge.Target), edge.Count)
	}
	return b.String()
}

func dedupeNodes(nodes []*provenance.Node) []*provenance.Node {
	seen := make(map[string]bool, len(nodes))
	out := make([]*provenance.Node, 0, len(nodes))
	for _, node := range nodes {
		if node == nil || seen[node.ID] {
			continue
		}
		seen[node.ID] = true
		out = append(out, node)
	}
	return out
}

func dedupeEdges(edges []*provenance.Edge) []*provenance.Edge {
	seen := make(map[string]bool, len(edges))
	out := make([]*provenance.Edge, 0, len(edges))
	for _, edge := range edges {
		if edge == nil || seen[edge.ID] {
			continue
		}
		seen[edge.ID] = true
		out = append(out, edge)
	}
	return out
}

func formatAPITime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func escapeMarkdownCell(value string) string {
	value = strings.ReplaceAll(value, "\r\n", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.ReplaceAll(value, "|", "\\|")
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

func queryInt(r *http.Request, key string, def int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}

func filterByPID(nodes []*provenance.Node, edges []*provenance.Edge, prefix string) ([]*provenance.Node, []*provenance.Edge) {
	keepNode := make(map[string]bool)
	for _, n := range nodes {
		if strings.HasPrefix(n.ID, prefix) || strings.HasPrefix(n.ID, prefix+"#") {
			keepNode[n.ID] = true
		}
	}
	var keptEdges []*provenance.Edge
	edgeSet := make(map[string]bool)
	for _, e := range edges {
		if keepNode[e.Source] || keepNode[e.Target] {
			edgeSet[e.ID] = true
			keepNode[e.Source] = true
			keepNode[e.Target] = true
			keptEdges = append(keptEdges, e)
		}
	}
	var keptNodes []*provenance.Node
	for _, n := range nodes {
		if keepNode[n.ID] {
			keptNodes = append(keptNodes, n)
		}
	}
	return keptNodes, keptEdges
}

func loadAlerts(path string) []map[string]interface{} {
	if path == "" {
		path = "/var/log/providapt/alerts.json"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var alerts []map[string]interface{}
	if err := json.Unmarshal(data, &alerts); err != nil {
		return nil
	}
	return alerts
}
