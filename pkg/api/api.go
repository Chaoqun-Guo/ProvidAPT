// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package api provides a lightweight HTTP API for the ProvidAPT
// provenance graph, supporting Cytoscape.js-compatible graph export,
// interactive node backtracking, and alert SVG snapshots.
//
// All endpoints return JSON (except SVG which returns image/svg+xml).
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	Status               string `json:"status"`                 // "healthy" or "unhealthy"
	UptimeSeconds        int64  `json:"uptime_seconds"`         // process uptime
	EbpfCollector        bool   `json:"ebpf_collector"`         // eBPF ring buffer active
	PipelineHealthy      bool   `json:"pipeline_healthy"`       // pipeline processing
	StoreHealthy         bool   `json:"store_healthy"`          // storage backend
	EventsIngested       uint64 `json:"events_ingested"`        // total ingested
	EventsDropped        uint64 `json:"events_dropped"`         // total dropped
	MemoryBytes          uint64 `json:"memory_bytes"`           // RSS in bytes
	Version              string `json:"version"`                // build version
	SanityCheck          string `json:"sanity_check,omitempty"` // "pass", "fail", or "" (not run)
	TelemetryEnabled     bool   `json:"telemetry_enabled,omitempty"`
	TelemetryHealthy     bool   `json:"telemetry_healthy,omitempty"`
	TelemetryLastSuccess string `json:"telemetry_last_success,omitempty"`
	TelemetryLastError   string `json:"telemetry_last_error,omitempty"`
}

// HealthCheckFunc is called by /health to determine daemon health.
type HealthCheckFunc func() HealthStatus

type ClusterAgent struct {
	AgentID         string   `json:"agent_id"`
	Group           string   `json:"group,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	Status          string   `json:"status"`
	Version         string   `json:"version,omitempty"`
	LastReportAt    string   `json:"last_report_at,omitempty"`
	EventsIngested  uint64   `json:"events_ingested,omitempty"`
	EventsDropped   uint64   `json:"events_dropped,omitempty"`
	MemoryBytes     uint64   `json:"memory_bytes,omitempty"`
	UptimeSeconds   int64    `json:"uptime_seconds,omitempty"`
	PipelineHealthy bool     `json:"pipeline_healthy"`
	StoreHealthy    bool     `json:"store_healthy"`
	AttachmentMode  string   `json:"attachment_mode,omitempty"`
}

type ClusterOverview struct {
	UpdatedAt      string         `json:"updated_at"`
	TotalAgents    int            `json:"total_agents"`
	HealthyAgents  int            `json:"healthy_agents"`
	DegradedAgents int            `json:"degraded_agents"`
	Agents         []ClusterAgent `json:"agents"`
}

type ClusterOverviewFunc func() ClusterOverview

type FleetList struct {
	UpdatedAt string               `json:"updated_at"`
	Group     string               `json:"group,omitempty"`
	Tag       string               `json:"tag,omitempty"`
	Agents    []ClusterAgent       `json:"agents"`
	History   []ControlActionAudit `json:"history,omitempty"`
}

type FleetListFunc func(group, tag string) FleetList

type FleetUpdate struct {
	AgentID string   `json:"agent_id"`
	Group   string   `json:"group,omitempty"`
	Tags    []string `json:"tags,omitempty"`
	Note    string   `json:"note,omitempty"`
	Actor   string   `json:"actor,omitempty"`
	Role    string   `json:"role,omitempty"`
}

type FleetUpdateFunc func(update FleetUpdate) error

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
	Category  string       `json:"category,omitempty"`
	Source    string       `json:"source,omitempty"`
	Entries   []AuditEntry `json:"entries"`
}

type AuditQueryFunc func(category, source string, limit int) AuditFeed

type LicenseStatus struct {
	UpdatedAt           string               `json:"updated_at"`
	Path                string               `json:"path,omitempty"`
	LicenseID           string               `json:"license_id,omitempty"`
	Present             bool                 `json:"present"`
	SizeBytes           int64                `json:"size_bytes,omitempty"`
	ModifiedAt          string               `json:"modified_at,omitempty"`
	Customer            string               `json:"customer,omitempty"`
	Edition             string               `json:"edition,omitempty"`
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
	Action string `json:"action"`
	Note   string `json:"note,omitempty"`
	Actor  string `json:"actor,omitempty"`
	Role   string `json:"role,omitempty"`
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
}

type PolicyCenter struct {
	UpdatedAt string               `json:"updated_at"`
	Current   PolicySummary        `json:"current"`
	Draft     PolicySummary        `json:"draft"`
	History   []PolicySummary      `json:"history"`
	Actions   []ControlActionAudit `json:"actions,omitempty"`
}

type PolicyCenterFunc func() PolicyCenter

type PolicyActionRequest struct {
	Action        string `json:"action"`
	Notes         string `json:"notes,omitempty"`
	TargetVersion int    `json:"target_version,omitempty"`
	Actor         string `json:"actor,omitempty"`
	Role          string `json:"role,omitempty"`
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
	Action   string `json:"action"`
	AlertID  string `json:"alert_id,omitempty"`
	Assignee string `json:"assignee,omitempty"`
	Duration string `json:"duration,omitempty"`
	Note     string `json:"note,omitempty"`
	Actor    string `json:"actor,omitempty"`
	Role     string `json:"role,omitempty"`
}

type AlertWorkflowActionFunc func(req AlertWorkflowActionRequest) (AlertWorkflowItem, error)

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

// ═══════════════════════════════════════════════════════════════
// Server
// ═══════════════════════════════════════════════════════════════

type Server struct {
	addr        string
	graph       *provenance.Graph
	store       *store.Store
	backtracer  *backtrace.Backtracer
	healthFn    HealthCheckFunc
	clusterFn   ClusterOverviewFunc
	fleetListFn FleetListFunc
	fleetSetFn  FleetUpdateFunc
	supportFn   SupportBundleFunc
	supportAct  SupportBundleActionFunc
	supportDl   SupportBundleDownloadFunc
	auditFn     AuditQueryFunc
	licenseFn   LicenseStatusFunc
	licenseAct  LicenseActionFunc
	upgradeFn   UpgradeReadinessFunc
	upgradeAct  UpgradeActionFunc
	policyFn    PolicyCenterFunc
	policyActFn PolicyActionFunc
	alertsFn    AlertWorkflowFunc
	alertActFn  AlertWorkflowActionFunc
	deliveryFn  NotifyDeliveryFunc
	deliveryAct NotifyDeliveryActionFunc
	mux         *http.ServeMux
	startTime   time.Time
	reloadFn    func() error
	authKeys    []string
	authRoles   map[string]string
	authIDs     map[string]string
	authEnabled bool
	rateLimiter *rateLimiter
	corsOrigins []string
}

func NewServer(addr string, graph *provenance.Graph, st *store.Store) *Server {
	s := &Server{
		addr:       addr,
		graph:      graph,
		store:      st,
		backtracer: backtrace.New(graph, st),
		startTime:  time.Now(),
	}
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

func (s *Server) SetAuditQueryFunc(fn AuditQueryFunc) {
	s.auditFn = fn
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

func (s *Server) SetAlertWorkflowFunc(fn AlertWorkflowFunc) {
	s.alertsFn = fn
}

func (s *Server) SetAlertWorkflowActionFunc(fn AlertWorkflowActionFunc) {
	s.alertActFn = fn
}

func (s *Server) SetNotifyDeliveryFunc(fn NotifyDeliveryFunc) {
	s.deliveryFn = fn
}

func (s *Server) SetNotifyDeliveryActionFunc(fn NotifyDeliveryActionFunc) {
	s.deliveryAct = fn
}

// SetReloadHandler registers a config reload callback called by
// POST /api/v1/admin/reload. Same logic as SIGHUP handling.
func (s *Server) SetReloadHandler(fn func() error) {
	s.reloadFn = fn
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
	h = authorizationMiddleware()(h)
	h = authMiddleware(s.authKeys, s.authRoles, s.authIDs, s.authEnabled)(h)
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
	mux.HandleFunc("/api/v1/control/fleet", s.jsonHandler(s.handleFleet))
	mux.HandleFunc("/api/v1/control/support", s.jsonHandler(s.handleSupportBundles))
	mux.HandleFunc("/api/v1/control/support/download", s.handleSupportBundleDownload)
	mux.HandleFunc("/api/v1/control/audit", s.jsonHandler(s.handleAuditFeed))
	mux.HandleFunc("/api/v1/control/license", s.jsonHandler(s.handleLicenseStatus))
	mux.HandleFunc("/api/v1/control/upgrade", s.jsonHandler(s.handleUpgradeReadiness))
	mux.HandleFunc("/api/v1/control/policies", s.jsonHandler(s.handlePolicies))
	mux.HandleFunc("/api/v1/control/alerts", s.jsonHandler(s.handleAlertWorkflow))
	mux.HandleFunc("/api/v1/control/deliveries", s.jsonHandler(s.handleNotifyDeliveries))
	mux.HandleFunc("/api/v1/graph/export", s.jsonHandler(s.handleExport))
	mux.HandleFunc("/api/v1/graph/node/", s.jsonHandler(s.handleNode)) // parsed from path
	mux.HandleFunc("/api/v1/alerts", s.jsonHandler(s.handleAlerts))
	mux.HandleFunc("/api/v1/admin/reload", s.jsonHandler(s.handleReload))
	mux.HandleFunc("/api/v1/events/search", s.jsonHandler(s.handleEventSearch))
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
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
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
		"status":    "running",
		"nodes":     stats.Nodes,
		"edges":     stats.Edges,
		"role":      CurrentRole(r),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	// Augment with health fields when available
	if s.healthFn != nil {
		h := s.healthFn()
		resp["health"] = h.Status
		resp["uptime_seconds"] = h.UptimeSeconds
		resp["memory_bytes"] = h.MemoryBytes
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
	return json.NewEncoder(w).Encode(overview)
}

func (s *Server) handleFleet(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		group := strings.TrimSpace(r.URL.Query().Get("group"))
		tag := strings.TrimSpace(r.URL.Query().Get("tag"))
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
		var update FleetUpdate
		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			return fmt.Errorf("decode fleet update: %w", err)
		}
		update.Role = CurrentRole(r)
		if update.Actor == "" {
			update.Actor = CurrentActor(r)
		}
		if strings.TrimSpace(update.AgentID) == "" {
			return fmt.Errorf("agent_id is required")
		}
		if err := s.fleetSetFn(update); err != nil {
			return err
		}
		return json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
	}
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
	return json.NewEncoder(w).Encode(feed)
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
		return json.NewEncoder(w).Encode(center)
	case http.MethodPost:
		if s.policyActFn == nil {
			w.WriteHeader(http.StatusNotImplemented)
			return json.NewEncoder(w).Encode(map[string]string{"error": "policy actions not enabled"})
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
		var req AlertWorkflowActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return fmt.Errorf("decode alert workflow action: %w", err)
		}
		req.Role = CurrentRole(r)
		if req.Actor == "" {
			req.Actor = CurrentActor(r)
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

// ── Graph export: /api/v1/graph/export?pid=1234&start=...&end=... ──

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

func (s *Server) handleAlertSVG(w http.ResponseWriter, r *http.Request, path string) error {
	// Parse: <id>/svg
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 || parts[1] != "svg" {
		return fmt.Errorf("usage: /api/v1/alerts/<id>/svg")
	}
	alertID := parts[0]

	svg, err := generateAlertSVG(alertID, s.graph)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Write(svg)
	return nil
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
