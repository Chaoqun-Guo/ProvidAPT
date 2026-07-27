// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package mgmt implements the ProvidAPT remote management
// architecture with gRPC, dynamic policy delivery, and mTLS.
package mgmt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	mgmtpb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/mgmt"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/certauth"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/analyzer"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/control"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/policy/sigma"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/version"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/telemetry"
)

// Server

// Server implements the ProvidAPTManagement gRPC service.
type Server struct {
	addr      string
	server    *grpc.Server
	config    *ServerConfig
	ctrl      *control.Controller
	analyzer  *analyzer.Analyzer
	alertSub  alertSubscription
	started   time.Time
	telemetry telemetryStatus
	policy    policyState
}

type telemetryStatus struct {
	mu              sync.Mutex
	Reports         int
	LastReportAt    time.Time
	LastContentType string
	LastAgentID     string
	Agents          map[string]AgentTelemetrySnapshot
}

type persistedControlPlaneState struct {
	Agents        map[string]persistedAgentMetadata `json:"agents,omitempty"`
	Fleet         map[string]AgentTelemetrySnapshot `json:"fleet,omitempty"`
	Policy        persistedPolicyState              `json:"policy,omitempty"`
	SavedAt       time.Time                         `json:"saved_at"`
	SchemaVersion int                               `json:"schema_version"`
}

type persistedAgentMetadata struct {
	Group               string    `json:"group,omitempty"`
	Tags                []string  `json:"tags,omitempty"`
	EnrollmentStatus    string    `json:"enrollment_status,omitempty"`
	EnrollmentNote      string    `json:"enrollment_note,omitempty"`
	EnrollmentUpdatedAt time.Time `json:"enrollment_updated_at,omitempty"`
	CertFingerprint     string    `json:"cert_fingerprint,omitempty"`
}

type persistedPolicyState struct {
	Current     PolicyRevision   `json:"current"`
	Draft       PolicyRevision   `json:"draft"`
	History     []PolicyRevision `json:"history,omitempty"`
	NextVersion int              `json:"next_version"`
	Bundle      policyBundle     `json:"bundle,omitempty"`
}

type AgentTelemetrySnapshot struct {
	AgentID              string    `json:"agent_id"`
	Hostname             string    `json:"hostname,omitempty"`
	OS                   string    `json:"os,omitempty"`
	OSVersion            string    `json:"os_version,omitempty"`
	Kernel               string    `json:"kernel,omitempty"`
	Architecture         string    `json:"architecture,omitempty"`
	CPUCount             int       `json:"cpu_count,omitempty"`
	Group                string    `json:"group,omitempty"`
	Tags                 []string  `json:"tags,omitempty"`
	Version              string    `json:"version,omitempty"`
	Status               string    `json:"status"`
	StatusReason         string    `json:"status_reason,omitempty"`
	LastReportAt         time.Time `json:"last_report_at"`
	LastReportAge        int64     `json:"last_report_age_seconds"`
	EventsIngested       uint64    `json:"events_ingested,omitempty"`
	EventsDropped        uint64    `json:"events_dropped,omitempty"`
	GraphNodes           int       `json:"graph_nodes,omitempty"`
	GraphEdges           int       `json:"graph_edges,omitempty"`
	MemoryBytes          uint64    `json:"memory_bytes,omitempty"`
	UptimeSeconds        int64     `json:"uptime_seconds,omitempty"`
	PipelineHealthy      bool      `json:"pipeline_healthy"`
	StoreHealthy         bool      `json:"store_healthy"`
	AttachmentMode       string    `json:"attachment_mode,omitempty"`
	AppliedPolicyVersion int       `json:"applied_policy_version,omitempty"`
	EnrollmentStatus     string    `json:"enrollment_status,omitempty"`
	EnrollmentNote       string    `json:"enrollment_note,omitempty"`
	EnrollmentUpdatedAt  time.Time `json:"enrollment_updated_at,omitempty"`
	CertFingerprint      string    `json:"cert_fingerprint,omitempty"`
}

type FleetFilter struct {
	Group string
	Tag   string
}

type PolicyRevision struct {
	Version          int       `json:"version"`
	State            string    `json:"state"`
	Notes            string    `json:"notes,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
	PublishedAt      time.Time `json:"published_at,omitempty"`
	ActiveRules      int       `json:"active_rules"`
	SigmaRuleIDs     []string  `json:"sigma_rule_ids,omitempty"`
	WhitelistCount   int       `json:"whitelist_count"`
	TaintSourceCount int       `json:"taint_source_count"`
	DeploymentStatus string    `json:"deployment_status,omitempty"`
	TargetGroup      string    `json:"target_group,omitempty"`
	TargetTag        string    `json:"target_tag,omitempty"`
	TargetAgents     int       `json:"target_agents,omitempty"`
	AckedAgents      int       `json:"acked_agents,omitempty"`
	PendingAgents    int       `json:"pending_agents,omitempty"`
	BundlePath       string    `json:"bundle_path,omitempty"`
	BundleSHA256     string    `json:"bundle_sha256,omitempty"`
}

type policyBundle struct {
	Version       int               `json:"version"`
	State         string            `json:"state"`
	Notes         string            `json:"notes,omitempty"`
	GeneratedAt   time.Time         `json:"generated_at"`
	SigmaRules    map[string]string `json:"sigma_rules,omitempty"`
	WhitelistKeys []string          `json:"whitelist_keys,omitempty"`
	TaintSources  []string          `json:"taint_sources,omitempty"`
}

type PolicyCenterSnapshot struct {
	UpdatedAt time.Time        `json:"updated_at"`
	Current   PolicyRevision   `json:"current"`
	Draft     PolicyRevision   `json:"draft"`
	History   []PolicyRevision `json:"history"`
}

type policyState struct {
	mu              sync.Mutex
	current         PolicyRevision
	draft           PolicyRevision
	history         []PolicyRevision
	nextVersion     int
	sigmaRules      map[string]string
	whitelistKeys   map[string]struct{}
	taintSourceKeys map[string]struct{}
}

// alertSubscription manages a dynamic list of WatchAlerts subscribers.
type alertSubscription struct {
	mu      sync.Mutex
	subs    []chan *mgmtpb.AlertEvent
	maxSubs int
}

// ServerConfig for the gRPC management server.
type ServerConfig struct {
	// ListenAddr -gRPC listen address (default ":50051").
	ListenAddr string

	// CertFile -TLS certificate file path.
	CertFile string

	// KeyFile -TLS private key file path.
	KeyFile string

	// CAFile -CA certificate file for client verification.
	CAFile string

	// RequireClientCert -if true, clients must present a valid cert.
	RequireClientCert bool

	// EnableTLS -if true, use TLS (mTLS if RequireClientCert).
	EnableTLS bool

	// AgentStaleAfter marks agents as STALE when no summary is received.
	AgentStaleAfter time.Duration

	// AgentOfflineAfter marks agents as OFFLINE when no summary is received.
	AgentOfflineAfter time.Duration

	// StateFile persists fleet metadata and policy publish history.
	StateFile string

	// PolicyBundleDir stores published policy bundle snapshots.
	PolicyBundleDir string

	// RevokedClientCertFingerprints are SHA-256 certificate fingerprints denied during mTLS handshakes.
	RevokedClientCertFingerprints []string

	// ClientCertRevoked optionally denies a verified client certificate during mTLS handshakes.
	ClientCertRevoked func(*x509.Certificate) bool
}

// SetController attaches the eBPF controller for runtime policy operations.
func (s *Server) SetController(ctrl *control.Controller) {
	s.ctrl = ctrl
}

// SetAnalyzer attaches the analyzer for alert streaming and config reload.
func (s *Server) SetAnalyzer(anz *analyzer.Analyzer) {
	s.analyzer = anz
	s.refreshPolicyDraft("analyzer attached")
}

// StartAlertForwarder begins forwarding analyzer alerts to all gRPC subscribers.
// Runs until alertCh is closed.
func (s *Server) StartAlertForwarder(alertCh <-chan *analyzer.Alert) {
	go func() {
		for al := range alertCh {
			evt := alertToEvent(al)
			s.alertSub.broadcast(evt)
		}
	}()
}

func alertToEvent(al *analyzer.Alert) *mgmtpb.AlertEvent {
	return &mgmtpb.AlertEvent{
		TimestampNs: al.DetectedAt.UnixNano(),
		AlertId:     string(al.Pattern) + ":" + al.AlertNodeID,
		Severity:    severityString(al.Severity),
		Title:       al.Headline,
		Description: al.Reason,
	}
}

func severityString(sev analyzer.Severity) string {
	switch sev {
	case analyzer.SeverityInfo:
		return "INFO"
	case analyzer.SeverityLow:
		return "LOW"
	case analyzer.SeverityMedium:
		return "MEDIUM"
	case analyzer.SeverityHigh:
		return "HIGH"
	case analyzer.SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (as *alertSubscription) broadcast(evt *mgmtpb.AlertEvent) {
	as.mu.Lock()
	defer as.mu.Unlock()
	for _, ch := range as.subs {
		select {
		case ch <- evt:
		default:
		}
	}
}

func (as *alertSubscription) subscribe(ch chan *mgmtpb.AlertEvent) {
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.maxSubs == 0 {
		as.maxSubs = 64
	}
	if len(as.subs) >= as.maxSubs {
		return
	}
	as.subs = append(as.subs, ch)
}

func (as *alertSubscription) unsubscribe(ch chan *mgmtpb.AlertEvent) {
	as.mu.Lock()
	defer as.mu.Unlock()
	for i, s := range as.subs {
		if s == ch {
			as.subs = append(as.subs[:i], as.subs[i+1:]...)
			close(ch)
			return
		}
	}
}

// DefaultServerConfig returns a secure default config.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddr:        ":50051",
		RequireClientCert: true,
		EnableTLS:         true,
		AgentStaleAfter:   2 * time.Minute,
		AgentOfflineAfter: 5 * time.Minute,
	}
}

func normalizeAgentMonitorConfig(cfg *ServerConfig) {
	if cfg.AgentStaleAfter <= 0 {
		cfg.AgentStaleAfter = 2 * time.Minute
	}
	if cfg.AgentOfflineAfter <= 0 {
		cfg.AgentOfflineAfter = 5 * time.Minute
	}
	if cfg.AgentOfflineAfter < cfg.AgentStaleAfter {
		cfg.AgentOfflineAfter = cfg.AgentStaleAfter
	}
	if strings.TrimSpace(cfg.PolicyBundleDir) == "" && strings.TrimSpace(cfg.StateFile) != "" {
		cfg.PolicyBundleDir = filepath.Join(filepath.Dir(cfg.StateFile), "policy-bundles")
	}
}

// NewServer creates a gRPC management server.
func NewServer(cfg *ServerConfig) (*Server, error) {
	if cfg == nil {
		cfg = DefaultServerConfig()
	}
	normalizeAgentMonitorConfig(cfg)
	s := &Server{
		addr:    cfg.ListenAddr,
		config:  cfg,
		started: time.Now(),
		telemetry: telemetryStatus{
			Agents: make(map[string]AgentTelemetrySnapshot),
		},
		policy: policyState{
			nextVersion:     2,
			sigmaRules:      make(map[string]string),
			whitelistKeys:   make(map[string]struct{}),
			taintSourceKeys: make(map[string]struct{}),
		},
	}
	initialPolicy := PolicyRevision{
		Version:          1,
		State:            "published",
		UpdatedAt:        s.started,
		PublishedAt:      s.started,
		DeploymentStatus: "local_applied",
	}
	s.policy.current = initialPolicy
	s.policy.draft = clonePolicyRevision(initialPolicy)
	s.policy.draft.State = "draft"
	s.policy.history = []PolicyRevision{clonePolicyRevision(initialPolicy)}
	if err := s.loadState(); err != nil {
		return nil, err
	}
	if err := s.ensureCurrentPolicyBundle(); err != nil {
		return nil, err
	}
	if cfg.ClientCertRevoked == nil {
		cfg.ClientCertRevoked = s.isClientCertRevoked
	}

	var opts []grpc.ServerOption

	if cfg.EnableTLS {
		tlsConfig, err := loadTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("load tls: %w", err)
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	s.server = grpc.NewServer(opts...)
	mgmtpb.RegisterProvidAPTManagementServer(s.server, s)
	mgmtpb.RegisterProvidAPTTelemetryServer(s.server, s)

	return s, nil
}

// Start begins listening for gRPC connections.
func (s *Server) Start() error {
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	log.Printf("[mgmt] gRPC server listening on %s (tls=%v, mTLS=%v)",
		s.addr, s.config.EnableTLS, s.config.RequireClientCert)

	go func() {
		if err := s.server.Serve(lis); err != nil {
			log.Printf("[mgmt] serve error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the gRPC server.
func (s *Server) Stop() {
	s.server.GracefulStop()
	log.Printf("[mgmt] server stopped")
}

// gRPC handler implementations

// Query handles provenance data queries.
func (s *Server) Query(ctx context.Context, req *mgmtpb.QueryRequest) (*mgmtpb.QueryResponse, error) {
	clientInfo := clientIdentity(ctx)
	log.Printf("[mgmt] Query from %s: %s", clientInfo, req.Query)

	resp := &mgmtpb.QueryResponse{
		ResultsJson: `{"message":"query received"}`,
		QueryTimeNs: time.Now().UnixNano(),
	}

	// If we have an analyzer, include alert count
	if s.analyzer != nil {
		alerts := s.analyzer.Alerts()
		resp.ResultsJson = fmt.Sprintf(`{"alert_count":%d}`, len(alerts))
	}

	return resp, nil
}

// WatchAlerts streams real-time alerts to authorized clients.
func (s *Server) WatchAlerts(filter *mgmtpb.AlertFilter, stream mgmtpb.ProvidAPTManagement_WatchAlertsServer) error {
	clientInfo := clientIdentity(stream.Context())
	log.Printf("[mgmt] Alert stream started from %s (min_severity=%s)",
		clientInfo, filter.MinSeverity)

	ch := make(chan *mgmtpb.AlertEvent, 64)
	s.alertSub.subscribe(ch)
	defer s.alertSub.unsubscribe(ch)

	for {
		select {
		case evt := <-ch:
			if err := stream.Send(evt); err != nil {
				return fmt.Errorf("send alert: %w", err)
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

// UpdatePolicy handles real-time policy updates.
func (s *Server) UpdatePolicy(ctx context.Context, update *mgmtpb.PolicyUpdate) (*mgmtpb.PolicyAck, error) {
	clientInfo := clientIdentity(ctx)

	ack := &mgmtpb.PolicyAck{
		Success:     true,
		AppliedAtNs: time.Now().UnixNano(),
	}

	switch u := update.Update.(type) {
	case *mgmtpb.PolicyUpdate_Whitelist:
		ack.Message = s.applyWhitelistUpdate(u.Whitelist, clientInfo)
	case *mgmtpb.PolicyUpdate_Sigma:
		log.Printf("[mgmt] Policy update from %s: sigma rule %s %s",
			clientInfo, u.Sigma.Action, u.Sigma.RuleId)

		if s.analyzer == nil {
			ack.Message = "analyzer not available"
			break
		}

		switch u.Sigma.Action {
		case "add", "update":
			parsed, err := sigma.ParseRule([]byte(u.Sigma.RuleYaml))
			if err != nil {
				ack.Success = false
				ack.Message = fmt.Sprintf("parse error: %v", err)
				break
			}
			s.analyzer.AddSigmaRule(u.Sigma.RuleId, parsed)
			s.recordSigmaRule(u.Sigma.RuleId, u.Sigma.RuleYaml, true)
			ack.Message = fmt.Sprintf("sigma rule %s applied", u.Sigma.RuleId)
		case "remove":
			s.analyzer.RemoveSigmaRule(u.Sigma.RuleId)
			s.recordSigmaRule(u.Sigma.RuleId, "", false)
			ack.Message = fmt.Sprintf("sigma rule %s removed", u.Sigma.RuleId)
		default:
			ack.Success = false
			ack.Message = fmt.Sprintf("unknown action %q", u.Sigma.Action)
		}
	case *mgmtpb.PolicyUpdate_TaintSource:
		log.Printf("[mgmt] Policy update from %s: taint source %s %s (label=%s)",
			clientInfo, u.TaintSource.Action, u.TaintSource.IpPrefix, u.TaintSource.Label)
		switch u.TaintSource.Action {
		case "add":
			if u.TaintSource.Label != "" {
				analyzer.AddUntrustedComm(u.TaintSource.Label)
				s.recordTaintSourceKey(u.TaintSource.IpPrefix+"|"+u.TaintSource.Label, true)
				ack.Message = fmt.Sprintf("taint source %s added (label=%s)", u.TaintSource.IpPrefix, u.TaintSource.Label)
			} else {
				s.recordTaintSourceKey(u.TaintSource.IpPrefix, true)
				ack.Message = fmt.Sprintf("taint source %s added (no label)", u.TaintSource.IpPrefix)
			}
		case "remove":
			if u.TaintSource.Label != "" {
				analyzer.RemoveUntrustedComm(u.TaintSource.Label)
				s.recordTaintSourceKey(u.TaintSource.IpPrefix+"|"+u.TaintSource.Label, false)
				ack.Message = fmt.Sprintf("taint source %s removed (label=%s)", u.TaintSource.IpPrefix, u.TaintSource.Label)
			} else {
				s.recordTaintSourceKey(u.TaintSource.IpPrefix, false)
				ack.Message = fmt.Sprintf("taint source %s removed", u.TaintSource.IpPrefix)
			}
		default:
			ack.Success = false
			ack.Message = fmt.Sprintf("unknown taint action %q", u.TaintSource.Action)
		}
	default:
		ack.Success = false
		ack.Message = "unknown update type"
	}
	if ack.Success {
		s.refreshPolicyDraft(ack.Message)
	}

	return ack, nil
}

func (s *Server) applyWhitelistUpdate(w *mgmtpb.WhitelistUpdate, clientInfo string) string {
	if s.ctrl == nil {
		log.Printf("[mgmt] whitelist update from %s: controller not available", clientInfo)
		return "controller not available"
	}

	log.Printf("[mgmt] Policy update from %s: whitelist %s %s=%s",
		clientInfo, w.Action, w.Target, w.Value)

	switch w.Target {
	case "pid":
		pid, err := strconv.ParseUint(w.Value, 10, 32)
		if err != nil {
			return fmt.Sprintf("invalid pid %q", w.Value)
		}
		switch w.Action {
		case "add":
			if err := s.ctrl.ExcludePID(uint32(pid)); err != nil {
				return fmt.Sprintf("exclude pid failed: %v", err)
			}
			s.recordWhitelistKey(fmt.Sprintf("pid:%d", pid), true)
			return fmt.Sprintf("PID %d excluded", pid)
		case "remove":
			if err := s.ctrl.UnExcludePID(uint32(pid)); err != nil {
				return fmt.Sprintf("unexclude pid failed: %v", err)
			}
			s.recordWhitelistKey(fmt.Sprintf("pid:%d", pid), false)
			return fmt.Sprintf("PID %d unexcluded", pid)
		}

	case "comm":
		// Comm-based whitelist -currently unsupported via gRPC
		switch w.Action {
		case "add":
			excluded, err := s.ctrl.ExcludeComms([]string{w.Value})
			if err != nil {
				return fmt.Sprintf("exclude comm failed: %v", err)
			}
			s.recordWhitelistKey("comm:"+w.Value, true)
			return fmt.Sprintf("comm %s excluded (%d running process(es))", w.Value, excluded)
		case "remove":
			s.recordWhitelistKey("comm:"+w.Value, false)
			return fmt.Sprintf("comm %s removed from policy draft; running PIDs remain excluded until restart or explicit PID unexclude", w.Value)
		case "clear":
			s.clearWhitelistKeys()
			return "comm whitelist metadata cleared"
		}

	case "path":
		switch w.Action {
		case "add":
			if err := s.ctrl.AddHotPath(w.Value); err != nil {
				return fmt.Sprintf("add hot path failed: %v", err)
			}
			s.recordWhitelistKey("path:"+w.Value, true)
			return fmt.Sprintf("hot path %s added", w.Value)
		case "remove":
			if err := s.ctrl.RemoveHotPath(w.Value); err != nil {
				return fmt.Sprintf("remove hot path failed: %v", err)
			}
			s.recordWhitelistKey("path:"+w.Value, false)
			return fmt.Sprintf("hot path %s removed", w.Value)
		case "clear":
			if err := s.ctrl.ClearHotPaths(); err != nil {
				return fmt.Sprintf("clear hot paths failed: %v", err)
			}
			s.clearWhitelistKeys()
			return "all hot paths cleared"
		}
	}

	return fmt.Sprintf("unknown whitelist target %q or action %q", w.Target, w.Action)
}

// Check handles health check requests.
func (s *Server) Check(ctx context.Context, req *mgmtpb.HealthCheck) (*mgmtpb.HealthStatus, error) {
	hs := &mgmtpb.HealthStatus{
		AgentRunning: true,
		Version:      version.String(),
		UptimeNs:     time.Since(s.started).Nanoseconds(),
		Status:       "HEALTHY",
	}

	if s.analyzer != nil {
		hs.TailedAlerts = int32(len(s.analyzer.Alerts()))
	}

	return hs, nil
}

func (s *Server) TelemetryOverview() []AgentTelemetrySnapshot {
	s.telemetry.mu.Lock()
	defer s.telemetry.mu.Unlock()

	agents := make([]AgentTelemetrySnapshot, 0, len(s.telemetry.Agents))
	now := time.Now()
	for _, snapshot := range s.telemetry.Agents {
		agents = append(agents, s.agentSnapshotStatus(snapshot, now))
	}
	return agents
}

func (s *Server) UpsertAgentMetadata(agentID, group string, tags []string) {
	s.telemetry.mu.Lock()
	snapshot := s.telemetry.Agents[agentID]
	snapshot.AgentID = agentID
	if group != "" {
		snapshot.Group = group
	}
	if tags != nil {
		snapshot.Tags = dedupeTags(tags)
	}
	s.telemetry.Agents[agentID] = snapshot
	s.telemetry.mu.Unlock()
	if err := s.saveState(); err != nil {
		log.Printf("[mgmt] save control-plane state: %v", err)
	}
}

func (s *Server) SetAgentEnrollment(agentID, status, note string) error {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return fmt.Errorf("agent_id is required")
	}
	status = normalizeEnrollmentStatus(status)
	if status == "" {
		return fmt.Errorf("unsupported enrollment status")
	}
	s.telemetry.mu.Lock()
	snapshot := s.telemetry.Agents[agentID]
	snapshot.AgentID = agentID
	snapshot.EnrollmentStatus = status
	snapshot.EnrollmentNote = strings.TrimSpace(note)
	snapshot.EnrollmentUpdatedAt = time.Now().UTC()
	s.telemetry.Agents[agentID] = snapshot
	s.telemetry.mu.Unlock()
	if err := s.saveState(); err != nil {
		log.Printf("[mgmt] save control-plane state: %v", err)
	}
	return nil
}

func (s *Server) FleetSnapshot(filter FleetFilter) []AgentTelemetrySnapshot {
	s.telemetry.mu.Lock()
	defer s.telemetry.mu.Unlock()

	agents := make([]AgentTelemetrySnapshot, 0, len(s.telemetry.Agents))
	now := time.Now()
	for _, snapshot := range s.telemetry.Agents {
		snapshot = s.agentSnapshotStatus(snapshot, now)
		if filter.Group != "" && !strings.EqualFold(snapshot.Group, filter.Group) {
			continue
		}
		if filter.Tag != "" && !hasTag(snapshot.Tags, filter.Tag) {
			continue
		}
		agents = append(agents, snapshot)
	}
	return agents
}

func (s *Server) agentSnapshotStatus(snapshot AgentTelemetrySnapshot, now time.Time) AgentTelemetrySnapshot {
	if snapshot.AgentID == "" {
		return snapshot
	}
	if snapshot.EnrollmentStatus == "" {
		snapshot.EnrollmentStatus = "pending"
	}
	if snapshot.EnrollmentStatus == "revoked" {
		snapshot.Status = "REVOKED"
		snapshot.StatusReason = enrollmentReason(snapshot)
		return snapshot
	}
	if snapshot.EnrollmentStatus == "quarantined" {
		snapshot.Status = "QUARANTINED"
		snapshot.StatusReason = enrollmentReason(snapshot)
		return snapshot
	}
	if snapshot.LastReportAt.IsZero() {
		snapshot.Status = "OFFLINE"
		snapshot.StatusReason = "no telemetry summary received"
		return snapshot
	}
	age := now.Sub(snapshot.LastReportAt)
	if age < 0 {
		age = 0
	}
	snapshot.LastReportAge = int64(age.Seconds())
	if age >= s.config.AgentOfflineAfter {
		snapshot.Status = "OFFLINE"
		snapshot.StatusReason = fmt.Sprintf("last report %s ago", age.Round(time.Second))
		return snapshot
	}
	if age >= s.config.AgentStaleAfter {
		snapshot.Status = "STALE"
		snapshot.StatusReason = fmt.Sprintf("last report %s ago", age.Round(time.Second))
		return snapshot
	}
	if snapshot.Status == "" {
		snapshot.Status = "HEALTHY"
	}
	if !snapshot.PipelineHealthy || !snapshot.StoreHealthy {
		if !strings.EqualFold(snapshot.Status, "ERROR") {
			snapshot.Status = "DEGRADED"
		}
		snapshot.StatusReason = "agent reported unhealthy pipeline or store"
		return snapshot
	}
	snapshot.StatusReason = ""
	return snapshot
}

func enrollmentReason(snapshot AgentTelemetrySnapshot) string {
	if strings.TrimSpace(snapshot.EnrollmentNote) != "" {
		return snapshot.EnrollmentNote
	}
	return "agent enrollment status is " + snapshot.EnrollmentStatus
}

func (s *Server) PolicyCenter() PolicyCenterSnapshot {
	s.policy.mu.Lock()
	defer s.policy.mu.Unlock()

	history := make([]PolicyRevision, len(s.policy.history))
	for index, item := range s.policy.history {
		history[index] = clonePolicyRevision(item)
	}

	return PolicyCenterSnapshot{
		UpdatedAt: s.policy.draft.UpdatedAt,
		Current:   clonePolicyRevision(s.policy.current),
		Draft:     clonePolicyRevision(s.policy.draft),
		History:   history,
	}
}

func (s *Server) PublishPolicy(notes string) PolicyRevision {
	return s.PublishPolicyFor(notes, FleetFilter{})
}

func (s *Server) PublishPolicyFor(notes string, filter FleetFilter) PolicyRevision {
	targetAgents := s.policyTargetAgentCount(filter)

	s.policy.mu.Lock()
	s.refreshPolicyDraftLocked(notes)
	published := clonePolicyRevision(s.policy.draft)
	published.Version = s.policy.nextVersion
	published.State = "published"
	published.Notes = strings.TrimSpace(notes)
	published.UpdatedAt = time.Now()
	published.PublishedAt = published.UpdatedAt
	published.TargetGroup = strings.TrimSpace(filter.Group)
	published.TargetTag = strings.TrimSpace(filter.Tag)
	published.TargetAgents = targetAgents
	published.AckedAgents = 0
	published.PendingAgents = targetAgents
	published.DeploymentStatus = "local_applied"
	if targetAgents > 0 {
		published.DeploymentStatus = "queued"
	}
	bundle := s.buildPolicyBundleLocked(published)
	if path, hash, err := s.writePolicyBundle(bundle); err != nil {
		log.Printf("[mgmt] write policy bundle: %v", err)
	} else {
		published.BundlePath = path
		published.BundleSHA256 = hash
	}
	s.policy.nextVersion++

	s.policy.current = clonePolicyRevision(published)
	s.policy.history = append(s.policy.history, clonePolicyRevision(published))
	s.policy.draft = clonePolicyRevision(published)
	s.policy.draft.State = "draft"
	out := clonePolicyRevision(published)
	s.policy.mu.Unlock()
	if err := s.saveState(); err != nil {
		log.Printf("[mgmt] save control-plane state: %v", err)
	}
	return out
}

func (s *Server) RollbackPolicy(version int, notes string) (PolicyRevision, error) {
	return s.RollbackPolicyFor(version, notes, FleetFilter{})
}

func (s *Server) RollbackPolicyFor(version int, notes string, filter FleetFilter) (PolicyRevision, error) {
	targetAgents := s.policyTargetAgentCount(filter)

	s.policy.mu.Lock()
	var target *PolicyRevision
	for index := range s.policy.history {
		if s.policy.history[index].Version == version {
			target = &s.policy.history[index]
			break
		}
	}
	if target == nil {
		s.policy.mu.Unlock()
		return PolicyRevision{}, fmt.Errorf("policy version %d not found", version)
	}

	rolled := clonePolicyRevision(*target)
	rolled.Version = s.policy.nextVersion
	rolled.State = "rolled_back"
	rolled.Notes = strings.TrimSpace(notes)
	rolled.UpdatedAt = time.Now()
	rolled.PublishedAt = rolled.UpdatedAt
	rolled.TargetGroup = strings.TrimSpace(filter.Group)
	rolled.TargetTag = strings.TrimSpace(filter.Tag)
	rolled.TargetAgents = targetAgents
	rolled.AckedAgents = 0
	rolled.PendingAgents = targetAgents
	rolled.DeploymentStatus = "rollback_queued"
	if targetAgents == 0 {
		rolled.DeploymentStatus = "local_applied"
	}
	if bundle, err := s.readPolicyBundleLocked(*target); err == nil {
		s.applyPolicyBundleLocked(bundle)
	} else {
		log.Printf("[mgmt] read rollback policy bundle: %v", err)
	}
	bundle := s.buildPolicyBundleLocked(rolled)
	if path, hash, err := s.writePolicyBundle(bundle); err != nil {
		log.Printf("[mgmt] write rollback policy bundle: %v", err)
	} else {
		rolled.BundlePath = path
		rolled.BundleSHA256 = hash
	}
	s.policy.nextVersion++

	s.policy.current = clonePolicyRevision(rolled)
	s.policy.history = append(s.policy.history, clonePolicyRevision(rolled))
	s.policy.draft = clonePolicyRevision(rolled)
	s.policy.draft.State = "draft"
	out := clonePolicyRevision(rolled)
	s.policy.mu.Unlock()
	if err := s.saveState(); err != nil {
		log.Printf("[mgmt] save control-plane state: %v", err)
	}
	return out, nil
}

// ReportEvents receives compressed or summarized telemetry batches from agents.
func (s *Server) ReportEvents(stream mgmtpb.ProvidAPTTelemetry_ReportEventsServer) error {
	var count int
	var lastType string
	var lastAgentID string
	var lastSummary telemetry.Summary
	certFingerprint := clientCertFingerprint(stream.Context())

	for {
		event, err := stream.Recv()
		if err != nil {
			if count == 0 {
				return stream.SendAndClose(&mgmtpb.ReportAck{
					Accepted:      true,
					ThrottleLevel: 0,
					Message:       s.policyAckMessage("no events received"),
				})
			}
			enrollmentStatus, enrollmentNote := s.agentEnrollment(lastSummary.AgentID)
			if enrollmentStatus == "revoked" {
				message := "agent revoked"
				if strings.TrimSpace(enrollmentNote) != "" {
					message += ": " + strings.TrimSpace(enrollmentNote)
				}
				return stream.SendAndClose(&mgmtpb.ReportAck{
					Accepted:      false,
					ThrottleLevel: 3,
					Message:       message,
				})
			}
			s.telemetry.mu.Lock()
			s.telemetry.Reports += count
			s.telemetry.LastReportAt = time.Now()
			s.telemetry.LastContentType = lastType
			s.telemetry.LastAgentID = lastAgentID
			metadataChanged := false
			if lastSummary.AgentID != "" {
				existing := s.telemetry.Agents[lastSummary.AgentID]
				nextCertFingerprint := firstNonEmpty(certFingerprint, existing.CertFingerprint)
				metadataChanged = normalizeCertFingerprint(nextCertFingerprint) != normalizeCertFingerprint(existing.CertFingerprint)
				s.telemetry.Agents[lastSummary.AgentID] = AgentTelemetrySnapshot{
					AgentID:              lastSummary.AgentID,
					Hostname:             lastSummary.Hostname,
					OS:                   lastSummary.OS,
					OSVersion:            lastSummary.OSVersion,
					Kernel:               lastSummary.Kernel,
					Architecture:         lastSummary.Architecture,
					CPUCount:             lastSummary.CPUCount,
					Group:                existing.Group,
					Tags:                 existing.Tags,
					Version:              lastSummary.Version,
					Status:               lastSummary.Status,
					LastReportAt:         s.telemetry.LastReportAt,
					EventsIngested:       lastSummary.EventsIngested,
					EventsDropped:        lastSummary.EventsDropped,
					GraphNodes:           lastSummary.GraphNodes,
					GraphEdges:           lastSummary.GraphEdges,
					MemoryBytes:          lastSummary.MemoryBytes,
					UptimeSeconds:        lastSummary.UptimeSeconds,
					PipelineHealthy:      lastSummary.PipelineHealthy,
					StoreHealthy:         lastSummary.StoreHealthy,
					AttachmentMode:       lastSummary.AttachmentMode,
					AppliedPolicyVersion: lastSummary.AppliedPolicyVersion,
					EnrollmentStatus:     existing.EnrollmentStatus,
					EnrollmentNote:       existing.EnrollmentNote,
					EnrollmentUpdatedAt:  existing.EnrollmentUpdatedAt,
					CertFingerprint:      nextCertFingerprint,
				}
			}
			s.telemetry.mu.Unlock()
			deploymentChanged := s.refreshPolicyDeploymentFromAgents()
			if lastSummary.AgentID != "" || metadataChanged || deploymentChanged {
				if err := s.saveState(); err != nil {
					log.Printf("[mgmt] save control-plane state: %v", err)
				}
			}
			return stream.SendAndClose(&mgmtpb.ReportAck{
				Accepted:      true,
				ThrottleLevel: 0,
				Message:       s.policyAckMessageForAgent(lastSummary.AgentID, fmt.Sprintf("accepted %d telemetry event(s)", count)),
			})
		}
		count++
		lastType = event.ContentType
		if event.ContentType == "summary" {
			var summary telemetry.Summary
			if json.Unmarshal(event.Payload, &summary) == nil && summary.AgentID != "" {
				lastAgentID = summary.AgentID
				lastSummary = summary
			}
		}
	}
}

func (s *Server) policyAckMessage(prefix string) string {
	return s.policyAckMessageForAgent("", prefix)
}

func (s *Server) policyAckMessageForAgent(agentID, prefix string) string {
	status, note := s.agentEnrollment(agentID)
	if status == "quarantined" {
		if strings.TrimSpace(note) != "" {
			return fmt.Sprintf("%s; policy_status=quarantined enrollment_note=%q", prefix, strings.TrimSpace(note))
		}
		return fmt.Sprintf("%s; policy_status=quarantined", prefix)
	}
	s.policy.mu.Lock()
	current := clonePolicyRevision(s.policy.current)
	s.policy.mu.Unlock()
	if current.Version <= 0 {
		return prefix
	}
	if agentID != "" && !s.agentMatchesPolicyTarget(agentID, current) {
		return fmt.Sprintf("%s; policy_status=not_targeted", prefix)
	}
	deploymentStatus := current.DeploymentStatus
	if deploymentStatus == "" {
		deploymentStatus = current.State
	}
	return fmt.Sprintf("%s; policy_version=%d policy_status=%s", prefix, current.Version, deploymentStatus)
}

func (s *Server) agentEnrollment(agentID string) (string, string) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return "pending", ""
	}
	s.telemetry.mu.Lock()
	defer s.telemetry.mu.Unlock()
	snapshot := s.telemetry.Agents[agentID]
	status := normalizeEnrollmentStatus(snapshot.EnrollmentStatus)
	if status == "" {
		status = "pending"
	}
	return status, snapshot.EnrollmentNote
}

func (s *Server) agentMatchesPolicyTarget(agentID string, policy PolicyRevision) bool {
	if strings.TrimSpace(policy.TargetGroup) == "" && strings.TrimSpace(policy.TargetTag) == "" {
		return true
	}
	s.telemetry.mu.Lock()
	defer s.telemetry.mu.Unlock()
	snapshot := s.telemetry.Agents[strings.TrimSpace(agentID)]
	if strings.TrimSpace(policy.TargetGroup) != "" && !strings.EqualFold(snapshot.Group, policy.TargetGroup) {
		return false
	}
	if strings.TrimSpace(policy.TargetTag) != "" && !hasTag(snapshot.Tags, policy.TargetTag) {
		return false
	}
	return true
}

func (s *Server) refreshPolicyDeploymentFromAgents() bool {
	s.policy.mu.Lock()
	targetGroup := s.policy.current.TargetGroup
	targetTag := s.policy.current.TargetTag
	s.policy.mu.Unlock()

	s.telemetry.mu.Lock()
	appliedByAgent := make(map[string]int, len(s.telemetry.Agents))
	for agentID, snapshot := range s.telemetry.Agents {
		if normalizeEnrollmentStatus(snapshot.EnrollmentStatus) == "revoked" {
			continue
		}
		if targetGroup != "" && !strings.EqualFold(snapshot.Group, targetGroup) {
			continue
		}
		if targetTag != "" && !hasTag(snapshot.Tags, targetTag) {
			continue
		}
		appliedByAgent[agentID] = snapshot.AppliedPolicyVersion
	}
	s.telemetry.mu.Unlock()

	s.policy.mu.Lock()
	defer s.policy.mu.Unlock()
	if s.policy.current.Version <= 0 || s.policy.current.TargetAgents <= 0 {
		return false
	}
	acked := 0
	for _, version := range appliedByAgent {
		if version >= s.policy.current.Version {
			acked++
		}
	}
	if acked > s.policy.current.TargetAgents {
		acked = s.policy.current.TargetAgents
	}
	pending := s.policy.current.TargetAgents - acked
	if pending < 0 {
		pending = 0
	}
	status := s.policy.current.DeploymentStatus
	if pending == 0 {
		status = "applied"
	} else if status == "" || status == "applied" {
		status = "queued"
	}
	if s.policy.current.AckedAgents == acked &&
		s.policy.current.PendingAgents == pending &&
		s.policy.current.DeploymentStatus == status {
		return false
	}
	s.policy.current.AckedAgents = acked
	s.policy.current.PendingAgents = pending
	s.policy.current.DeploymentStatus = status
	for index := range s.policy.history {
		if s.policy.history[index].Version == s.policy.current.Version {
			s.policy.history[index].AckedAgents = acked
			s.policy.history[index].PendingAgents = pending
			s.policy.history[index].DeploymentStatus = status
		}
	}
	return true
}

func (s *Server) refreshPolicyDraft(notes string) {
	s.policy.mu.Lock()
	defer s.policy.mu.Unlock()
	s.refreshPolicyDraftLocked(notes)
}

func (s *Server) refreshPolicyDraftLocked(notes string) {
	draft := clonePolicyRevision(s.policy.current)
	draft.State = "draft"
	draft.UpdatedAt = time.Now()
	if strings.TrimSpace(notes) != "" {
		draft.Notes = strings.TrimSpace(notes)
	}
	draft.ActiveRules = 0
	draft.SigmaRuleIDs = nil
	if s.analyzer != nil {
		draft.SigmaRuleIDs = s.analyzer.SigmaRuleIDs()
		draft.ActiveRules = len(draft.SigmaRuleIDs)
	}
	draft.WhitelistCount = len(s.policy.whitelistKeys)
	draft.TaintSourceCount = len(s.policy.taintSourceKeys)
	s.policy.draft = draft
}

func (s *Server) buildPolicyBundleLocked(revision PolicyRevision) policyBundle {
	bundle := policyBundle{
		Version:       revision.Version,
		State:         revision.State,
		Notes:         strings.TrimSpace(revision.Notes),
		GeneratedAt:   time.Now().UTC(),
		SigmaRules:    make(map[string]string, len(s.policy.sigmaRules)),
		WhitelistKeys: sortedPolicyKeys(s.policy.whitelistKeys),
		TaintSources:  sortedPolicyKeys(s.policy.taintSourceKeys),
	}
	for ruleID, ruleYAML := range s.policy.sigmaRules {
		bundle.SigmaRules[ruleID] = ruleYAML
	}
	if len(bundle.SigmaRules) == 0 {
		bundle.SigmaRules = nil
	}
	return bundle
}

func (s *Server) applyPolicyBundleLocked(bundle policyBundle) {
	s.policy.sigmaRules = make(map[string]string, len(bundle.SigmaRules))
	for ruleID, ruleYAML := range bundle.SigmaRules {
		s.policy.sigmaRules[ruleID] = ruleYAML
	}
	s.policy.whitelistKeys = keysToSet(bundle.WhitelistKeys)
	s.policy.taintSourceKeys = keysToSet(bundle.TaintSources)
}

func (s *Server) writePolicyBundle(bundle policyBundle) (string, string, error) {
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("encode policy bundle: %w", err)
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	if strings.TrimSpace(s.config.PolicyBundleDir) == "" {
		return "", hash, nil
	}
	if err := os.MkdirAll(s.config.PolicyBundleDir, 0750); err != nil {
		return "", "", fmt.Errorf("create policy bundle dir: %w", err)
	}
	path := filepath.Join(s.config.PolicyBundleDir, fmt.Sprintf("policy-v%d.json", bundle.Version))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return "", "", fmt.Errorf("write policy bundle: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", "", fmt.Errorf("replace policy bundle: %w", err)
	}
	return path, hash, nil
}

func (s *Server) ensureCurrentPolicyBundle() error {
	s.policy.mu.Lock()
	if s.policy.current.Version <= 0 {
		s.policy.mu.Unlock()
		return nil
	}
	if strings.TrimSpace(s.policy.current.BundlePath) != "" {
		if _, err := os.Stat(s.policy.current.BundlePath); err == nil {
			s.policy.mu.Unlock()
			return nil
		}
	}
	current := clonePolicyRevision(s.policy.current)
	bundle := s.buildPolicyBundleLocked(current)
	path, hash, err := s.writePolicyBundle(bundle)
	if err != nil {
		s.policy.mu.Unlock()
		return err
	}
	s.policy.current.BundlePath = path
	s.policy.current.BundleSHA256 = hash
	s.policy.draft.BundlePath = path
	s.policy.draft.BundleSHA256 = hash
	for index := range s.policy.history {
		if s.policy.history[index].Version == current.Version {
			s.policy.history[index].BundlePath = path
			s.policy.history[index].BundleSHA256 = hash
		}
	}
	s.policy.mu.Unlock()
	return s.saveState()
}

func (s *Server) readPolicyBundleLocked(revision PolicyRevision) (policyBundle, error) {
	if strings.TrimSpace(revision.BundlePath) == "" {
		return policyBundle{}, fmt.Errorf("policy version %d has no bundle path", revision.Version)
	}
	data, err := os.ReadFile(revision.BundlePath)
	if err != nil {
		return policyBundle{}, fmt.Errorf("read policy bundle %s: %w", revision.BundlePath, err)
	}
	if revision.BundleSHA256 != "" {
		sum := sha256.Sum256(data)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), revision.BundleSHA256) {
			return policyBundle{}, fmt.Errorf("policy bundle checksum mismatch for version %d", revision.Version)
		}
	}
	var bundle policyBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return policyBundle{}, fmt.Errorf("decode policy bundle: %w", err)
	}
	return bundle, nil
}

func (s *Server) policyTargetAgentCount(filter FleetFilter) int {
	s.telemetry.mu.Lock()
	defer s.telemetry.mu.Unlock()
	count := 0
	for _, snapshot := range s.telemetry.Agents {
		if normalizeEnrollmentStatus(snapshot.EnrollmentStatus) == "revoked" {
			continue
		}
		if strings.TrimSpace(filter.Group) != "" && !strings.EqualFold(snapshot.Group, strings.TrimSpace(filter.Group)) {
			continue
		}
		if strings.TrimSpace(filter.Tag) != "" && !hasTag(snapshot.Tags, strings.TrimSpace(filter.Tag)) {
			continue
		}
		count++
	}
	return count
}

func (s *Server) loadState() error {
	if strings.TrimSpace(s.config.StateFile) == "" {
		return nil
	}
	state, ok, err := loadPersistedControlPlaneState(s.config.StateFile)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	s.telemetry.mu.Lock()
	for agentID, snapshot := range state.Fleet {
		if snapshot.AgentID == "" {
			snapshot.AgentID = agentID
		}
		snapshot.Tags = dedupeTags(snapshot.Tags)
		snapshot.CertFingerprint = normalizeCertFingerprint(snapshot.CertFingerprint)
		s.telemetry.Agents[agentID] = snapshot
	}
	for agentID, metadata := range state.Agents {
		snapshot := s.telemetry.Agents[agentID]
		snapshot.AgentID = agentID
		snapshot.Group = metadata.Group
		snapshot.Tags = dedupeTags(metadata.Tags)
		snapshot.EnrollmentStatus = normalizeEnrollmentStatus(metadata.EnrollmentStatus)
		if snapshot.EnrollmentStatus == "" {
			snapshot.EnrollmentStatus = "pending"
		}
		snapshot.EnrollmentNote = metadata.EnrollmentNote
		snapshot.EnrollmentUpdatedAt = metadata.EnrollmentUpdatedAt
		snapshot.CertFingerprint = normalizeCertFingerprint(metadata.CertFingerprint)
		s.telemetry.Agents[agentID] = snapshot
	}
	s.telemetry.mu.Unlock()

	s.policy.mu.Lock()
	if state.Policy.Current.Version > 0 {
		s.policy.current = clonePolicyRevision(state.Policy.Current)
	}
	if state.Policy.Draft.Version > 0 {
		s.policy.draft = clonePolicyRevision(state.Policy.Draft)
	}
	if len(state.Policy.History) > 0 {
		s.policy.history = make([]PolicyRevision, 0, len(state.Policy.History))
		for _, item := range state.Policy.History {
			s.policy.history = append(s.policy.history, clonePolicyRevision(item))
		}
	}
	if state.Policy.NextVersion > 0 {
		s.policy.nextVersion = state.Policy.NextVersion
	}
	if state.Policy.Bundle.Version > 0 ||
		len(state.Policy.Bundle.SigmaRules) > 0 ||
		len(state.Policy.Bundle.WhitelistKeys) > 0 ||
		len(state.Policy.Bundle.TaintSources) > 0 {
		s.applyPolicyBundleLocked(state.Policy.Bundle)
	}
	s.policy.mu.Unlock()
	return nil
}

func (s *Server) saveState() error {
	if strings.TrimSpace(s.config.StateFile) == "" {
		return nil
	}
	state := persistedControlPlaneState{
		Agents:        map[string]persistedAgentMetadata{},
		Fleet:         map[string]AgentTelemetrySnapshot{},
		SavedAt:       time.Now().UTC(),
		SchemaVersion: 1,
	}

	s.telemetry.mu.Lock()
	for agentID, snapshot := range s.telemetry.Agents {
		snapshot.AgentID = firstNonEmpty(snapshot.AgentID, agentID)
		snapshot.Tags = append([]string(nil), snapshot.Tags...)
		snapshot.CertFingerprint = normalizeCertFingerprint(snapshot.CertFingerprint)
		state.Fleet[agentID] = snapshot
		if snapshot.Group == "" && len(snapshot.Tags) == 0 && snapshot.EnrollmentStatus == "" && snapshot.EnrollmentNote == "" && snapshot.CertFingerprint == "" {
			continue
		}
		state.Agents[agentID] = persistedAgentMetadata{
			Group:               snapshot.Group,
			Tags:                append([]string(nil), snapshot.Tags...),
			EnrollmentStatus:    snapshot.EnrollmentStatus,
			EnrollmentNote:      snapshot.EnrollmentNote,
			EnrollmentUpdatedAt: snapshot.EnrollmentUpdatedAt,
			CertFingerprint:     normalizeCertFingerprint(snapshot.CertFingerprint),
		}
	}
	s.telemetry.mu.Unlock()

	s.policy.mu.Lock()
	state.Policy = persistedPolicyState{
		Current:     clonePolicyRevision(s.policy.current),
		Draft:       clonePolicyRevision(s.policy.draft),
		History:     make([]PolicyRevision, 0, len(s.policy.history)),
		NextVersion: s.policy.nextVersion,
		Bundle:      s.buildPolicyBundleLocked(s.policy.current),
	}
	for _, item := range s.policy.history {
		state.Policy.History = append(state.Policy.History, clonePolicyRevision(item))
	}
	s.policy.mu.Unlock()

	return savePersistedControlPlaneState(s.config.StateFile, state)
}

func (s *Server) recordSigmaRule(ruleID, ruleYAML string, present bool) {
	s.policy.mu.Lock()
	defer s.policy.mu.Unlock()
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return
	}
	if present {
		s.policy.sigmaRules[ruleID] = ruleYAML
	} else {
		delete(s.policy.sigmaRules, ruleID)
	}
}

func (s *Server) recordWhitelistKey(key string, present bool) {
	s.policy.mu.Lock()
	defer s.policy.mu.Unlock()
	if present {
		s.policy.whitelistKeys[key] = struct{}{}
	} else {
		delete(s.policy.whitelistKeys, key)
	}
}

func (s *Server) clearWhitelistKeys() {
	s.policy.mu.Lock()
	defer s.policy.mu.Unlock()
	s.policy.whitelistKeys = make(map[string]struct{})
}

func (s *Server) recordTaintSourceKey(key string, present bool) {
	s.policy.mu.Lock()
	defer s.policy.mu.Unlock()
	if present {
		s.policy.taintSourceKeys[key] = struct{}{}
	} else {
		delete(s.policy.taintSourceKeys, key)
	}
}

func clonePolicyRevision(revision PolicyRevision) PolicyRevision {
	revision.SigmaRuleIDs = append([]string(nil), revision.SigmaRuleIDs...)
	return revision
}

func sortedPolicyKeys(keys map[string]struct{}) []string {
	if len(keys) == 0 {
		return nil
	}
	out := make([]string, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func keysToSet(keys []string) map[string]struct{} {
	out := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key != "" {
			out[key] = struct{}{}
		}
	}
	return out
}

func normalizeEnrollmentStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "pending":
		return "pending"
	case "approve", "approved", "enroll", "enrolled", "active":
		return "approved"
	case "quarantine", "quarantined":
		return "quarantined"
	case "revoke", "revoked", "deny", "denied":
		return "revoked"
	default:
		return ""
	}
}

func dedupeTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(tags))
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		key := strings.ToLower(tag)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, tag)
	}
	return out
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if strings.EqualFold(tag, want) {
			return true
		}
	}
	return false
}

// mTLS

// loadTLSConfig loads TLS configuration with optional mutual auth.
func loadTLSConfig(cfg *ServerConfig) (*tls.Config, error) {
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		cert, err = generateSelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("load cert: %w", err)
		}
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if cfg.RequireClientCert {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			tlsCfg.ClientAuth = tls.RequireAnyClientCert
			log.Printf("[mgmt] mTLS: client cert required (no CA)")
		} else {
			caPool := x509.NewCertPool()
			caPool.AppendCertsFromPEM(caCert)
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
			tlsCfg.ClientCAs = caPool
			log.Printf("[mgmt] mTLS: client cert required with CA verification")
		}
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("client certificate required")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse client certificate: %w", err)
			}
			fingerprint := normalizeCertFingerprint(fingerprintCertificate(cert))
			for _, revoked := range cfg.RevokedClientCertFingerprints {
				if fingerprint != "" && fingerprint == normalizeCertFingerprint(revoked) {
					return fmt.Errorf("client certificate revoked: %s", fingerprint)
				}
			}
			if cfg.ClientCertRevoked != nil && cfg.ClientCertRevoked(cert) {
				return fmt.Errorf("client certificate revoked: %s", fingerprint)
			}
			return nil
		}
	}

	return tlsCfg, nil
}

// clientIdentity extracts the client identity from the gRPC context.
func clientIdentity(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			if len(tlsInfo.State.VerifiedChains) > 0 {
				cn := tlsInfo.State.VerifiedChains[0][0].Subject.CommonName
				return fmt.Sprintf("CN=%s", cn)
			}
		}
	}
	return "unknown"
}

// Self-signed certificate generator (development only)

func clientCertFingerprint(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			if len(tlsInfo.State.PeerCertificates) > 0 {
				return fingerprintCertificate(tlsInfo.State.PeerCertificates[0])
			}
		}
	}
	return ""
}

func fingerprintCertificate(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for index, item := range sum {
		parts[index] = fmt.Sprintf("%02X", item)
	}
	return strings.Join(parts, ":")
}

func normalizeCertFingerprint(value string) string {
	value = strings.TrimSpace(strings.ToUpper(value))
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "-", ":")
	if strings.Contains(value, ":") {
		parts := strings.Split(value, ":")
		normalized := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				normalized = append(normalized, part)
			}
		}
		return strings.Join(normalized, ":")
	}
	if len(value) == 64 {
		parts := make([]string, 0, 32)
		for index := 0; index < len(value); index += 2 {
			parts = append(parts, value[index:index+2])
		}
		return strings.Join(parts, ":")
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (s *Server) isClientCertRevoked(cert *x509.Certificate) bool {
	fingerprint := normalizeCertFingerprint(fingerprintCertificate(cert))
	if fingerprint == "" {
		return false
	}
	s.telemetry.mu.Lock()
	defer s.telemetry.mu.Unlock()
	for _, snapshot := range s.telemetry.Agents {
		if normalizeEnrollmentStatus(snapshot.EnrollmentStatus) == "revoked" &&
			normalizeCertFingerprint(snapshot.CertFingerprint) == fingerprint {
			return true
		}
	}
	return false
}

func generateSelfSignedCert() (tls.Certificate, error) {
	// Try persistent certauth (production use)
	certDir := filepath.Join(os.TempDir(), "providapt-certs")
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert dir: %w", err)
	}

	caDir := filepath.Join(certDir, "ca")
	srvDir := filepath.Join(certDir, "server")
	cliDir := filepath.Join(certDir, "client")

	cfg := &certauth.Config{
		CADir:      caDir,
		ServerDir:  srvDir,
		ClientDir:  cliDir,
		ValidYears: 10,
		KeyBits:    4096,
	}

	certFile, keyFile, _, err := certauth.Initialize(cfg)
	if err == nil {
		log.Printf("[mgmt] using certauth-generated certificates in %s", certDir)
		return tls.LoadX509KeyPair(certFile, keyFile)
	}

	// Fallback: ephemeral self-signed cert (dev only)
	log.Printf("[mgmt] certauth init failed (%v); generating ephemeral self-signed cert", err)
	return generateEphemeralCert()
}

// generateEphemeralCert creates an in-memory self-signed certificate for development use.
func generateEphemeralCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"ProvidAPT"},
			CommonName:   "providapt-dev",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

// Client (for management center)

// ClientConfig for connecting to the proviAPT management server.
type ClientConfig struct {
	ServerAddr string
	CertFile   string
	KeyFile    string
	CAFile     string
	ServerName string
}

// NewClient creates a mTLS-secured gRPC client connection.
func NewClient(cfg *ClientConfig) (*grpc.ClientConn, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if caData, err := os.ReadFile(cfg.CAFile); err == nil {
		caPool.AppendCertsFromPEM(caData)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   cfg.ServerName,
		MinVersion:   tls.VersionTLS12,
	}

	conn, err := grpc.Dial(cfg.ServerAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	return conn, nil
}
