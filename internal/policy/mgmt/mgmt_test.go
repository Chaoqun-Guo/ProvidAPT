// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mgmt

import (
	"context"
	"io"
	"testing"
	"time"

	mgmtpb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/mgmt"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/analyzer"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// mockWatchAlertsStream implements mgmtpb.ProvidAPTManagement_WatchAlertsServer.
type mockWatchAlertsStream struct {
	ctx context.Context
}

func (m *mockWatchAlertsStream) Send(*mgmtpb.AlertEvent) error { return nil }
func (m *mockWatchAlertsStream) Context() context.Context      { return m.ctx }
func (m *mockWatchAlertsStream) SetHeader(metadata.MD) error   { return nil }
func (m *mockWatchAlertsStream) SendHeader(metadata.MD) error  { return nil }
func (m *mockWatchAlertsStream) SetTrailer(metadata.MD)        {}
func (m *mockWatchAlertsStream) SendMsg(interface{}) error     { return nil }
func (m *mockWatchAlertsStream) RecvMsg(interface{}) error     { return nil }

type mockReportEventsStream struct {
	ctx    context.Context
	events []*mgmtpb.CompressedEvent
	index  int
	ack    *mgmtpb.ReportAck
}

func (m *mockReportEventsStream) SendAndClose(ack *mgmtpb.ReportAck) error {
	m.ack = ack
	return nil
}

func (m *mockReportEventsStream) Recv() (*mgmtpb.CompressedEvent, error) {
	if m.index >= len(m.events) {
		return nil, io.EOF
	}
	event := m.events[m.index]
	m.index++
	return event, nil
}

func (m *mockReportEventsStream) Context() context.Context     { return m.ctx }
func (m *mockReportEventsStream) SetHeader(metadata.MD) error  { return nil }
func (m *mockReportEventsStream) SendHeader(metadata.MD) error { return nil }
func (m *mockReportEventsStream) SetTrailer(metadata.MD)       {}
func (m *mockReportEventsStream) SendMsg(interface{}) error    { return nil }
func (m *mockReportEventsStream) RecvMsg(interface{}) error    { return nil }

var _ mgmtpb.ProvidAPTTelemetry_ReportEventsServer = (*mockReportEventsStream)(nil)
var _ grpc.ServerStream = (*mockReportEventsStream)(nil)

// ─── Server tests ───────────────────────────────────────────

func TestDefaultServerConfig(t *testing.T) {
	cfg := DefaultServerConfig()
	if cfg.ListenAddr != ":50051" {
		t.Errorf("addr = %s", cfg.ListenAddr)
	}
	if !cfg.RequireClientCert {
		t.Error("should require client cert")
	}
	if !cfg.EnableTLS {
		t.Error("should enable TLS")
	}
}

func TestNewServer(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.EnableTLS = false // disable for test
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
}

func TestServerStartStop(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ListenAddr = ":0"
	cfg.EnableTLS = false
	s, _ := NewServer(cfg)
	err := s.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	s.Stop()
}

func TestQuery(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.EnableTLS = false
	s, _ := NewServer(cfg)

	req := &mgmtpb.QueryRequest{
		Query:      "MATCH (p:Process)-[:READ]->(f:File) RETURN p",
		MaxResults: 100,
	}
	resp, err := s.Query(context.Background(), req)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if resp == nil {
		t.Fatal("nil response")
	}
	if resp.ResultCount != 0 {
		t.Errorf("count = %d", resp.ResultCount)
	}
}

func TestUpdatePolicyWhitelist(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.EnableTLS = false
	s, _ := NewServer(cfg)

	update := &mgmtpb.PolicyUpdate{
		Update: &mgmtpb.PolicyUpdate_Whitelist{
			Whitelist: &mgmtpb.WhitelistUpdate{
				Action: "add", Target: "pid", Value: "1234",
			},
		},
	}
	ack, err := s.UpdatePolicy(context.Background(), update)
	if err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}
	if !ack.Success {
		t.Errorf("ack success = %v", ack.Success)
	}
}

func TestUpdatePolicySigma(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.EnableTLS = false
	s, _ := NewServer(cfg)

	// Attach an analyzer for the sigma rule to be applied
	g := provenance.NewGraph()
	anz := analyzer.New(g, nil)
	s.SetAnalyzer(anz)

	update := &mgmtpb.PolicyUpdate{
		Update: &mgmtpb.PolicyUpdate_Sigma{
			Sigma: &mgmtpb.SigmaRule{
				Action: "add", RuleId: "rule-001",
				RuleYaml: "title: Test Rule\ndetection:\n  selection:\n    EventType: \"10\"\n  condition: selection",
			},
		},
	}
	ack, _ := s.UpdatePolicy(context.Background(), update)
	if !ack.Success {
		t.Errorf("sigma update failed: %s", ack.Message)
	}
	if ack.Message != "sigma rule rule-001 applied" {
		t.Errorf("ack message = %q, want %q", ack.Message, "sigma rule rule-001 applied")
	}
}

func TestUpdatePolicyTaintSource(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.EnableTLS = false
	s, _ := NewServer(cfg)

	update := &mgmtpb.PolicyUpdate{
		Update: &mgmtpb.PolicyUpdate_TaintSource{
			TaintSource: &mgmtpb.TaintSource{
				Action: "add", IpPrefix: "5.6.7.8", Label: "C2_server",
			},
		},
	}
	ack, _ := s.UpdatePolicy(context.Background(), update)
	if !ack.Success {
		t.Errorf("taint update failed: %s", ack.Message)
	}
}

func TestHealthCheck(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.EnableTLS = false
	s, _ := NewServer(cfg)

	status, err := s.Check(context.Background(), &mgmtpb.HealthCheck{RequestingAgent: "test"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !status.AgentRunning {
		t.Error("agent should be running")
	}
	if status.Version == "" {
		t.Error("version should not be empty")
	}
	if status.Status != "HEALTHY" {
		t.Errorf("status = %s", status.Status)
	}
}

func TestHealthCheckUptime(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.EnableTLS = false
	s, _ := NewServer(cfg)

	time.Sleep(10 * time.Millisecond)
	status, _ := s.Check(context.Background(), &mgmtpb.HealthCheck{})
	if status.UptimeNs <= 0 {
		t.Error("uptime should be > 0")
	}
}

func TestWatchAlerts(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.EnableTLS = false
	s, _ := NewServer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err := s.WatchAlerts(&mgmtpb.AlertFilter{MinSeverity: "HIGH"}, &mockWatchAlertsStream{ctx: ctx})
	if err != nil {
		t.Fatalf("WatchAlerts: %v", err)
	}
}

func TestReportEventsSummary(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.EnableTLS = false
	s, _ := NewServer(cfg)

	stream := &mockReportEventsStream{
		ctx: context.Background(),
		events: []*mgmtpb.CompressedEvent{
			{
				ContentType: "summary",
				Payload:     []byte(`{"agent_id":"agent-01"}`),
			},
		},
	}

	if err := s.ReportEvents(stream); err != nil {
		t.Fatalf("ReportEvents: %v", err)
	}
	if stream.ack == nil || !stream.ack.Accepted {
		t.Fatal("expected accepted telemetry ack")
	}
	if s.telemetry.Reports != 1 {
		t.Fatalf("reports = %d, want 1", s.telemetry.Reports)
	}
	if s.telemetry.LastContentType != "summary" {
		t.Fatalf("last content type = %q", s.telemetry.LastContentType)
	}
	if s.telemetry.LastAgentID != "agent-01" {
		t.Fatalf("last agent id = %q", s.telemetry.LastAgentID)
	}
	overview := s.TelemetryOverview()
	if len(overview) != 1 {
		t.Fatalf("overview len = %d, want 1", len(overview))
	}
	if overview[0].AgentID != "agent-01" {
		t.Fatalf("overview agent id = %q", overview[0].AgentID)
	}
}

func TestFleetMetadata(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.EnableTLS = false
	s, _ := NewServer(cfg)

	s.UpsertAgentMetadata("agent-01", "prod", []string{"linux", "db", "linux"})
	all := s.FleetSnapshot(FleetFilter{})
	if len(all) != 1 {
		t.Fatalf("fleet size = %d, want 1", len(all))
	}
	if all[0].Group != "prod" {
		t.Fatalf("group = %q", all[0].Group)
	}
	if len(all[0].Tags) != 2 {
		t.Fatalf("tags = %#v", all[0].Tags)
	}

	filtered := s.FleetSnapshot(FleetFilter{Group: "prod", Tag: "linux"})
	if len(filtered) != 1 {
		t.Fatalf("filtered size = %d, want 1", len(filtered))
	}
	miss := s.FleetSnapshot(FleetFilter{Group: "dev"})
	if len(miss) != 0 {
		t.Fatalf("miss size = %d, want 0", len(miss))
	}
}

func TestPolicyCenterPublishRollback(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.EnableTLS = false
	s, _ := NewServer(cfg)

	g := provenance.NewGraph()
	anz := analyzer.New(g, nil)
	s.SetAnalyzer(anz)

	update := &mgmtpb.PolicyUpdate{
		Update: &mgmtpb.PolicyUpdate_Sigma{
			Sigma: &mgmtpb.SigmaRule{
				Action:   "add",
				RuleId:   "rule-001",
				RuleYaml: "title: Test Rule\ndetection:\n  selection:\n    EventType: \"10\"\n  condition: selection",
			},
		},
	}
	ack, err := s.UpdatePolicy(context.Background(), update)
	if err != nil || !ack.Success {
		t.Fatalf("UpdatePolicy: ack=%#v err=%v", ack, err)
	}

	center := s.PolicyCenter()
	if center.Draft.ActiveRules == 0 {
		t.Fatalf("draft active rules = %d", center.Draft.ActiveRules)
	}

	published := s.PublishPolicy("release candidate")
	if published.Version != 2 {
		t.Fatalf("published version = %d, want 2", published.Version)
	}
	if published.State != "published" {
		t.Fatalf("published state = %q", published.State)
	}

	rolled, err := s.RollbackPolicy(1, "rollback")
	if err != nil {
		t.Fatalf("RollbackPolicy: %v", err)
	}
	if rolled.Version != 3 {
		t.Fatalf("rolled version = %d, want 3", rolled.Version)
	}
	if rolled.State != "rolled_back" {
		t.Fatalf("rolled state = %q", rolled.State)
	}
}

func TestReportEventsEmptyStream(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.EnableTLS = false
	s, _ := NewServer(cfg)

	stream := &mockReportEventsStream{
		ctx:    context.Background(),
		events: nil,
	}

	if err := s.ReportEvents(stream); err != nil {
		t.Fatalf("ReportEvents: %v", err)
	}
	if stream.ack == nil || !stream.ack.Accepted {
		t.Fatal("expected accepted empty telemetry ack")
	}
	if stream.ack.Message != "no events received" {
		t.Fatalf("ack message = %q", stream.ack.Message)
	}
}

// ─── mTLS tests ─────────────────────────────────────────────

func TestClientIdentityUnknown(t *testing.T) {
	ctx := context.Background()
	id := clientIdentity(ctx)
	if id != "unknown" {
		t.Errorf("identity = %s", id)
	}
}

func TestLoadTLSConfigNoCert(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.CertFile = "/nonexistent/cert.pem"
	cfg.KeyFile = "/nonexistent/key.pem"

	// Without valid certs, should fall back to self-signed (which will error)
	_, err := loadTLSConfig(cfg)
	if err == nil {
		t.Log("loadTLSConfig: fallback path (expected to try self-signed)")
	} else {
		t.Logf("loadTLSConfig: %v (expected without cert files)", err)
	}
}

func TestNewClientNoCerts(t *testing.T) {
	cfg := &ClientConfig{
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
		CAFile:   "/nonexistent/ca.pem",
	}
	_, err := NewClient(cfg)
	if err == nil {
		t.Error("expected error without certs")
	} else {
		t.Logf("NewClient: %v (expected)", err)
	}
}

// ─── Policy update type tests ───────────────────────────────

func TestWhitelistUpdate(t *testing.T) {
	w := &mgmtpb.WhitelistUpdate{Action: "add", Target: "comm", Value: "curl"}
	if w.Action != "add" {
		t.Errorf("action = %s", w.Action)
	}
	if w.Target != "comm" {
		t.Errorf("target = %s", w.Target)
	}
}

func TestSigmaRule(t *testing.T) {
	r := &mgmtpb.SigmaRule{Action: "add", RuleId: "test-rule", RuleYaml: "title: test"}
	if r.RuleId != "test-rule" {
		t.Errorf("id = %s", r.RuleId)
	}
}

func TestTaintSource(t *testing.T) {
	ts := &mgmtpb.TaintSource{Action: "add", IpPrefix: "10.0.0.0/8", Label: "internal"}
	if ts.IpPrefix != "10.0.0.0/8" {
		t.Errorf("prefix = %s", ts.IpPrefix)
	}
}

// ─── Integration test ───────────────────────────────────────

func TestMgmtIntegration(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ListenAddr = ":0"
	cfg.EnableTLS = false
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	err = s.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()

	// 1. Health check
	health, _ := s.Check(context.Background(), &mgmtpb.HealthCheck{})
	t.Logf("Health: version=%s status=%s uptime=%d",
		health.Version, health.Status, health.UptimeNs)

	// 2. Query
	qResp, _ := s.Query(context.Background(), &mgmtpb.QueryRequest{
		Query:      "MATCH (p:Process)-[:READ]->(f:File) RETURN p",
		MaxResults: 50,
	})
	t.Logf("Query: %d results", qResp.ResultCount)

	// 3. Policy update — whitelist
	wlAck, _ := s.UpdatePolicy(context.Background(), &mgmtpb.PolicyUpdate{
		Update: &mgmtpb.PolicyUpdate_Whitelist{
			Whitelist: &mgmtpb.WhitelistUpdate{
				Action: "add", Target: "pid", Value: "1234",
			},
		},
	})
	t.Logf("Whitelist update: success=%v msg=%s", wlAck.Success, wlAck.Message)

	// 4. Policy update — sigma rule
	sigmaAck, _ := s.UpdatePolicy(context.Background(), &mgmtpb.PolicyUpdate{
		Update: &mgmtpb.PolicyUpdate_Sigma{
			Sigma: &mgmtpb.SigmaRule{
				Action: "add", RuleId: "rule-webshell",
				RuleYaml: "title: Web Shell\ndetection:\n  selection:\n    Comm: \"bash\"\n  condition: selection",
			},
		},
	})
	t.Logf("Sigma update: success=%v", sigmaAck.Success)

	// 5. Policy update — taint source
	taintAck, _ := s.UpdatePolicy(context.Background(), &mgmtpb.PolicyUpdate{
		Update: &mgmtpb.PolicyUpdate_TaintSource{
			TaintSource: &mgmtpb.TaintSource{
				Action: "add", IpPrefix: "5.6.7.8", Label: "C2",
			},
		},
	})
	t.Logf("Taint update: success=%v", taintAck.Success)

	t.Log("Management integration OK")
}
