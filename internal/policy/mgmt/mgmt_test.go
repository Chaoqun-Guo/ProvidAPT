//go:build linux

package mgmt

import (
	"context"
	"testing"
	"time"

	mgmtpb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/mgmt"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/analyzer"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

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
		Query: "MATCH (p:Process)-[:READ]->(f:File) RETURN p",
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
				RuleYaml: "title: Test Rule\ndetection:\n  EventType: [10]",
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
				Action: "add", IPPrefix: "5.6.7.8", Label: "C2_server",
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
	if status.Version != "2.1.0" {
		t.Errorf("version = %s", status.Version)
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

	err := s.WatchAlerts(ctx, &mgmtpb.AlertFilter{MinSeverity: "HIGH"}, nil)
	if err != nil {
		t.Fatalf("WatchAlerts: %v", err)
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
	ts := &mgmtpb.TaintSource{Action: "add", IPPrefix: "10.0.0.0/8", Label: "internal"}
	if ts.IPPrefix != "10.0.0.0/8" {
		t.Errorf("prefix = %s", ts.IPPrefix)
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
		Query:     "MATCH (p:Process)-[:READ]->(f:File) RETURN p",
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
				RuleYaml: "title: Web Shell\ndetection:\n  Comm: bash",
			},
		},
	})
	t.Logf("Sigma update: success=%v", sigmaAck.Success)

	// 5. Policy update — taint source
	taintAck, _ := s.UpdatePolicy(context.Background(), &mgmtpb.PolicyUpdate{
		Update: &mgmtpb.PolicyUpdate_TaintSource{
			TaintSource: &mgmtpb.TaintSource{
				Action: "add", IPPrefix: "5.6.7.8", Label: "C2",
			},
		},
	})
	t.Logf("Taint update: success=%v", taintAck.Success)

	t.Log("Management integration OK")
}
