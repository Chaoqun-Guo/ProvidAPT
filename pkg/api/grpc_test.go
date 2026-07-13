// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/mgmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

// ─── Test: NewGRPCServer ───────────────────────────────────────────────

func TestNewGRPCServer(t *testing.T) {
	g := provenance.NewGraph()
	srv := NewGRPCServer(":0", GRPCOptions{
		Graph:   g,
		Version: "test-1.0",
	})
	if srv == nil {
		t.Fatal("NewGRPCServer returned nil")
	}
	srv.Stop()
}

// ─── Helper: mock WatchAlerts stream ────────────────────────────────────

type mockWatchAlertsStream struct {
	ctx context.Context
}

func (m *mockWatchAlertsStream) Send(*pb.AlertEvent) error    { return nil }
func (m *mockWatchAlertsStream) Context() context.Context     { return m.ctx }
func (m *mockWatchAlertsStream) SetHeader(metadata.MD) error  { return nil }
func (m *mockWatchAlertsStream) SendHeader(metadata.MD) error { return nil }
func (m *mockWatchAlertsStream) SetTrailer(metadata.MD)       {}
func (m *mockWatchAlertsStream) SendMsg(interface{}) error    { return nil }
func (m *mockWatchAlertsStream) RecvMsg(interface{}) error    { return nil }

var _ grpc.ServerStream = (*mockWatchAlertsStream)(nil)

// ─── Tests: severityMatches ─────────────────────────────────────────────

func TestSeverityMatches(t *testing.T) {
	tests := []struct {
		name   string
		filter string
		actual string
		want   bool
	}{
		{"info=info", "info", "info", true},
		{"low=low", "low", "low", true},
		{"medium=medium", "medium", "medium", true},
		{"high=high", "high", "high", true},
		{"critical=critical", "critical", "critical", true},
		// Filter should match >= level
		{"info→critical", "info", "critical", true},
		{"info→medium", "info", "medium", true},
		{"low→high", "low", "high", true},
		{"medium→critical", "medium", "critical", true},
		// Filter should NOT match below level
		{"critical→info", "critical", "info", false},
		{"high→low", "high", "low", false},
		{"medium→info", "medium", "info", false},
		// Unknown levels (fallback to true)
		{"unknown filter", "bogus", "info", true},
		{"unknown actual", "info", "bogus", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := severityMatches(tt.filter, tt.actual)
			if got != tt.want {
				t.Errorf("severityMatches(%q, %q) = %v, want %v", tt.filter, tt.actual, got, tt.want)
			}
		})
	}
}

// ─── Tests: matchesQuery ────────────────────────────────────────────────

func TestMatchesQuery(t *testing.T) {
	n := &provenance.Node{
		ID:      "node-123",
		Label:   "bash",
		Subtype: "process",
	}
	tests := []struct {
		name    string
		keyword string
		want    bool
	}{
		{"exact ID", "node-123", true},
		{"exact label", "bash", true},
		{"substring ID (len>=3)", "node", true},
		{"substring label (len>=3)", "bas", true},
		{"subtype match", "process", true},
		{"short keyword (<3 chars)", "x", false},
		{"no match", "zzzzz", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesQuery(n, tt.keyword)
			if got != tt.want {
				t.Errorf("matchesQuery(%+v, %q) = %v, want %v", n, tt.keyword, got, tt.want)
			}
		})
	}
}

// ─── Tests: contains / indexOf ─────────────────────────────────────────

func TestContains(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		substr string
		want   bool
	}{
		{"exact", "hello", "hello", true},
		{"substring", "hello world", "world", true},
		{"empty s", "", "a", false},
		{"empty substr", "hello", "", false},
		{"both empty", "", "", true},
		{"substr longer", "ab", "abc", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contains(tt.s, tt.substr)
			if got != tt.want {
				t.Errorf("contains(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

func TestIndexOf(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		substr string
		want   int
	}{
		{"start", "hello", "he", 0},
		{"middle", "hello", "ll", 2},
		{"end", "hello", "lo", 3},
		{"not found", "hello", "xyz", -1},
		{"too long", "ab", "abc", -1},
		{"exact match", "hello", "hello", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := indexOf(tt.s, tt.substr)
			if got != tt.want {
				t.Errorf("indexOf(%q, %q) = %d, want %d", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

// ─── Tests: truncateNodes / truncateEdges ──────────────────────────────

func TestTruncateNodes(t *testing.T) {
	nodes := []*provenance.Node{
		{ID: "a", ProvType: "process", Subtype: "bash", Label: "bash"},
		{ID: "b", ProvType: "file", Subtype: "config", Label: "/etc/passwd"},
		{ID: "c", ProvType: "network", Subtype: "socket", Label: "1.2.3.4"},
	}
	tests := []struct {
		name string
		max  int
		nlen int
	}{
		{"fewer than max", 10, 3},
		{"exactly max", 3, 3},
		{"truncated", 2, 2},
		{"zero max", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateNodes(nodes, tt.max)
			if len(got) != tt.nlen {
				t.Errorf("truncateNodes(len=%d, max=%d) = len %d, want %d", len(nodes), tt.max, len(got), tt.nlen)
			}
		})
	}
}

func TestTruncateNodesNil(t *testing.T) {
	got := truncateNodes(nil, 10)
	if len(got) != 0 {
		t.Errorf("expected empty, got len %d", len(got))
	}
}

func TestTruncateEdges(t *testing.T) {
	edges := []*provenance.Edge{
		{Source: "a", Target: "b", Relation: "used", Count: 1},
		{Source: "b", Target: "c", Relation: "wasGeneratedBy", Count: 2},
	}
	tests := []struct {
		name string
		max  int
		elen int
	}{
		{"fewer than max", 10, 2},
		{"exactly max", 2, 2},
		{"truncated", 1, 1},
		{"zero max", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateEdges(edges, tt.max)
			if len(got) != tt.elen {
				t.Errorf("truncateEdges(len=%d, max=%d) = len %d, want %d", len(edges), tt.max, len(got), tt.elen)
			}
		})
	}
}

func TestTruncateEdgesNil(t *testing.T) {
	got := truncateEdges(nil, 10)
	if len(got) != 0 {
		t.Errorf("expected empty, got len %d", len(got))
	}
}

// ─── Tests: gRPC Query (direct server calls) ──────────────────────────

func TestQuery_WithGraph(t *testing.T) {
	g := provenance.NewGraph()
	svr := &provaptManagementServer{
		startedAt: time.Now(),
		graph:     g,
		version:   "test-1.0",
	}
	resp, err := svr.Query(context.Background(), &pb.QueryRequest{
		Query:      "anything",
		MaxResults: 100,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if resp.ResultCount < 0 {
		t.Errorf("expected non-negative result count, got %d", resp.ResultCount)
	}
	if resp.ResultsJson == "" {
		t.Error("expected non-empty ResultsJson")
	}
}

func TestQuery_NilGraph(t *testing.T) {
	svr := &provaptManagementServer{
		startedAt: time.Now(),
		graph:     nil,
		version:   "test-1.0",
	}
	resp, err := svr.Query(context.Background(), &pb.QueryRequest{Query: "x"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if resp.ResultCount != 0 {
		t.Errorf("expected 0 for nil graph, got %d", resp.ResultCount)
	}
}

func TestQuery_ContainerFilter(t *testing.T) {
	g := provenance.NewGraph()
	svr := &provaptManagementServer{
		startedAt: time.Now(),
		graph:     g,
		version:   "test-1.0",
	}
	resp, err := svr.Query(context.Background(), &pb.QueryRequest{
		Container: "nonexistent",
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if resp.ResultCount != 0 {
		t.Errorf("expected 0 for no-match container, got %d", resp.ResultCount)
	}
}

// ─── Tests: gRPC Check ────────────────────────────────────────────────

func TestCheck_GraphOnlyDegraded(t *testing.T) {
	// Graph present but nil pipeline → DEGRADED
	g := provenance.NewGraph()
	svr := &provaptManagementServer{
		startedAt: time.Now(),
		graph:     g,
		pipeline:  nil,
		version:   "1.2.2",
	}
	resp, err := svr.Check(context.Background(), &pb.HealthCheck{})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !resp.AgentRunning {
		t.Error("expected AgentRunning=true")
	}
	if resp.Version != "1.2.2" {
		t.Errorf("got Version=%q, want %q", resp.Version, "1.2.2")
	}
	// Pipeline is nil, so status is DEGRADED
	if resp.Status != "DEGRADED" {
		t.Errorf("got Status=%q, want DEGRADED", resp.Status)
	}
}

func TestCheck_Degraded(t *testing.T) {
	svr := &provaptManagementServer{
		startedAt: time.Now(),
		graph:     nil,
		pipeline:  nil,
		version:   "1.2.2",
	}
	resp, err := svr.Check(context.Background(), &pb.HealthCheck{})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.Status != "DEGRADED" {
		t.Errorf("got Status=%q, want DEGRADED", resp.Status)
	}
}

// ─── Tests: UpdatePolicy ───────────────────────────────────────────────

func TestUpdatePolicy_AllBranches(t *testing.T) {
	svr := &provaptManagementServer{
		startedAt: time.Now(),
		version:   "test-1.0",
	}
	tests := []struct {
		name   string
		update *pb.PolicyUpdate
	}{
		{"whitelist", &pb.PolicyUpdate{
			Update: &pb.PolicyUpdate_Whitelist{
				Whitelist: &pb.WhitelistUpdate{Action: "add", Target: "comm", Value: "bash"},
			},
		}},
		{"sigma", &pb.PolicyUpdate{
			Update: &pb.PolicyUpdate_Sigma{
				Sigma: &pb.SigmaRule{Action: "add", RuleId: "SIGMA-001", RuleYaml: "detect: mimikatz"},
			},
		}},
		{"taint source", &pb.PolicyUpdate{
			Update: &pb.PolicyUpdate_TaintSource{
				TaintSource: &pb.TaintSource{Action: "add", IpPrefix: "10.0.0.0/8", Label: "internal"},
			},
		}},
		{"threshold", &pb.PolicyUpdate{
			Update: &pb.PolicyUpdate_Threshold{
				Threshold: &pb.RuleThreshold{RuleId: "RULE-01", Score: 75.0},
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svr.UpdatePolicy(context.Background(), tt.update)
			if err != nil {
				t.Fatalf("UpdatePolicy: %v", err)
			}
			if !resp.Success {
				t.Error("expected resp.Success=true")
			}
		})
	}
}

// ─── Tests: WatchAlerts ─────────────────────────────────────────────────

func TestWatchAlerts_NilAlertPipeline(t *testing.T) {
	svr := &provaptManagementServer{
		startedAt: time.Now(),
		version:   "test-1.0",
	}
	stream := &mockWatchAlertsStream{ctx: context.Background()}
	err := svr.WatchAlerts(&pb.AlertFilter{MinSeverity: "info"}, stream)
	if err != nil {
		t.Errorf("WatchAlerts with nil pipeline: %v", err)
	}
}

// ─── Tests: ReportEvents ────────────────────────────────────────────────

type mockReportEventsStream struct {
	ctx    context.Context
	events []*pb.CompressedEvent
	index  int
	ack    *pb.ReportAck
}

func (m *mockReportEventsStream) SendAndClose(ack *pb.ReportAck) error {
	m.ack = ack
	return nil
}

func (m *mockReportEventsStream) Recv() (*pb.CompressedEvent, error) {
	if m.index >= len(m.events) {
		return nil, io.EOF
	}
	evt := m.events[m.index]
	m.index++
	return evt, nil
}

func (m *mockReportEventsStream) Context() context.Context     { return m.ctx }
func (m *mockReportEventsStream) SetHeader(metadata.MD) error  { return nil }
func (m *mockReportEventsStream) SendHeader(metadata.MD) error { return nil }
func (m *mockReportEventsStream) SetTrailer(metadata.MD)       {}
func (m *mockReportEventsStream) SendMsg(interface{}) error    { return nil }
func (m *mockReportEventsStream) RecvMsg(interface{}) error    { return nil }

var _ pb.ProvidAPTTelemetry_ReportEventsServer = (*mockReportEventsStream)(nil)
var _ grpc.ServerStream = (*mockReportEventsStream)(nil)

func TestReportEvents_NoEventCh(t *testing.T) {
	svr := &provaptTelemetryServer{eventCh: nil}
	stream := &mockReportEventsStream{
		ctx: context.Background(),
		events: []*pb.CompressedEvent{
			{ContentType: "raw", Payload: []byte{0, 1, 2, 3}},
		},
	}
	err := svr.ReportEvents(stream)
	if err != nil {
		t.Fatalf("ReportEvents: %v", err)
	}
	if stream.ack == nil {
		t.Fatal("expected ack")
	}
	if !stream.ack.Accepted {
		t.Error("expected ack.Accepted=true")
	}
}

func TestReportEvents_UnknownContentType(t *testing.T) {
	svr := &provaptTelemetryServer{eventCh: nil}
	stream := &mockReportEventsStream{
		ctx: context.Background(),
		events: []*pb.CompressedEvent{
			{ContentType: "protobuf", Payload: []byte("data")},
		},
	}
	err := svr.ReportEvents(stream)
	if err != nil {
		t.Fatalf("ReportEvents: %v", err)
	}
	if stream.ack == nil {
		t.Fatal("expected ack")
	}
	if stream.ack.Accepted {
		t.Error("expected ack.Accepted=false (dropped unknown content type)")
	}
}

// ─── Tests: bufconn-based gRPC server start/stop ────────────────────────

func TestReportEvents_PersistsSummaryTelemetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telemetry.ndjson")
	svr := &provaptTelemetryServer{telemetryPath: path}
	stream := &mockReportEventsStream{
		ctx: context.Background(),
		events: []*pb.CompressedEvent{
			{ContentType: "summary", Payload: []byte(`{"agent_id":"agent-01"}`), OriginalSize: 23, TimestampNs: 123},
		},
	}
	if err := svr.ReportEvents(stream); err != nil {
		t.Fatalf("ReportEvents: %v", err)
	}
	if stream.ack == nil || !stream.ack.Accepted {
		t.Fatalf("ack = %#v", stream.ack)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read telemetry sink: %v", err)
	}
	if !strings.Contains(string(data), `"content_type":"summary"`) || !strings.Contains(string(data), `"payload_base64"`) {
		t.Fatalf("unexpected telemetry sink: %s", data)
	}
}

func TestGRPCServerStartStop(t *testing.T) {
	g := provenance.NewGraph()
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	registerGRPCServices(srv, GRPCOptions{Graph: g, Version: "test"})
	go srv.Serve(lis)
	srv.Stop()
	// Success if no panic or deadlock
}
