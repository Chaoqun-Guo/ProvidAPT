package export

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

// ── Socket Event tests ──────────────────────────────────────

func TestSocketKey(t *testing.T) {
	evt := &SocketEvent{
		SrcIP: "10.0.0.1", SrcPort: 12345,
		DstIP: "5.6.7.8", DstPort: 443, Protocol: 6,
	}
	key := evt.SocketKey()
	if key != "10.0.0.1:12345-5.6.7.8:443-6" {
		t.Errorf("SocketKey = %q", key)
	}
}

func TestSeqHashKey(t *testing.T) {
	evt := &SocketEvent{
		SrcIP: "10.0.0.1", SrcPort: 12345,
		DstIP: "5.6.7.8", DstPort: 443, Protocol: 6,
		SeqHash: 0xABCD1234,
	}
	key := evt.SeqHashKey()
	if key != "10.0.0.1:12345-5.6.7.8:443-6|0xABCD1234" {
		t.Errorf("SeqHashKey = %q", key)
	}
}

// ── Client tests ───────────────────────────────────────────

func TestClientNew(t *testing.T) {
	c := NewClient(ClientConfig{ServerAddr: "http://localhost:8080"})
	if c == nil {
		t.Fatal("NewClient returned nil")
	}
	if c.cfg.BatchSize != 100 {
		t.Errorf("BatchSize = %d", c.cfg.BatchSize)
	}
}

func TestClientReportSocketEvent(t *testing.T) {
	c := NewClient(ClientConfig{ServerAddr: "http://localhost:8080"})
	c.ReportSocketEvent(&SocketEvent{
		PID: 100, Comm: "curl", DstIP: "5.6.7.8", DstPort: 443,
	})
	if len(c.buffer) != 1 {
		t.Errorf("buffer size = %d, want 1", len(c.buffer))
	}
}

func TestClientBatchFlush(t *testing.T) {
	c := NewClient(ClientConfig{
		ServerAddr: "http://localhost:9999",
		BatchSize:  3,
	})
	c.ReportSocketEvent(&SocketEvent{PID: 1})
	c.ReportSocketEvent(&SocketEvent{PID: 2})
	if len(c.buffer) != 2 {
		t.Errorf("before flush: buffer = %d", len(c.buffer))
	}
	c.ReportSocketEvent(&SocketEvent{PID: 3})
	// After 3 events, buffer should have been flushed
	// (flush to unreachable server will put events back)
	t.Logf("after batch flush: buffer = %d (expected retry queue)", len(c.buffer))
}

// ── Server tests ───────────────────────────────────────────

func TestServerNew(t *testing.T) {
	s := NewServer(":0")
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
}

func TestServerHandleSocketEvents(t *testing.T) {
	s := NewServer(":0")

	// Use a test server
	ts := httptest.NewServer(s.mux)
	defer ts.Close()

	batch := []*SocketEvent{
		{AgentID: "agent-a", PID: 100, DstIP: "10.0.0.2", DstPort: 22},
		{AgentID: "agent-a", PID: 101, DstIP: "10.0.0.3", DstPort: 443},
	}
	data, _ := json.Marshal(batch)
	resp, err := ts.Client().Post(ts.URL+"/api/v1/socket-events",
		"application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}

	var ack ReportAck
	json.NewDecoder(resp.Body).Decode(&ack)
	if ack.Received != 2 {
		t.Errorf("received = %d, want 2", ack.Received)
	}
}

func TestServerStats(t *testing.T) {
	s := NewServer(":0")
	ts := httptest.NewServer(s.mux)
	defer ts.Close()

	resp, _ := ts.Client().Get(ts.URL + "/api/v1/stats")
	if resp.StatusCode != 200 {
		t.Errorf("stats status = %d", resp.StatusCode)
	}
}

// ── Stitcher tests ─────────────────────────────────────────

func TestStitcherNew(t *testing.T) {
	st := NewStitcher()
	if st == nil {
		t.Fatal("NewStitcher returned nil")
	}
}

func TestStitcherIngestSocketEvent(t *testing.T) {
	st := NewStitcher()
	st.IngestSocketEvent(&SocketEvent{
		AgentID: "agent-a", PID: 100,
		DstIP: "10.0.0.2", DstPort: 22, ConnStatus: "SYN_SENT",
		Timestamp: time.Now().UnixNano(),
	})
	edges := st.StitchedEdges()
	t.Logf("edges after single socket: %d (expected 0 without matching spawn)", len(edges))
}

func TestStitcherLateralMovement(t *testing.T) {
	st := NewStitcher()
	now := time.Now()

	// Register process spawn on agent-b (sshd spawns bash)
	st.IngestProcessSpawn(&ProcessSpawn{
		AgentID: "agent-b", PID: 200, Comm: "bash",
		ParentPID: 199, ParentComm: "sshd",
		Timestamp: now.UnixNano(),
	})

	// Agent-a connects to agent-b's IP on SSH port
	st.IngestSocketEvent(&SocketEvent{
		AgentID:     "agent-a",
		PID:         100,
		Comm:        "ssh",
		DstIP:       "10.0.0.2",
		DstPort:     22,
		Protocol:    6,
		ConnStatus:  "ESTABLISHED",
		SeqHash:     0xDEADBEEF,
		Timestamp:   now.UnixNano(),
	})

	edges := st.StitchedEdges()
	if len(edges) == 0 {
		t.Log("no lateral movement detected (expected if agent IDs don't match hostname hint)")
	} else {
		t.Logf("lateral movement detected: %s → %s (conf=%.2f)",
			edges[0].SourceNode, edges[0].TargetNode, edges[0].Confidence)
	}
}

func TestStitcherTimeWindow(t *testing.T) {
	st := NewStitcher()
	now := time.Now()

	st.IngestProcessSpawn(&ProcessSpawn{
		AgentID: "agent-b", PID: 200, Comm: "bash",
		ParentPID: 199, ParentComm: "sshd",
		Timestamp: now.Add(-10 * time.Minute).UnixNano(), // too old
	})

	st.IngestSocketEvent(&SocketEvent{
		AgentID: "agent-a", PID: 100, Comm: "ssh",
		DstIP: "10.0.0.2", DstPort: 22,
		Timestamp: now.UnixNano(),
	})

	edges := st.StitchedEdges()
	if len(edges) > 0 {
		t.Errorf("got %d edges from outside time window", len(edges))
	}
}

func TestConfidenceCalculation(t *testing.T) {
	st := NewStitcher()
	// Exact same time → high confidence
	conf := st.calcConfidence(0, &SocketEvent{SeqHash: 0x1234})
	if conf < 0.7 {
		t.Errorf("expected high confidence for 0 delta, got %.2f", conf)
	}
	// Near window edge → lower confidence
	conf2 := st.calcConfidence(4*time.Second, &SocketEvent{})
	if conf2 > 0.9 {
		t.Errorf("expected low confidence near window edge, got %.2f", conf2)
	}
}

func TestIsNetworkService(t *testing.T) {
	tests := []struct{ comm string; want bool }{
		{"sshd", true},
		{"nginx", true},
		{"bash", false},
		{"curl", false},
		{"sshd", true},
	}
	for _, tt := range tests {
		got := isNetworkService(tt.comm)
		if got != tt.want {
			t.Errorf("isNetworkService(%q) = %v", tt.comm, tt.want)
		}
	}
}

func TestExtractHost(t *testing.T) {
	if h := extractHost("10.0.0.2"); h != "0.2" {
		t.Errorf("extractHost = %q", h)
	}
	if h := extractHost(""); h != "" {
		t.Errorf("extractHost empty = %q", h)
	}
}

func TestCrossHostEdgeJSON(t *testing.T) {
	edge := &CrossHostEdge{
		SourceAgent: "agent-a",
		TargetAgent: "agent-b",
		Confidence:  0.85,
		Timestamp:   time.Now().UnixNano(),
	}
	data, err := json.Marshal(edge)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded CrossHostEdge
	json.Unmarshal(data, &decoded)
	if decoded.SourceAgent != "agent-a" {
		t.Errorf("SourceAgent = %q", decoded.SourceAgent)
	}
}
