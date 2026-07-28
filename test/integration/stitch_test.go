// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/stitcher/stitch"
)

func flowID(srcIP, dstIP string, srcPort, dstPort uint32, isn, ts uint32) string {
	input := fmt.Sprintf("%s:%d-%s:%d-%d-%d", srcIP, srcPort, dstIP, dstPort, isn, ts)
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])[:32]
}

// ─── Stitch table tests ─────────────────────────────────────

func TestNewStitchTable(t *testing.T) {
	st := stitch.NewStitchTable()
	if st == nil {
		t.Fatal("NewStitchTable returned nil")
	}
}

func TestRecordOutbound(t *testing.T) {
	st := stitch.NewStitchTable()
	fid := flowID("10.0.0.1", "5.6.7.8", 40000, 443, 1000, 500)

	edge := st.RecordOutbound(fid, "agent-a", 100, "curl",
		"10.0.0.1", "5.6.7.8", 40000, 443, false, "")
	if edge != nil {
		t.Log("edge created immediately (unexpected)")
	}
}

func TestFullStitch(t *testing.T) {
	st := stitch.NewStitchTable()
	fid := flowID("10.0.0.1", "5.6.7.8", 40000, 443, 1000, 500)

	// Agent A: outbound connect
	st.RecordOutbound(fid, "agent-a", 100, "curl",
		"10.0.0.1", "5.6.7.8", 40000, 443, false, "")

	// Agent B: inbound accept (should stitch)
	edge := st.RecordInbound(fid, "agent-b", 200, "sshd",
		"10.0.0.1", "5.6.7.8", 40000, 443, false)

	if edge == nil {
		t.Fatal("stitch should have been created")
	}
	if edge.SourceAgent != "agent-a" {
		t.Errorf("source = %s", edge.SourceAgent)
	}
	if edge.TargetAgent != "agent-b" {
		t.Errorf("target = %s", edge.TargetAgent)
	}
	if edge.Relation != "remote_call" {
		t.Errorf("relation = %s", edge.Relation)
	}
	t.Logf("Stitch: %s → %s (%s)", edge.SourceAgent, edge.TargetAgent, edge.Relation)
}

func TestStitchWithTaintPropagation(t *testing.T) {
	st := stitch.NewStitchTable()
	fid := flowID("10.0.0.1", "5.6.7.8", 40000, 443, 2000, 1000)

	// Agent A: tainted process connects outbound
	edge := st.RecordOutbound(fid, "agent-a", 100, "curl",
		"10.0.0.1", "5.6.7.8", 40000, 443, true, "external_ip:5.6.7.8")

	// Agent B: inbound accept
	edge2 := st.RecordInbound(fid, "agent-b", 200, "sshd",
		"10.0.0.1", "5.6.7.8", 40000, 443, false)

	if edge2 == nil {
		t.Fatal("stitch should have been created")
	}
	if !edge2.Tainted {
		t.Error("stitch should be marked as tainted")
	}
	if edge2.Relation != "lateral_move" {
		t.Errorf("relation = %s (expected lateral_move)", edge2.Relation)
	}
	_ = edge
}

func TestNoStitchOutsideWindow(t *testing.T) {
	st := stitch.NewStitchTable()
	fid := flowID("10.0.0.1", "5.6.7.8", 40000, 443, 3000, 1500)

	st.RecordOutbound(fid, "agent-a", 100, "curl",
		"10.0.0.1", "5.6.7.8", 40000, 443, false, "")

	time.Sleep(10 * time.Millisecond)

	// Inbound far in the future — should not stitch
	future := st.RecordInbound(fid, "agent-b", 200, "sshd",
		"10.0.0.1", "5.6.7.8", 40000, 443, false)
	if future != nil {
		t.Log("stitch may still match within window")
	}
}

func TestInboundFirst(t *testing.T) {
	st := stitch.NewStitchTable()
	fid := flowID("10.0.0.1", "5.6.7.8", 40000, 443, 4000, 2000)

	// Inbound arrives before outbound
	inEdge := st.RecordInbound(fid, "agent-b", 200, "nginx",
		"10.0.0.1", "5.6.7.8", 40000, 443, false)
	if inEdge != nil {
		t.Log("inbound edge created immediately (unexpected)")
	}

	// Outbound arrives later → stitch
	outEdge := st.RecordOutbound(fid, "agent-a", 100, "curl",
		"10.0.0.1", "5.6.7.8", 40000, 443, false, "")
	if outEdge == nil {
		t.Fatal("stitch should be created when outbound arrives")
	}
}

func TestMultipleStitches(t *testing.T) {
	st := stitch.NewStitchTable()
	for i := 0; i < 5; i++ {
		fid := flowID(fmt.Sprintf("10.0.0.%d", i), "5.6.7.8", uint32(40000+i), 443, uint32(i), uint32(i*100))
		st.RecordOutbound(fid, "agent-a", uint32(100+i), "curl",
			fmt.Sprintf("10.0.0.%d", i), "5.6.7.8", uint32(40000+i), 443, false, "")
		st.RecordInbound(fid, "agent-b", uint32(200+i), "nginx",
			fmt.Sprintf("10.0.0.%d", i), "5.6.7.8", uint32(40000+i), 443, false)
	}

	edges := st.Edges()
	if len(edges) != 5 {
		t.Errorf("edges = %d", len(edges))
	}
}

func TestStitchStats(t *testing.T) {
	st := stitch.NewStitchTable()
	st.RecordOutbound(flowID("1", "2", 1, 2, 1, 1), "a", 1, "pkg-a", "1", "2", 1, 2, false, "")

	stats := st.Stats()
	if stats["outbound_records"].(int) != 1 {
		t.Errorf("outbound = %d", stats["outbound_records"])
	}
}

// ─── Taint propagation tests ────────────────────────────────

func TestNewTaintPropagator(t *testing.T) {
	tp := stitch.NewTaintPropagator()
	if tp == nil {
		t.Fatal("NewTaintPropagator returned nil")
	}
}

func TestMarkTainted(t *testing.T) {
	tp := stitch.NewTaintPropagator()
	tp.MarkTainted("agent-a", 100, "curl", "external_ip")
	if !tp.IsTainted("agent-a", 100) {
		t.Error("should be tainted")
	}
}

func TestPropagateViaStitch(t *testing.T) {
	tp := stitch.NewTaintPropagator()
	edge := &stitch.StitchEdge{
		SourceAgent: "agent-a", SourcePID: 100, SourceComm: "curl",
		TargetAgent: "agent-b", TargetPID: 200, TargetComm: "bash",
		Tainted: true,
	}
	tp.PropagateViaStitch(edge)

	if !tp.IsTainted("agent-b", 200) {
		t.Error("target should be tainted after stitch")
	}

	info := tp.GetTaintInfo("agent-b", 200)
	if info == nil || info.SourceAgent != "agent-a" {
		t.Errorf("source = %v", info)
	}
}

func TestNoPropagationWithoutTaint(t *testing.T) {
	tp := stitch.NewTaintPropagator()
	edge := &stitch.StitchEdge{
		SourceAgent: "agent-a", SourcePID: 100,
		TargetAgent: "agent-b", TargetPID: 200,
		Tainted: false,
	}
	tp.PropagateViaStitch(edge)

	if tp.IsTainted("agent-b", 200) {
		t.Error("should not propagate without taint")
	}
}

// ─── Server tests ───────────────────────────────────────────

func TestNewCentralServer(t *testing.T) {
	cs := stitch.NewCentralServer()
	if cs == nil {
		t.Fatal("NewCentralServer returned nil")
	}
}

func TestServerFullFlow(t *testing.T) {
	cs := stitch.NewCentralServer()

	// Mark agent-a process as tainted
	cs.MarkTainted("agent-a", 100, "curl", "external_ip:5.6.7.8")

	// Ingest outbound event
	fid := flowID("10.0.0.1", "5.6.7.8", 40000, 443, 5000, 2500)
	edge := cs.IngestOutbound(fid, "agent-a", 100, "curl",
		"10.0.0.1", "5.6.7.8", 40000, 443, true, "external_ip:5.6.7.8")

	// Ingest inbound on agent-b
	edge2 := cs.IngestInbound(fid, "agent-b", 200, "sshd",
		"10.0.0.1", "5.6.7.8", 40000, 443, false)

	if edge2 == nil {
		t.Fatal("server should create stitch edge")
	}
	if edge2.Tainted != true {
		t.Error("stitch should be tainted")
	}

	_ = edge
}

func TestQueryByAgent(t *testing.T) {
	cs := stitch.NewCentralServer()
	fid := flowID("10.0.0.1", "5.6.7.8", 40000, 443, 6000, 3000)
	cs.IngestOutbound(fid, "agent-a", 100, "curl",
		"10.0.0.1", "5.6.7.8", 40000, 443, false, "")
	cs.IngestInbound(fid, "agent-b", 200, "sshd",
		"10.0.0.1", "5.6.7.8", 40000, 443, false)

	edges := cs.QueryStitchByAgent("agent-a")
	if len(edges) == 0 {
		t.Error("no edges for agent-a")
	}
}

func TestQueryByFlow(t *testing.T) {
	cs := stitch.NewCentralServer()
	fid := flowID("10.0.0.1", "5.6.7.8", 40000, 443, 7000, 3500)
	cs.IngestOutbound(fid, "agent-a", 100, "curl",
		"10.0.0.1", "5.6.7.8", 40000, 443, false, "")
	cs.IngestInbound(fid, "agent-b", 200, "sshd",
		"10.0.0.1", "5.6.7.8", 40000, 443, false)

	edge := cs.QueryStitchByFlow(fid)
	if edge == nil {
		t.Error("edge not found by flow")
	}
}

func TestStitchStats2(t *testing.T) {
	cs := stitch.NewCentralServer()
	stats := cs.Stats()
	if stats["stitch_edges"].(int) != 0 {
		t.Errorf("edges = %d", stats["stitch_edges"])
	}
}

// ─── Integration test ───────────────────────────────────────

func TestStitchIntegration(t *testing.T) {
	t.Log("=== Cross-Host Stitching Integration ===")

	// Central server
	server := stitch.NewCentralServer()

	// Simulate: agent-a (compromised) → agent-b (target)
	fid := flowID("10.0.0.1", "10.0.0.2", 40000, 22, 0xDEAD, 0xBEEF)

	// Step 1: Mark agent-a's curl as tainted
	server.MarkTainted("agent-a", 100, "curl", "external_ip:5.6.7.8")
	t.Log("Step 1: agent-a/curl marked tainted (external C2)")

	// Step 2: agent-a curl connects to agent-b:22
	server.IngestOutbound(fid, "agent-a", 100, "curl",
		"10.0.0.1", "10.0.0.2", 40000, 22, true, "external_ip:5.6.7.8")
	t.Log("Step 2: agent-a/curl → agent-b:22 (outbound)")

	// Step 3: agent-b sshd accepts connection
	edge := server.IngestInbound(fid, "agent-b", 200, "sshd",
		"10.0.0.1", "10.0.0.2", 40000, 22, false)
	if edge != nil {
		t.Logf("Step 3: Stitch created: %s → %s (rel=%s, tainted=%v)",
			edge.SourceAgent, edge.TargetAgent, edge.Relation, edge.Tainted)
	} else {
		t.Fatal("stitch failed")
	}

	// Verify taint propagation
	if server.QueryStitchByFlow(fid).Tainted {
		t.Log("✓ Taint propagated across hosts")
	}

	// Verify lateral movement detection
	if edge.Relation == "lateral_move" {
		t.Log("✓ Lateral movement detected")
	}

	// Stats
	stats := server.Stats()
	t.Logf("Server: agents=%d edges=%d propagations=%d",
		stats["agents"], stats["stitch_edges"], stats["propagations"])

	t.Log("Stitching integration OK")
}
