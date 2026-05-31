package stitch

import (
	"testing"
)

func TestStitchTableNew(t *testing.T) {
	st := NewStitchTable()
	if st == nil {
		t.Fatal("NewStitchTable returned nil")
	}
}

func TestStitchTableRecordOutbound(t *testing.T) {
	st := NewStitchTable()
	edge := st.RecordOutbound("flow-000000000001", "agent-a", 100, "curl", "10.0.0.1", "198.51.100.1", 8080, 443, false, "")
	if edge != nil {
		t.Error("expected nil edge before inbound recorded")
	}
}

func TestStitchTableFullRoundTrip(t *testing.T) {
	st := NewStitchTable()
	st.RecordOutbound("flow-000000000001", "agent-a", 100, "curl", "10.0.0.1", "198.51.100.1", 8080, 443, false, "")
	edge := st.RecordInbound("flow-000000000001", "agent-b", 200, "sshd", "198.51.100.1", "10.0.0.1", 443, 8080, false)

	if edge == nil {
		t.Fatal("expected edge after matching inbound")
	}
	if edge.SourceAgent != "agent-a" {
		t.Errorf("source agent = %s", edge.SourceAgent)
	}
	if edge.TargetAgent != "agent-b" {
		t.Errorf("target agent = %s", edge.TargetAgent)
	}
}

func TestStitchTableGetByFlowID(t *testing.T) {
	st := NewStitchTable()
	st.RecordOutbound("flow-000000000001", "agent-a", 100, "curl", "10.0.0.1", "198.51.100.1", 8080, 443, false, "")
	st.RecordInbound("flow-000000000001", "agent-b", 200, "sshd", "198.51.100.1", "10.0.0.1", 443, 8080, false)

	outbound, inbound := st.GetByFlowID("flow-000000000001")
	if outbound == nil {
		t.Fatal("outbound is nil")
	}
	if inbound == nil {
		t.Fatal("inbound is nil")
	}
	if outbound.Comm != "curl" {
		t.Errorf("outbound comm = %s", outbound.Comm)
	}
}

func TestStitchTableGetByAgent(t *testing.T) {
	st := NewStitchTable()
	st.RecordOutbound("flow-000000000001", "agent-a", 100, "curl", "10.0.0.1", "198.51.100.1", 8080, 443, false, "")
	st.RecordInbound("flow-000000000001", "agent-b", 200, "sshd", "198.51.100.1", "10.0.0.1", 443, 8080, false)

	outs, ins := st.GetByAgent("agent-a")
	if len(outs) != 1 {
		t.Errorf("outbounds for agent-a = %d", len(outs))
	}
	if len(ins) != 0 {
		t.Errorf("inbounds for agent-a = %d", len(ins))
	}
}

func TestStitchTableCleanOld(t *testing.T) {
	st := NewStitchTable()
	st.RecordOutbound("flow-000000000001", "agent-a", 100, "curl", "10.0.0.1", "198.51.100.1", 8080, 443, false, "")
	st.CleanOld()
}

func TestStitchTableStats(t *testing.T) {
	st := NewStitchTable()
	st.RecordOutbound("flow-000000000001", "agent-a", 100, "curl", "10.0.0.1", "198.51.100.1", 8080, 443, false, "")
	st.RecordInbound("flow-000000000001", "agent-b", 200, "sshd", "198.51.100.1", "10.0.0.1", 443, 8080, false)

	stats := st.Stats()
	if stats["stitched_edges"].(int) != 1 {
		t.Errorf("edges = %d", stats["stitched_edges"])
	}
}

func TestTaintPropagatorNew(t *testing.T) {
	tp := NewTaintPropagator()
	if tp == nil {
		t.Fatal("NewTaintPropagator returned nil")
	}
}

func TestTaintPropagatorMarkAndCheck(t *testing.T) {
	tp := NewTaintPropagator()
	tp.MarkTainted("agent-a", 100, "curl", "sigma-rule: C2 beacon")

	if !tp.IsTainted("agent-a", 100) {
		t.Error("expected process to be tainted")
	}
	if tp.IsTainted("agent-a", 999) {
		t.Error("unrelated process should not be tainted")
	}
}

func TestTaintPropagatorGetInfo(t *testing.T) {
	tp := NewTaintPropagator()
	tp.MarkTainted("agent-a", 100, "curl", "sigma-rule: C2 beacon")

	info := tp.GetTaintInfo("agent-a", 100)
	if info == nil {
		t.Fatal("expected taint info")
	}
	if info.Source != "sigma-rule: C2 beacon" {
		t.Errorf("source = %s", info.Source)
	}
}

func TestTaintPropagatorPropagate(t *testing.T) {
	tp := NewTaintPropagator()
	tp.MarkTainted("agent-a", 100, "curl", "C2 beacon")
	tp.PropagateViaStitch(&StitchEdge{
		FlowID:      "test-flow-00000000001",
		SourceAgent: "agent-a",
		SourcePID:   100,
		TargetAgent: "agent-b",
		TargetPID:   200,
		Tainted:     true,
	})

	if !tp.IsTainted("agent-b", 200) {
		t.Error("expected taint to propagate to inbound process")
	}
}

func TestTaintPropagatorStats(t *testing.T) {
	tp := NewTaintPropagator()
	tp.MarkTainted("agent-a", 100, "curl", "C2")
	stats := tp.Stats()
	if stats["hosts_tracked"].(int) != 1 {
		t.Errorf("hosts_tracked = %d", stats["hosts_tracked"])
	}
}

func TestCentralServerNew(t *testing.T) {
	cs := NewCentralServer()
	if cs == nil {
		t.Fatal("NewCentralServer returned nil")
	}
}

func TestCentralServerIngest(t *testing.T) {
	cs := NewCentralServer()
	cs.IngestOutbound("flow-000000000001", "agent-a", 100, "curl", "10.0.0.1", "198.51.100.1", 8080, 443, false, "")
	cs.IngestInbound("flow-000000000001", "agent-b", 200, "sshd", "198.51.100.1", "10.0.0.1", 443, 8080, false)

	edges := cs.QueryStitchByAgent("agent-a")
	if len(edges) != 1 {
		t.Errorf("edges for agent-a = %d", len(edges))
	}

	edge := cs.QueryStitchByFlow("flow-000000000001")
	if edge == nil {
		t.Fatal("expected edge for flow-1")
	}
}

func TestCentralServerMarkTainted(t *testing.T) {
	cs := NewCentralServer()
	cs.IngestOutbound("flow-000000000001", "agent-a", 100, "curl", "10.0.0.1", "198.51.100.1", 8080, 443, false, "")
	cs.IngestInbound("flow-000000000001", "agent-b", 200, "sshd", "198.51.100.1", "10.0.0.1", 443, 8080, false)
	cs.MarkTainted("agent-a", 100, "curl", "C2 beacon")
}
