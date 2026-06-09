// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package stitch implements cross-host causal chain stitching for ProvidAPT.
//
// Core algorithm:
//  1. Maintain a Network_Stitch_Table mapping flow fingerprints to connections
//  2. Match outbound connect events with inbound accept events via fingerprint
//  3. Create RemoteCall edges linking processes across machines
//  4. Propagate taint labels across stitch points
package stitch

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?// Connection mapping table
// 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?
// FlowFingerprint uniquely identifies a TCP flow.
// Derived from (src_ip, src_port, dst_ip, dst_port, isn, tsval).
type FlowFingerprint struct {
	FlowID  string `json:"flow_id"` // SHA256 of 5-tuple + ISN + TS
	SrcIP   string `json:"src_ip"`
	DstIP   string `json:"dst_ip"`
	SrcPort uint32 `json:"src_port"`
	DstPort uint32 `json:"dst_port"`
}

// ConnectionRecord tracks one side of a connection.
type ConnectionRecord struct {
	Fingerprint FlowFingerprint `json:"fingerprint"`
	AgentID     string          `json:"agent_id"`
	PID         uint32          `json:"pid"`
	Comm        string          `json:"comm"`
	Direction   string          `json:"direction"` // "outbound" or "inbound"
	Tainted     bool            `json:"tainted"`
	TaintSource string          `json:"taint_source,omitempty"`
	Timestamp   time.Time       `json:"timestamp"`
}

// StitchEdge represents a cross-host causal relationship.
type StitchEdge struct {
	ID          string    `json:"id"`
	FlowID      string    `json:"flow_id"`
	SourceAgent string    `json:"source_agent"`
	SourcePID   uint32    `json:"source_pid"`
	SourceComm  string    `json:"source_comm"`
	TargetAgent string    `json:"target_agent"`
	TargetPID   uint32    `json:"target_pid"`
	TargetComm  string    `json:"target_comm"`
	Relation    string    `json:"relation"` // "remote_call", "lateral_move"
	Tainted     bool      `json:"tainted"`
	CreatedAt   time.Time `json:"created_at"`
}

// StitchTable is the central connection mapping table.
type StitchTable struct {
	mu          sync.Mutex
	outbound    map[string]*ConnectionRecord // flowID 鈫?outbound conn
	inbound     map[string]*ConnectionRecord // flowID 鈫?inbound conn
	edges       []*StitchEdge                // produced stitch edges
	edgeCounter int
	window      time.Duration // matching window (default 30s)
}

// NewStitchTable creates a connection mapping table.
func NewStitchTable() *StitchTable {
	return &StitchTable{
		outbound: make(map[string]*ConnectionRecord),
		inbound:  make(map[string]*ConnectionRecord),
		window:   30 * time.Second,
	}
}

// 鈹€鈹€鈹€ Record ingestion 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

// RecordOutbound stores an outbound connection event.
// If a matching inbound record exists within the time window,
// a StitchEdge is created immediately.
func (st *StitchTable) RecordOutbound(flowID, agentID string, pid uint32, comm string,
	srcIP, dstIP string, srcPort, dstPort uint32, tainted bool, taintSource string) *StitchEdge {

	rec := &ConnectionRecord{
		Fingerprint: FlowFingerprint{FlowID: flowID, SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort},
		AgentID:     agentID,
		PID:         pid,
		Comm:        comm,
		Direction:   "outbound",
		Tainted:     tainted,
		TaintSource: taintSource,
		Timestamp:   time.Now(),
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	st.outbound[flowID] = rec
	log.Printf("[stitch] OUTBOUND: %s 鈫?%s (agent=%s pid=%d flow=%s)", srcIP, dstIP, agentID, pid, flowID[:16])

	// Check for matching inbound
	if inbound, ok := st.inbound[flowID]; ok {
		delta := rec.Timestamp.Sub(inbound.Timestamp)
		if delta < 0 {
			delta = -delta
		}
		if delta <= st.window {
			return st.createEdge(rec, inbound)
		}
	}
	return nil
}

// RecordInbound stores an inbound connection event.
// If a matching outbound record exists, a StitchEdge is created.
func (st *StitchTable) RecordInbound(flowID, agentID string, pid uint32, comm string,
	srcIP, dstIP string, srcPort, dstPort uint32, tainted bool) *StitchEdge {

	rec := &ConnectionRecord{
		Fingerprint: FlowFingerprint{FlowID: flowID, SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort},
		AgentID:     agentID,
		PID:         pid,
		Comm:        comm,
		Direction:   "inbound",
		Tainted:     tainted,
		Timestamp:   time.Now(),
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	st.inbound[flowID] = rec
	log.Printf("[stitch] INBOUND: %s 鈫?%s (agent=%s pid=%d flow=%s)", srcIP, dstIP, agentID, pid, flowID[:16])

	// Check for matching outbound
	if outbound, ok := st.outbound[flowID]; ok {
		delta := rec.Timestamp.Sub(outbound.Timestamp)
		if delta < 0 {
			delta = -delta
		}
		if delta <= st.window {
			return st.createEdge(outbound, rec)
		}
	}
	return nil
}

// createEdge produces a StitchEdge and handles taint propagation.
func (st *StitchTable) createEdge(outbound, inbound *ConnectionRecord) *StitchEdge {
	st.edgeCounter++
	edge := &StitchEdge{
		ID:          fmt.Sprintf("SE-%d", st.edgeCounter),
		FlowID:      outbound.Fingerprint.FlowID,
		SourceAgent: outbound.AgentID,
		SourcePID:   outbound.PID,
		SourceComm:  outbound.Comm,
		TargetAgent: inbound.AgentID,
		TargetPID:   inbound.PID,
		TargetComm:  inbound.Comm,
		Relation:    "remote_call",
		Tainted:     outbound.Tainted || inbound.Tainted,
		CreatedAt:   time.Now(),
	}

	// Taint propagation: outbound taint 鈫?inbound process
	if outbound.Tainted {
		log.Printf("[stitch] TAINT PROPAGATION: %s/%s 鈫?%s/%s (source=%s)",
			outbound.AgentID, outbound.Comm, inbound.AgentID, inbound.Comm,
			outbound.TaintSource)
		inbound.Tainted = true
	}

	// Lateral movement detection
	if outbound.Tainted {
		edge.Relation = "lateral_move"
	}

	st.edges = append(st.edges, edge)
	log.Printf("[stitch] EDGE: %s 鈫?%s via flow %s (rel=%s, tainted=%v)",
		outbound.AgentID, inbound.AgentID, edge.FlowID[:16], edge.Relation, edge.Tainted)

	return edge
}

// 鈹€鈹€鈹€ Queries 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

// Edges returns all stitched edges.
func (st *StitchTable) Edges() []*StitchEdge {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]*StitchEdge, len(st.edges))
	copy(out, st.edges)
	return out
}

// GetByFlowID returns the connection records for a flow.
func (st *StitchTable) GetByFlowID(flowID string) (*ConnectionRecord, *ConnectionRecord) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.outbound[flowID], st.inbound[flowID]
}

// GetByAgent returns all records for an agent.
func (st *StitchTable) GetByAgent(agentID string) (outbounds, inbounds []*ConnectionRecord) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, rec := range st.outbound {
		if rec.AgentID == agentID {
			outbounds = append(outbounds, rec)
		}
	}
	for _, rec := range st.inbound {
		if rec.AgentID == agentID {
			inbounds = append(inbounds, rec)
		}
	}
	return
}

// CleanOld removes entries older than the window.
func (st *StitchTable) CleanOld() {
	st.mu.Lock()
	defer st.mu.Unlock()
	cutoff := time.Now().Add(-st.window)
	for id, rec := range st.outbound {
		if rec.Timestamp.Before(cutoff) {
			delete(st.outbound, id)
		}
	}
	for id, rec := range st.inbound {
		if rec.Timestamp.Before(cutoff) {
			delete(st.inbound, id)
		}
	}
}

// Stats returns stitch table statistics.
func (st *StitchTable) Stats() map[string]interface{} {
	st.mu.Lock()
	defer st.mu.Unlock()
	return map[string]interface{}{
		"outbound_records": len(st.outbound),
		"inbound_records":  len(st.inbound),
		"stitched_edges":   len(st.edges),
		"matching_window":  st.window.String(),
	}
}
