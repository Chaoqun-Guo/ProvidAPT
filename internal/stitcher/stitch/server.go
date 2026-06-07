// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package stitch

import (
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Central stitch server
// ═══════════════════════════════════════════════════════════════

// CentralServer receives telemetry from multiple agents and
// performs cross-host stitching.
type CentralServer struct {
	table      *StitchTable
	propagator *TaintPropagator
	agents     map[string]bool // known agent IDs
	mu         sync.Mutex
	startedAt  time.Time
}

// NewCentralServer creates a central stitching server.
func NewCentralServer() *CentralServer {
	return &CentralServer{
		table:      NewStitchTable(),
		propagator: NewTaintPropagator(),
		agents:     make(map[string]bool),
		startedAt:  time.Now(),
	}
}

// IngestOutbound processes an outbound connection event from an agent.
func (cs *CentralServer) IngestOutbound(flowID, agentID string, pid uint32, comm string,
	srcIP, dstIP string, srcPort, dstPort uint32, tainted bool, taintSource string) *StitchEdge {

	cs.mu.Lock()
	cs.agents[agentID] = true
	cs.mu.Unlock()

	edge := cs.table.RecordOutbound(flowID, agentID, pid, comm, srcIP, dstIP, srcPort, dstPort, tainted, taintSource)
	if edge != nil {
		cs.propagator.PropagateViaStitch(edge)
	}
	return edge
}

// IngestInbound processes an inbound connection event from an agent.
func (cs *CentralServer) IngestInbound(flowID, agentID string, pid uint32, comm string,
	srcIP, dstIP string, srcPort, dstPort uint32, tainted bool) *StitchEdge {

	cs.mu.Lock()
	cs.agents[agentID] = true
	cs.mu.Unlock()

	edge := cs.table.RecordInbound(flowID, agentID, pid, comm, srcIP, dstIP, srcPort, dstPort, tainted)
	if edge != nil {
		cs.propagator.PropagateViaStitch(edge)
	}
	return edge
}

// MarkTainted marks a process on an agent as tainted.
func (cs *CentralServer) MarkTainted(agentID string, pid uint32, comm string, source string) {
	cs.propagator.MarkTainted(agentID, pid, comm, source)
}

// QueryStitchByAgent returns all stitch edges involving an agent.
func (cs *CentralServer) QueryStitchByAgent(agentID string) []*StitchEdge {
	allEdges := cs.table.Edges()
	var out []*StitchEdge
	for _, e := range allEdges {
		if e.SourceAgent == agentID || e.TargetAgent == agentID {
			out = append(out, e)
		}
	}
	return out
}

// QueryStitchByFlow returns stitch edges for a flow ID.
func (cs *CentralServer) QueryStitchByFlow(flowID string) *StitchEdge {
	for _, e := range cs.table.Edges() {
		if e.FlowID == flowID {
			return e
		}
	}
	return nil
}

// CleanupPeriodically runs maintenance in the background.
func (cs *CentralServer) CleanupPeriodically(stopCh <-chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cs.table.CleanOld()
			case <-stopCh:
				return
			}
		}
	}()
}

// Stats returns server statistics.
func (cs *CentralServer) Stats() map[string]interface{} {
	cs.mu.Lock()
	agentCount := len(cs.agents)
	cs.mu.Unlock()

	stitchStats := cs.table.Stats()
	propStats := cs.propagator.Stats()
	uptime := time.Since(cs.startedAt).String()

	return map[string]interface{}{
		"agents":         agentCount,
		"uptime":         uptime,
		"stitch_edges":   stitchStats["stitched_edges"],
		"propagations":   propStats["propagations"],
		"outbound":       stitchStats["outbound_records"],
		"inbound":        stitchStats["inbound_records"],
	}
}
