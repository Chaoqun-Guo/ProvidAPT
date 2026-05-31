package stitch

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Cross-host taint propagation
// ═══════════════════════════════════════════════════════════════

// TaintPropagator manages taint propagation across stitch points.
type TaintPropagator struct {
	mu        sync.Mutex
	hostTaints map[string]map[uint32]*TaintInfo // agentID → {PID → taint}
	propagated int
}

// TaintInfo holds taint state for a process.
type TaintInfo struct {
	PID         uint32    `json:"pid"`
	Comm        string    `json:"comm"`
	Tainted     bool      `json:"tainted"`
	Source      string    `json:"source"`       // how it was tainted
	SourceAgent string    `json:"source_agent"` // originating agent
	SourcePID   uint32    `json:"source_pid"`   // originating PID
	UpdatedAt   time.Time `json:"updated_at"`
}

// NewTaintPropagator creates a cross-host taint propagator.
func NewTaintPropagator() *TaintPropagator {
	return &TaintPropagator{
		hostTaints: make(map[string]map[uint32]*TaintInfo),
	}
}

// MarkTainted marks a local process as tainted.
func (tp *TaintPropagator) MarkTainted(agentID string, pid uint32, comm string, source string) {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	if _, ok := tp.hostTaints[agentID]; !ok {
		tp.hostTaints[agentID] = make(map[uint32]*TaintInfo)
	}
	tp.hostTaints[agentID][pid] = &TaintInfo{
		PID:       pid,
		Comm:      comm,
		Tainted:   true,
		Source:    source,
		UpdatedAt: time.Now(),
	}
	log.Printf("[taint-prop] MARK: agent=%s pid=%d comm=%s source=%s", agentID, pid, comm, source)
}

// PropagateViaStitch propagates taint across a stitch edge.
// Called when a StitchEdge is created.
func (tp *TaintPropagator) PropagateViaStitch(edge *StitchEdge) {
	if !edge.Tainted {
		return
	}

	tp.mu.Lock()
	defer tp.mu.Unlock()

	// Ensure target agent has a taint map
	if _, ok := tp.hostTaints[edge.TargetAgent]; !ok {
		tp.hostTaints[edge.TargetAgent] = make(map[uint32]*TaintInfo)
	}

	// Propagate taint to the target process
	tp.hostTaints[edge.TargetAgent][edge.TargetPID] = &TaintInfo{
		PID:         edge.TargetPID,
		Comm:        edge.TargetComm,
		Tainted:     true,
		Source:      fmt.Sprintf("cross-host-stitch:%s", edge.FlowID[:16]),
		SourceAgent: edge.SourceAgent,
		SourcePID:   edge.SourcePID,
		UpdatedAt:   time.Now(),
	}
	tp.propagated++

	log.Printf("[taint-prop] PROPAGATE: %s/%s → %s/%s (via stitch %s)",
		edge.SourceAgent, edge.SourceComm, edge.TargetAgent, edge.TargetComm, edge.ID)
}

// IsTainted checks if a process is tainted.
func (tp *TaintPropagator) IsTainted(agentID string, pid uint32) bool {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	if agentTaints, ok := tp.hostTaints[agentID]; ok {
		if info, ok := agentTaints[pid]; ok {
			return info.Tainted
		}
	}
	return false
}

// GetTaintInfo returns taint info for a process.
func (tp *TaintPropagator) GetTaintInfo(agentID string, pid uint32) *TaintInfo {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	if agentTaints, ok := tp.hostTaints[agentID]; ok {
		if info, ok := agentTaints[pid]; ok {
			return info
		}
	}
	return nil
}

// Stats returns propagator statistics.
func (tp *TaintPropagator) Stats() map[string]interface{} {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return map[string]interface{}{
		"hosts_tracked": len(tp.hostTaints),
		"propagations":  tp.propagated,
	}
}
