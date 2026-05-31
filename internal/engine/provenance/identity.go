package provenance

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Enhanced process identity management
//
// Provides:
//   1. PID + start_time composite ID — prevents PID reuse from
//      corrupting the provenance graph.
//   2. Process inheritance — propagates security context from
//      parent to child on fork.
//   3. Orphan process handling — attaches orphaned processes to
//      a virtual unknown_parent node.
// ═══════════════════════════════════════════════════════════════

// ─── Constants ──────────────────────────────────────────────

// unknownParentID is the virtual node for orphaned processes.
const unknownParentID = "p:0:unknown_parent"

// startTimeUnknown is used when start_time cannot be read.
const startTimeUnknown = 0

// ─── Start-time reader ─────────────────────────────────────

// readStartTime reads the process start time from /proc/<pid>/stat.
// Field 22 (1-indexed) is starttime in jiffies since boot.
// Returns 0 on error (caller falls back to PID-only ID).
func readStartTime(pid uint32) uint64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return startTimeUnknown
	}
	// Format: pid (comm) state ... field22 ...
	// Find the closing paren of comm, then skip 20 fields
	fields := strings.Fields(string(data))
	if len(fields) < 22 {
		return startTimeUnknown
	}
	// comm may contain spaces/parens — find the last ')' in the raw data
	raw := string(data)
	closeParen := strings.LastIndex(raw, ")")
	if closeParen < 0 {
		return startTimeUnknown
	}
	// Fields after the comm include: state, ppid, pgid, sid, tty_nr, tty_pgrp,
	// flags, min_flt, cmin_flt, maj_flt, cmaj_flt, utime, stime, cutime, cstime,
	// priority, nice, num_threads, it_real_val, starttime (field 22)
	after := raw[closeParen+2:] // skip ") "
	parts := strings.Fields(after)
	if len(parts) < 20 {
		return startTimeUnknown
	}
	val, err := strconv.ParseUint(parts[19], 10, 64)
	if err != nil {
		return startTimeUnknown
	}
	return val
}

// ─── Process ID builder ─────────────────────────────────────

// ProcessNodeID builds a unique process node ID combining PID and
// start_time.  Format: "p:<pid>:<start_time>"
//
// This prevents PID reuse from merging distinct process lifetimes
// into a single graph node.
func ProcessNodeID(pid uint32) string {
	startTime := readStartTime(pid)
	if startTime == startTimeUnknown {
		// Fallback: just use PID (v1 compatible)
		return nodeID("p", pid)
	}
	return nodeID("p", pid, startTime)
}

// ─── Process identity tracker ───────────────────────────────

// ProcessStore tracks parent-child relationships and resolves
// orphaned processes to the virtual unknown_parent node.
type ProcessStore struct {
	mu          sync.Mutex
	parentOf    map[uint32]uint32  // child_pid → parent_pid
	knownPIDs   map[uint32]bool    // PIDs we've seen in the graph
}

// NewProcessStore creates a process relationship tracker.
func NewProcessStore() *ProcessStore {
	return &ProcessStore{
		parentOf:  make(map[uint32]uint32),
		knownPIDs: make(map[uint32]bool),
	}
}

// RecordFork stores the parent-child relationship for later use.
func (ps *ProcessStore) RecordFork(parentPID, childPID uint32) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.parentOf[childPID] = parentPID
	ps.knownPIDs[parentPID] = true
	ps.knownPIDs[childPID] = true
}

// RecordProcess marks a PID as known in the graph.
func (ps *ProcessStore) RecordProcess(pid uint32) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.knownPIDs[pid] = true
}

// ResolveParent returns the parent PID for a process.
// If the parent is not known (orphan), returns 0.
func (ps *ProcessStore) ResolveParent(pid uint32) uint32 {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.parentOf[pid]
}

// IsOrphan returns true if the process has no known parent in the graph.
func (ps *ProcessStore) IsOrphan(pid uint32) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	parent, ok := ps.parentOf[pid]
	if !ok || !ps.knownPIDs[parent] {
		return true
	}
	return false
}

// ─── Parent context inheritance ─────────────────────────────

// InheritParentContext copies security-relevant labels from parent
// to child node.  This ensures that even after fork, the child
// retains the parent's identity and security context.
func InheritParentContext(child, parent *Node) {
	if child == nil || parent == nil {
		return
	}

	// Inherit identity attributes
	for _, key := range []string{"identity", "session_id", "source_ip", "auth_method"} {
		if v, ok := parent.Attributes[key]; ok {
			child.Attributes[key] = v
		}
	}

	// Inherit taint-like markers
	for _, key := range []string{"taint", "monitor_level"} {
		if v, ok := parent.Attributes[key]; ok {
			child.Attributes[key] = v
		}
	}
}

// ─── Graph integration ──────────────────────────────────────

// EnsureParentNode checks if a process's parent exists in the graph.
// If not, creates the unknown_parent virtual node as the parent.
// This prevents provenance branches from being dropped.
func (g *Graph) EnsureParentNode(pid uint32, ts time.Time) {
	parentPID := g.procStore.ResolveParent(pid)
	if parentPID == 0 {
		// No parent recorded — attach to unknown_parent
		g.getOrCreateNode(unknownParentID, ProvActivity, SubProcess,
			"unknown_parent", ts)
		return
	}

	// Try to find the parent node
	parentID := ProcessNodeID(parentPID)
	if _, exists := g.nodes[parentID]; !exists {
		// Parent exited — attach to unknown_parent
		// but record the parent PID for forensic purposes
		parentNode := g.getOrCreateNode(unknownParentID, ProvActivity,
			SubProcess, "unknown_parent", ts)
		parentNode.upsertAttr("original_parent_pid", parentPID)
	}
}
