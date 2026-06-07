// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package respond implements surgical response actions for ProvidAPT v2.1.
//
// Actions:
//   1. Causal blocking — block high-risk process trees via eBPF LSM
//   2. File quarantine — permission-lock files written by malicious processes
//   3. Response policy — YAML-configured action rules
package respond

import (
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Causal blocking — isolate process trees
// ═══════════════════════════════════════════════════════════════

// BlockLevel defines the isolation strictness.
type BlockLevel int

const (
	BlockNone     BlockLevel = 0
	BlockNetwork  BlockLevel = 1 // block network access only
	BlockSensitive BlockLevel = 2 // block network + sensitive paths
	BlockAll      BlockLevel = 3 // block all non-essential syscalls
)

func (bl BlockLevel) String() string {
	switch bl {
	case BlockNone:
		return "NONE"
	case BlockNetwork:
		return "NETWORK_ONLY"
	case BlockSensitive:
		return "SENSITIVE"
	case BlockAll:
		return "FULL_ISOLATION"
	default:
		return "UNKNOWN"
	}
}

// BlockedProcess tracks an isolated process tree.
type BlockedProcess struct {
	PID       uint32     `json:"pid"`
	Comm      string     `json:"comm"`
	Level     BlockLevel `json:"level"`
	BlockedAt time.Time  `json:"blocked_at"`
	Children  []uint32   `json:"children,omitempty"`
}

// CausalBlocker manages process isolation via eBPF LSM maps.
//
// In production, it writes to a BPF_MAP_TYPE_HASH that the LSM
// programs read to decide whether to allow or deny operations.
type CausalBlocker struct {
	mu       sync.Mutex
	blocked  map[uint32]*BlockedProcess // PID → block info
	children map[uint32]bool            // all PIDs in blocked trees
}

// NewCausalBlocker creates a process isolation manager.
func NewCausalBlocker() *CausalBlocker {
	return &CausalBlocker{
		blocked:  make(map[uint32]*BlockedProcess),
		children: make(map[uint32]bool),
	}
}

// BlockProcess isolates a process and its future children.
// The level determines what operations are denied.
func (cb *CausalBlocker) BlockProcess(pid uint32, comm string, level BlockLevel) *BlockedProcess {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	bp := &BlockedProcess{
		PID:       pid,
		Comm:      comm,
		Level:     level,
		BlockedAt: time.Now(),
	}
	cb.blocked[pid] = bp
	cb.children[pid] = true

	// In production: write to BPF map
	//   blocked_pids_map.Put(pid, uint32(level))
	//   LSM programs check this map at file_open, socket_connect

	log.Printf("[respond] BLOCKED pid=%d comm=%s level=%s", pid, comm, level)
	return bp
}

// AddChild registers a child process of a blocked tree.
func (cb *CausalBlocker) AddChild(parentPID, childPID uint32) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if _, ok := cb.blocked[parentPID]; ok {
		cb.children[childPID] = true
		cb.blocked[parentPID].Children = append(cb.blocked[parentPID].Children, childPID)

		// In production: also write child PID to BPF map
		log.Printf("[respond] child added: %d → %d", parentPID, childPID)
	}
}

// IsBlocked checks if a PID is in an isolated process tree.
func (cb *CausalBlocker) IsBlocked(pid uint32) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.children[pid]
}

// BlockLevel returns the isolation level for a blocked PID.
func (cb *CausalBlocker) BlockLevel(pid uint32) BlockLevel {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if bp, ok := cb.blocked[pid]; ok {
		return bp.Level
	}
	return BlockNone
}

// UnblockProcess removes isolation from a process tree.
func (cb *CausalBlocker) UnblockProcess(pid uint32) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if bp, ok := cb.blocked[pid]; ok {
		// Remove all children
		for _, childPID := range bp.Children {
			delete(cb.children, childPID)
		}
		delete(cb.children, pid)
		delete(cb.blocked, pid)

		// In production: delete from BPF map
		log.Printf("[respond] UNBLOCKED pid=%d", pid)
	}
}

// Stats returns blocker statistics.
func (cb *CausalBlocker) Stats() map[string]interface{} {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return map[string]interface{}{
		"blocked_trees": len(cb.blocked),
		"blocked_pids":  len(cb.children),
	}
}
