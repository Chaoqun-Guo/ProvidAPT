// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package respond implements surgical response actions for ProvidAPT.
//
// Actions:
//  1. Causal blocking — block high-risk process trees via eBPF LSM
//  2. File quarantine — permission-lock files written by malicious processes
//  3. Response policy — YAML-configured action rules
package respond

import (
	"log"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

// ═══════════════════════════════════════════════════════════════
// Causal blocking — isolate process trees
// ═══════════════════════════════════════════════════════════════

// BlockLevel defines the isolation strictness.
type BlockLevel int

const (
	BlockNone      BlockLevel = 0
	BlockNetwork   BlockLevel = 1 // block network access only
	BlockSensitive BlockLevel = 2 // block network + sensitive paths
	BlockAll       BlockLevel = 3 // block all non-essential syscalls
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
	blocked  map[uint32]*BlockedProcess // PID -> block info
	children map[uint32]bool            // all PIDs in blocked trees
	bpfMap   *ebpf.Map                  // pinned BPF map, nil if unavailable
}

// NewCausalBlocker creates a process isolation manager.
// If a BPF map path is provided, attempts to open it for kernel-level blocking.
// When the BPF map is unavailable, blocking is in-memory only.
func NewCausalBlocker(bpfMapPath string) *CausalBlocker {
	cb := &CausalBlocker{
		blocked:  make(map[uint32]*BlockedProcess),
		children: make(map[uint32]bool),
	}
	if bpfMapPath != "" {
		m, err := ebpf.LoadPinnedMap(bpfMapPath, &ebpf.LoadPinOptions{})
		if err == nil {
			cb.bpfMap = m
			log.Printf("[respond] BPF map opened: %s", bpfMapPath)
		} else {
			log.Printf("[respond] BPF map not available at %s: %v (in-memory fallback)", bpfMapPath, err)
		}
	}
	return cb
}

// bpfPut writes a PID with its block level to the BPF map (best-effort).
func (cb *CausalBlocker) bpfPut(pid uint32, level BlockLevel) {
	if cb.bpfMap == nil {
		return
	}
	val := uint32(level)
	if err := cb.bpfMap.Put(pid, val); err != nil {
		log.Printf("[respond] BPF map Put pid=%d: %v", pid, err)
	}
}

// bpfDelete removes a PID from the BPF map (best-effort).
func (cb *CausalBlocker) bpfDelete(pid uint32) {
	if cb.bpfMap == nil {
		return
	}
	if err := cb.bpfMap.Delete(pid); err != nil {
		log.Printf("[respond] BPF map Delete pid=%d: %v", pid, err)
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

	// Write to BPF map for kernel-level enforcement
	cb.bpfPut(pid, level)

	log.Printf("[respond] BLOCKED pid=%d comm=%s level=%s", pid, comm, level)
	return bp
}

// AddChild registers a child process of a blocked tree.
func (cb *CausalBlocker) AddChild(parentPID, childPID uint32) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if bp, ok := cb.blocked[parentPID]; ok {
		cb.children[childPID] = true
		bp.Children = append(bp.Children, childPID)

		// Also write child PID to BPF map at same level as parent
		cb.bpfPut(childPID, bp.Level)

		log.Printf("[respond] child added: %d -> %d", parentPID, childPID)
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
		// Remove all children from BPF map and tracking
		for _, childPID := range bp.Children {
			cb.bpfDelete(childPID)
			delete(cb.children, childPID)
		}
		cb.bpfDelete(pid)
		delete(cb.children, pid)
		delete(cb.blocked, pid)

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
