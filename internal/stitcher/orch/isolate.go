// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package orch

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Multi-dimensional isolation
// ═══════════════════════════════════════════════════════════════

// IsolationEngine executes isolation commands on the local agent.
type IsolationEngine struct {
	mu      sync.Mutex
	uidBlock   map[uint32]time.Time   // UID → expiry
	commBlock  map[string]time.Time   // comm → expiry
	fileLocks  map[string]time.Time   // file hash → expiry
	ipBlock    map[string]time.Time   // IP → expiry
	processBlock map[uint32]time.Time // PID → expiry
}

// NewIsolationEngine creates an isolation engine.
func NewIsolationEngine() *IsolationEngine {
	return &IsolationEngine{
		uidBlock:   make(map[uint32]time.Time),
		commBlock:  make(map[string]time.Time),
		fileLocks:  make(map[string]time.Time),
		ipBlock:    make(map[string]time.Time),
		processBlock: make(map[uint32]time.Time),
	}
}

// ExecuteCommand applies a policy command to the local system.
func (ie *IsolationEngine) ExecuteCommand(cmd *PolicyCommand) {
	ie.mu.Lock()
	defer ie.mu.Unlock()

	expiry := time.Now().Add(cmd.TTL)

	switch cmd.Type {
	case CmdBlockUID:
		var uid uint32
		fmt.Sscanf(cmd.Target, "%d", &uid)
		ie.uidBlock[uid] = expiry
		log.Printf("[isolate] UID BLOCK: %d (until %v)", uid, expiry)

		// In production: write to eBPF map so LSM hooks deny exec/fork
		// blocked_uids_map.Put(uid, 1)

	case CmdBlockComm:
		ie.commBlock[cmd.Target] = expiry
		log.Printf("[isolate] COMM BLOCK: %s", cmd.Target)

	case CmdLockFile:
		ie.fileLocks[cmd.Target] = expiry
		log.Printf("[isolate] FILE LOCK: hash=%s", cmd.Target)

	case CmdBlockIP:
		ie.ipBlock[cmd.Target] = expiry
		log.Printf("[isolate] IP BLOCK: %s", cmd.Target)

	case CmdBlockProcess:
		var pid uint32
		fmt.Sscanf(cmd.Target, "%d", &pid)
		ie.processBlock[pid] = expiry
		log.Printf("[isolate] PROCESS BLOCK: PID %d", pid)
	}
}

// IsUIDBlocked checks if a UID is blocked.
func (ie *IsolationEngine) IsUIDBlocked(uid uint32) bool {
	ie.mu.Lock()
	defer ie.mu.Unlock()
	expiry, ok := ie.uidBlock[uid]
	return ok && time.Now().Before(expiry)
}

// IsCommBlocked checks if a process comm is blocked.
func (ie *IsolationEngine) IsCommBlocked(comm string) bool {
	ie.mu.Lock()
	defer ie.mu.Unlock()
	expiry, ok := ie.commBlock[comm]
	return ok && time.Now().Before(expiry)
}

// IsFileLocked checks if a file hash is locked.
func (ie *IsolationEngine) IsFileLocked(hash string) bool {
	ie.mu.Lock()
	defer ie.mu.Unlock()
	expiry, ok := ie.fileLocks[hash]
	return ok && time.Now().Before(expiry)
}

// IsIPBlocked checks if an IP is blocked.
func (ie *IsolationEngine) IsIPBlocked(ip string) bool {
	ie.mu.Lock()
	defer ie.mu.Unlock()
	expiry, ok := ie.ipBlock[ip]
	return ok && time.Now().Before(expiry)
}

// BlockedCounts returns the number of active blocks.
func (ie *IsolationEngine) BlockedCounts() map[string]int {
	ie.mu.Lock()
	defer ie.mu.Unlock()
	return map[string]int{
		"uid_blocks":    len(ie.uidBlock),
		"comm_blocks":   len(ie.commBlock),
		"file_locks":    len(ie.fileLocks),
		"ip_blocks":     len(ie.ipBlock),
		"process_blocks": len(ie.processBlock),
	}
}
