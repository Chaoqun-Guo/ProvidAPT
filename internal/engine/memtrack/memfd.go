// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package memtrack implements memory execution tracing for ProvidAPT v2.1.
//
// Tracks:
//   1. memfd_create — anonymous memory-backed file descriptors
//   2. mmap PROT_EXEC — executable memory mappings
//   3. fexecve — execution from memory file descriptors
//
// Enables complete "memory download → memory execution" provenance chains.
package memtrack

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Memory file tracking
// ═══════════════════════════════════════════════════════════════

// MemfdEntry represents an anonymous memory file created via memfd_create.
type MemfdEntry struct {
	FD          int       `json:"fd"`
	Name        string    `json:"name"`        // name passed to memfd_create
	PID         uint32    `json:"pid"`         // creating process
	Comm        string    `json:"comm"`        // creating process name
	CreatedAt   time.Time `json:"created_at"`
	Written     bool      `json:"written"`     // has data been written?
	WriteSize   int64     `json:"write_size"`  // total bytes written
	ExecPID     uint32    `json:"exec_pid,omitempty"`  // PID that executed it
	ExecComm    string    `json:"exec_comm,omitempty"`  // process that executed it
}

// MemfdTracker monitors anonymous memory file operations.
type MemfdTracker struct {
	mu      sync.Mutex
	entries map[int]*MemfdEntry // fd → entry
	history []*MemfdEntry       // completed entries
}

// NewMemfdTracker creates a memfd tracker.
func NewMemfdTracker() *MemfdTracker {
	return &MemfdTracker{
		entries: make(map[int]*MemfdEntry),
	}
}

// OnCreate is called when memfd_create fires (from eBPF).
func (mt *MemfdTracker) OnCreate(fd int, name string, pid uint32, comm string) {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	entry := &MemfdEntry{
		FD:        fd,
		Name:      name,
		PID:       pid,
		Comm:      comm,
		CreatedAt: time.Now(),
	}
	mt.entries[fd] = entry
	log.Printf("[memfd] CREATE fd=%d name=%s pid=%d comm=%s", fd, name, pid, comm)
}

// OnWrite is called when data is written to a memfd.
func (mt *MemfdTracker) OnWrite(fd int, size int64) {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	if entry, ok := mt.entries[fd]; ok {
		entry.Written = true
		entry.WriteSize += size
	}
}

// OnExec is called when a memfd is executed via fexecve.
// Returns the memfd entry for provenance chain linkage.
func (mt *MemfdTracker) OnExec(fd int, pid uint32, comm string) *MemfdEntry {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	if entry, ok := mt.entries[fd]; ok {
		entry.ExecPID = pid
		entry.ExecComm = comm
		// Move to history
		delete(mt.entries, fd)
		mt.history = append(mt.history, entry)
		log.Printf("[memfd] EXEC fd=%d (%s) by pid=%d comm=%s — chain complete", fd, entry.Name, pid, comm)
		return entry
	}
	return nil
}

// OnClose is called when a memfd is closed without execution.
func (mt *MemfdTracker) OnClose(fd int) {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	if entry, ok := mt.entries[fd]; ok {
		mt.history = append(mt.history, entry)
		delete(mt.entries, fd)
	}
}

// GetEntry returns the current entry for a memfd.
func (mt *MemfdTracker) GetEntry(fd int) *MemfdEntry {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	return mt.entries[fd]
}

// ActiveCount returns the number of active memfds.
func (mt *MemfdTracker) ActiveCount() int {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	return len(mt.entries)
}

// CompletedChains returns all completed memfd→exec chains.
func (mt *MemfdTracker) CompletedChains() []*MemfdEntry {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	out := make([]*MemfdEntry, len(mt.history))
	copy(out, mt.history)
	return out
}

// ChainSummary returns a human-readable summary of a complete chain.
func (me *MemfdEntry) ChainSummary() string {
	return fmt.Sprintf("[memfd] %s (fd=%d) created by %s(%d), written=%d bytes, executed by %s(%d)",
		me.Name, me.FD, me.Comm, me.PID, me.WriteSize, me.ExecComm, me.ExecPID)
}
