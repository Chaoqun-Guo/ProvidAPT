// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package memtrack

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// fexecve — execution from memory file descriptor
// ═══════════════════════════════════════════════════════════════

// ExecChain represents a complete "memory download → memory execution" chain.
type ExecChain struct {
	MemfdCreate  *MemfdEntry  `json:"memfd_create"`  // memfd_create event
	MemfdWrite   *WriteEvent  `json:"memfd_write"`   // data written to memfd
	MmapExec     *MmapEntry   `json:"mmap_exec"`     // executable mapping
	Fexecve      *FexecveEvent `json:"fexecve"`      // execution via fexecve
	Complete     bool         `json:"complete"`      // all 4 stages present
}

// WriteEvent records data written to a memfd.
type WriteEvent struct {
	FD       int       `json:"fd"`
	PID      uint32    `json:"pid"`
	Comm     string    `json:"comm"`
	Size     int64     `json:"size"`
	Offset   int64     `json:"offset,omitempty"`
	ContentHash string `json:"content_hash,omitempty"` // SHA256 of first 4KB
	Time     time.Time `json:"time"`
}

// FexecveEvent records execution via fexecve syscall.
type FexecveEvent struct {
	FD          int       `json:"fd"`
	PID         uint32    `json:"pid"`
	Comm        string    `json:"comm"`
	Filename    string    `json:"filename"`  // /proc/self/fd/<N>
	Argv        string    `json:"argv,omitempty"` // first 128 chars
	Time        time.Time `json:"time"`
}

// ExecFlowTracker ties memfd_create → write → mmap → fexecve into chains.
type ExecFlowTracker struct {
	mu       sync.Mutex
	memfds   *MemfdTracker
	mmaps    *MmapTracker
	writes   []*WriteEvent
	fexecves []*FexecveEvent
	chains   []*ExecChain
}

// NewExecFlowTracker creates a complete execution flow tracker.
func NewExecFlowTracker(memfds *MemfdTracker, mmaps *MmapTracker) *ExecFlowTracker {
	return &ExecFlowTracker{
		memfds: memfds,
		mmaps:  mmaps,
	}
}

// OnWrite records a write to a memfd and links it to the chain.
func (eft *ExecFlowTracker) OnWrite(fd int, pid uint32, comm string, size int64) {
	evt := &WriteEvent{
		FD:   fd,
		PID:  pid,
		Comm: comm,
		Size: size,
		Time: time.Now(),
	}

	eft.mu.Lock()
	eft.writes = append(eft.writes, evt)
	eft.mu.Unlock()

	// Notify the memfd tracker
	if eft.memfds != nil {
		eft.memfds.OnWrite(fd, size)
	}

	log.Printf("[execflow] WRITE fd=%d pid=%d comm=%s size=%d", fd, pid, comm, size)
}

// OnFexecve records execution via fexecve and builds the complete chain.
func (eft *ExecFlowTracker) OnFexecve(fd int, pid uint32, comm string, argv string) *ExecChain {
	evt := &FexecveEvent{
		FD:       fd,
		PID:      pid,
		Comm:     comm,
		Filename: fmt.Sprintf("/proc/self/fd/%d", fd),
		Argv:     argv,
		Time:     time.Now(),
	}

	eft.mu.Lock()
	eft.fexecves = append(eft.fexecves, evt)
	eft.mu.Unlock()

	// Build the complete chain
	chain := &ExecChain{}

	// Get memfd entry (if it exists)
	if eft.memfds != nil {
		entry := eft.memfds.OnExec(fd, pid, comm)
		if entry != nil {
			chain.MemfdCreate = entry
		}
	}

	chain.Fexecve = evt

	// Find corresponding mmap entries
	if eft.mmaps != nil {
		mappings := eft.mmaps.GetExecMappings(pid)
		for _, m := range mappings {
			if m.IsMemFD || m.SourceFD == fd {
				chain.MmapExec = m
				break
			}
		}
	}

	// Find corresponding write events
	for _, w := range eft.writes {
		if w.FD == fd {
			chain.MemfdWrite = w
			break
		}
	}

	chain.Complete = chain.MemfdCreate != nil &&
		chain.MemfdWrite != nil &&
		chain.Fexecve != nil

	eft.mu.Lock()
	eft.chains = append(eft.chains, chain)
	eft.mu.Unlock()

	log.Printf("[execflow] CHAIN: %s", chain.Summary())
	return chain
}

// Chains returns all completed execution chains.
func (eft *ExecFlowTracker) Chains() []*ExecChain {
	eft.mu.Lock()
	defer eft.mu.Unlock()
	out := make([]*ExecChain, len(eft.chains))
	copy(out, eft.chains)
	return out
}

// Summary returns a human-readable chain description.
func (ec *ExecChain) Summary() string {
	var parts []string
	if ec.MemfdCreate != nil {
		parts = append(parts, fmt.Sprintf("create(%s)", ec.MemfdCreate.Name))
	}
	if ec.MemfdWrite != nil {
		parts = append(parts, fmt.Sprintf("write(%d bytes)", ec.MemfdWrite.Size))
	}
	if ec.MmapExec != nil {
		parts = append(parts, "mmap(RX)")
	}
	if ec.Fexecve != nil {
		parts = append(parts, fmt.Sprintf("exec(%s)", ec.Fexecve.Comm))
	}
	return fmt.Sprintf("memfd: %s", strings.Join(parts, " → "))
}

// Stats returns flow tracker statistics.
func (eft *ExecFlowTracker) Stats() map[string]interface{} {
	eft.mu.Lock()
	defer eft.mu.Unlock()
	return map[string]interface{}{
		"writes":       len(eft.writes),
		"fexecves":     len(eft.fexecves),
		"chains":       len(eft.chains),
		"active_memfd": eft.memfds.ActiveCount(),
	}
}
