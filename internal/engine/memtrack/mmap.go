// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package memtrack

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Memory mapping (mmap PROT_EXEC) tracking
// ═══════════════════════════════════════════════════════════════

// MmapEntry records an executable memory mapping.
type MmapEntry struct {
	PID        uint32    `json:"pid"`
	Comm       string    `json:"comm"`
	Addr       uint64    `json:"addr"`       // start address
	Size       uint64    `json:"size"`       // mapping size
	Prot       uint32    `json:"prot"`       // memory protection flags
	Flags      uint32    `json:"flags"`      // mapping flags
	SourceFD   int       `json:"source_fd"`  // source file descriptor (if any)
	SourceFile string    `json:"source_file"` // source file path
	IsMemFD    bool      `json:"is_memfd"`   // mapped from a memfd?
	Timestamp  time.Time `json:"timestamp"`
}

// MmapTracker monitors executable memory mappings.
type MmapTracker struct {
	mu      sync.Mutex
	entries []*MmapEntry
}

// NewMmapTracker creates an mmap tracker.
func NewMmapTracker() *MmapTracker {
	return &MmapTracker{}
}

// OnMmapExec is called when mmap with PROT_EXEC is detected.
// sourceFD and sourceFile may be empty for anonymous mappings.
func (mt *MmapTracker) OnMmapExec(pid uint32, comm string, addr, size uint64,
	prot, flags uint32, sourceFD int, sourceFile string, isMemfd bool) {

	entry := &MmapEntry{
		PID:        pid,
		Comm:       comm,
		Addr:       addr,
		Size:       size,
		Prot:       prot,
		Flags:      flags,
		SourceFD:   sourceFD,
		SourceFile: sourceFile,
		IsMemFD:    isMemfd,
		Timestamp:  time.Now(),
	}

	mt.mu.Lock()
	mt.entries = append(mt.entries, entry)
	mt.mu.Unlock()

	source := sourceFile
	if isMemfd {
		source = fmt.Sprintf("memfd:%d", sourceFD)
	}
	log.Printf("[mmap] EXEC: pid=%d comm=%s addr=0x%x size=%d source=%s",
		pid, comm, addr, size, source)
}

// GetExecMappings returns all executable mappings for a PID.
func (mt *MmapTracker) GetExecMappings(pid uint32) []*MmapEntry {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	var out []*MmapEntry
	for _, e := range mt.entries {
		if e.PID == pid {
			out = append(out, e)
		}
	}
	return out
}

// Count returns total tracked entries.
func (mt *MmapTracker) Count() int {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	return len(mt.entries)
}
