// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package defense provides runtime self-protection for ProvidAPT
// through eBPF-backed mechanisms:
//
//  1. Log protection — registers RocksDB storage inodes with the
//     kernel eBPF program to prevent unauthorised writes.
//
//  2. Death monitoring — registers the agent PID so the kernel
//     can emit EV_AGENT_KILLED events if the process is killed.
//
//  3. Watchdog integration — exposes an event channel consumed by
//     the providapt-watchdog binary.
package defense

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/cilium/ebpf"
)

// ─── Constants (matching kernel/bpf/defense.bpf.c) ────────

const (
	AgentFlag    uint32 = 1 << 0
	WatchdogFlag uint32 = 1 << 1
)

// ─── Manager ────────────────────────────────────────────────

// Manager manages the eBPF defense maps.
type Manager struct {
	agentMap        *ebpf.Map
	protectedInodes *ebpf.Map
	defenseRB       *RingBufReader
}

// RingBufReader reads from the defense ring buffer.
type RingBufReader struct {
	events chan *collector.Event
}

// New creates a defense manager from loaded eBPF objects.
func New(agentMap *ebpf.Map, protectedInodes *ebpf.Map, defenseRB *ebpf.Map) *Manager {
	return &Manager{
		agentMap:        agentMap,
		protectedInodes: protectedInodes,
		defenseRB:       &RingBufReader{events: make(chan *collector.Event, 64)},
	}
}

// ── PID registration ───────────────────────────────────────

// RegisterAgentPID announces our PID to the kernel eBPF program.
// This enables death monitoring and log protection exemptions.
func (m *Manager) RegisterAgentPID(pid uint32) error {
	if m.agentMap == nil {
		return fmt.Errorf("agent eBPF map not initialized")
	}
	return m.agentMap.Put(pid, AgentFlag)
}

// UnregisterAgentPID removes our PID on graceful shutdown.
func (m *Manager) UnregisterAgentPID(pid uint32) error {
	if m.agentMap == nil {
		return fmt.Errorf("agent eBPF map not initialized")
	}
	return m.agentMap.Delete(pid)
}

// RegisterWatchdogPID announces the watchdog's PID.
func (m *Manager) RegisterWatchdogPID(pid uint32) error {
	if m.agentMap == nil {
		return fmt.Errorf("agent eBPF map not initialized")
	}
	return m.agentMap.Put(pid, WatchdogFlag)
}

// ── Inode protection ───────────────────────────────────────

// ProtectPath registers a file path's inode as protected.
// After registration, only the agent/watchdog can write to it.
func (m *Manager) ProtectPath(path string) error {
	if m.protectedInodes == nil {
		return fmt.Errorf("protected inodes eBPF map not initialized")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	stat, ok := info.Sys().(interface{ Ino() uint64 })
	if !ok {
		return fmt.Errorf("no inode access on %s", path)
	}
	inode := stat.Ino()
	return m.protectedInodes.Put(inode, uint32(0))
}

// ProtectDirectory recursively registers all files in a directory.
func (m *Manager) ProtectDirectory(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Protect the directory itself
			if e := m.ProtectPath(path); e != nil {
				log.Printf("[defense] protect dir %s: %v", path, e)
			}
			return nil
		}
		return m.ProtectPath(path)
	})
}

// ── Event channel ──────────────────────────────────────────

// DeathEvents returns a channel that receives agent death events.
func (m *Manager) DeathEvents() <-chan *collector.Event {
	return m.defenseRB.events
}

// ═══════════════════════════════════════════════════════════════
// Auto-defence integration for main.go
// ═══════════════════════════════════════════════════════════════

// Setup configures all defence mechanisms at startup.
// It should be called after the eBPF loader initialises.
func Setup(mgr *Manager, storePath string) error {
	if mgr == nil {
		return fmt.Errorf("defense manager is nil")
	}

	// 1. Register our PID
	pid := uint32(os.Getpid())
	if err := mgr.RegisterAgentPID(pid); err != nil {
		return fmt.Errorf("register agent pid: %w", err)
	}
	log.Printf("[defense] registered agent PID %d", pid)

	// 2. Protect the RocksDB storage
	if storePath != "" {
		if err := mgr.ProtectDirectory(storePath); err != nil {
			log.Printf("[defense] protect store %s: %v", storePath, err)
		} else {
			log.Printf("[defense] protected storage: %s", storePath)
		}
	}

	return nil
}
