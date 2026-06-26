// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package control provides dynamic runtime control over the eBPF
// kernel programs — allowing userspace to inject PID/path whitelist
// entries, read taint state, and query sampling statistics without
// reloading the BPF programs.
package control

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
)

// ─── Taint flags (must match kernel/include/taint.h) ────────
const (
	TaintNone       uint32 = 0
	TaintNetConnect uint32 = 1 << 0
	TaintFileWrite  uint32 = 1 << 1
	TaintSetuid     uint32 = 1 << 2
	TaintParent     uint32 = 1 << 3
)

var taintNames = map[uint32]string{
	TaintNetConnect: "NET_CONNECT",
	TaintFileWrite:  "FILE_WRITE",
	TaintSetuid:     "SETUID",
	TaintParent:     "PARENT",
}

func TaintString(flags uint32) string {
	if flags == TaintNone {
		return "NONE"
	}
	s := ""
	var known uint32
	for mask, name := range taintNames {
		if flags&mask != 0 {
			known |= mask
			if s != "" {
				s += "|"
			}
			s += name
		}
	}
	if unknown := flags & ^known; unknown != 0 {
		if s != "" {
			s += "|"
		}
		s += fmt.Sprintf("0x%x", unknown)
	}
	return s
}

// ─── Controller ─────────────────────────────────────────────

// Controller manages the optimisation maps exposed by the
// eBPF LSM programs:
//
//	pid_whitelist   — PIDs to exclude from monitoring entirely
//	taint_map       — per-process taint flags (read-only)
//	sample_counters — adaptive sampling counters (read-only)
//	dedup_map       — kernel-side frequency limiting (read-only)
//	hot_paths       — high-interest path prefixes (writable)
type Controller struct {
	mu             sync.Mutex
	pidWhitelist   *ebpf.Map
	taintMap       *ebpf.Map
	sampleCounters *ebpf.Map
	hotPaths       *ebpf.Map
}

// New creates a Controller from loaded eBPF objects.
func New(pidWhitelist, taintMap, sampleCounters, hotPaths *ebpf.Map) *Controller {
	return &Controller{
		pidWhitelist:   pidWhitelist,
		taintMap:       taintMap,
		sampleCounters: sampleCounters,
		hotPaths:       hotPaths,
	}
}

// ── PID whitelist ──────────────────────────────────────────

// ExcludePID marks a process PID as excluded from monitoring.
// Whitelisted PIDs skip ALL event emission in the kernel.
func (ctl *Controller) ExcludePID(pid uint32) error {
	return ctl.pidWhitelist.Put(pid, uint32(1))
}

// UnExcludePID removes a PID from the whitelist.
func (ctl *Controller) UnExcludePID(pid uint32) error {
	return ctl.pidWhitelist.Delete(pid)
}

// IsExcluded checks if a PID is whitelisted.
func (ctl *Controller) IsExcluded(pid uint32) bool {
	var v uint32
	err := ctl.pidWhitelist.Lookup(pid, &v)
	return err == nil
}

// ── Taint queries ──────────────────────────────────────────

// GetTaint returns the taint flags for a PID.
// Returns 0 (TaintNone) if the process has no taint.
func (ctl *Controller) GetTaint(pid uint32) (uint32, error) {
	var flags uint32
	err := ctl.taintMap.Lookup(pid, &flags)
	if err != nil {
		return TaintNone, nil // not tainted
	}
	return flags, nil
}

// DumpTaints iterates all tainted PIDs and calls fn for each.
func (ctl *Controller) DumpTaints(fn func(pid uint32, flags uint32)) {
	iter := ctl.taintMap.Iterate()
	var pid uint32
	var flags uint32
	for iter.Next(&pid, &flags) {
		fn(pid, flags)
	}
}

// ── Convenience: batch exclude (common noisy processes) ────

// DefaultExcludes adds common build/update tool PIDs to the
// whitelist. It scans /proc for processes matching known noisy comm
// names and excludes them from monitoring.
func (ctl *Controller) DefaultExcludes() error {
	noisyComms := []string{
		"yum", "dnf", "apt", "dpkg", "rpm",
		"make", "gcc", "cc", "g++", "clang",
		"systemd-journal", "systemd-resolve",
		"cron", "anacron", "systemd-tmpfiles",
		"updatedb", "locate", "plocate",
		"mandb", "catman",
	}
	excluded, err := ctl.ExcludeComms(noisyComms)
	if err != nil {
		return err
	}
	log.Printf("[control] default excludes applied: excluded %d noisy processes", excluded)
	return nil
}

// ExcludeComm scans /proc and excludes all running processes with the given comm.
func (ctl *Controller) ExcludeComm(comm string) (int, error) {
	return ctl.ExcludeComms([]string{comm})
}

// ExcludeComms scans /proc and excludes all running processes with matching comm names.
func (ctl *Controller) ExcludeComms(comms []string) (int, error) {
	if len(comms) == 0 {
		return 0, nil
	}
	targets := make(map[string]struct{}, len(comms))
	for _, comm := range comms {
		trimmed := strings.TrimSpace(comm)
		if trimmed == "" {
			continue
		}
		targets[trimmed] = struct{}{}
	}
	if len(targets) == 0 {
		return 0, nil
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("scan /proc: %w", err)
	}

	var excluded int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}

		commData, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(commData))
		if _, ok := targets[comm]; !ok {
			continue
		}

		if err := ctl.ExcludePID(uint32(pid)); err != nil {
			log.Printf("[control] failed to exclude PID %d (%s): %v", pid, comm, err)
			continue
		}
		excluded++
	}

	return excluded, nil
}

// ── Hot path management ─────────────────────────────────────

// AddHotPath registers a path prefix for mandatory full reporting.
// Events matching this prefix will bypass kernel dedup.
// Examples: "/etc", "/root", "/tmp", "/home/*"
func (ctl *Controller) AddHotPath(prefix string) error {
	hash := fnv1a32(prefix)
	return ctl.hotPaths.Put(hash, uint32(1))
}

// RemoveHotPath removes a path prefix from the hot path map.
func (ctl *Controller) RemoveHotPath(prefix string) error {
	hash := fnv1a32(prefix)
	return ctl.hotPaths.Delete(hash)
}

// ClearHotPaths removes all hot path entries.
func (ctl *Controller) ClearHotPaths() error {
	// Iterate and delete all entries
	iter := ctl.hotPaths.Iterate()
	var key uint32
	for iter.Next(&key, nil) {
		if err := ctl.hotPaths.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

// fnv1a32 computes the FNV-1a hash of a string (matching kernel side).
func fnv1a32(s string) uint32 {
	var h uint32 = 2166136261
	for _, c := range []byte(s) {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}

// ── Stats ──────────────────────────────────────────────────

// Stats returns a snapshot of all three maps.
func (ctl *Controller) Stats() (stats map[string]interface{}) {
	stats = map[string]interface{}{
		"pid_whitelist_entries":  0,
		"tainted_processes":      0,
		"active_sample_counters": 0,
	}
	pidCount := 0
	defer func() {
		if recover() != nil {
			stats["pid_whitelist_entries"] = 0
			stats["tainted_processes"] = 0
			stats["active_sample_counters"] = 0
		}
	}()
	if ctl != nil && ctl.pidWhitelist != nil {
		iter := ctl.pidWhitelist.Iterate()
		var k uint32
		for iter.Next(&k, nil) {
			pidCount++
		}
	}

	taintCount := 0
	if ctl != nil && ctl.taintMap != nil {
		iter2 := ctl.taintMap.Iterate()
		var pid uint32
		for iter2.Next(&pid, nil) {
			taintCount++
		}
	}

	sampleCount := 0
	if ctl != nil && ctl.sampleCounters != nil {
		iter3 := ctl.sampleCounters.Iterate()
		var key uint64
		for iter3.Next(&key, nil) {
			sampleCount++
		}
	}

	stats["pid_whitelist_entries"] = pidCount
	stats["tainted_processes"] = taintCount
	stats["active_sample_counters"] = sampleCount
	return stats
}
