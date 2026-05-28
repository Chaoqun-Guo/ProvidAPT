// Package control provides dynamic runtime control over the eBPF
// kernel programs — allowing userspace to inject PID/path whitelist
// entries, read taint state, and query sampling statistics without
// reloading the BPF programs.
package control

import (
	"fmt"
	"log"
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
	for mask, name := range taintNames {
		if flags&mask != 0 {
			if s != "" {
				s += "|"
			}
			s += name
		}
	}
	return s
}

// ─── Controller ─────────────────────────────────────────────

// Controller manages the three optimisation maps exposed by the
// eBPF LSM programs:
//
//   pid_whitelist   — PIDs to exclude from monitoring entirely
//   taint_map       — per-process taint flags (read-only from userspace)
//   sample_counters — adaptive sampling counters (read-only)
type Controller struct {
	mu             sync.Mutex
	pidWhitelist   *ebpf.Map
	taintMap       *ebpf.Map
	sampleCounters *ebpf.Map
}

// New creates a Controller from loaded eBPF objects.
func New(pidWhitelist, taintMap, sampleCounters *ebpf.Map) *Controller {
	return &Controller{
		pidWhitelist:   pidWhitelist,
		taintMap:       taintMap,
		sampleCounters: sampleCounters,
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
// whitelist.  This should be called AFTER process discovery.
// In practice, userspace monitors fork events and adds PIDs
// matching known comm names.
func (ctl *Controller) DefaultExcludes() error {
	noisyComms := []string{
		"yum", "dnf", "apt", "dpkg", "rpm",
		"make", "gcc", "cc", "g++", "clang",
		"systemd-journal", "systemd-resolve",
		"cron", "anacron", "systemd-tmpfiles",
		"updatedb", "locate", "plocate",
		"mandb", "catman",
	}
	// Note: We can't resolve comm→PID without scanning /proc.
	// This is a placeholder — the actual implementation should
	// watch for fork events with these comm names and add their PIDs.
	log.Printf("[control] default excludes configured for %d comms; "+
		"PIDs must be resolved dynamically via /proc scan", len(noisyComms))
	for _, c := range noisyComms {
		log.Printf("  exclude-by-comm: %s", c)
	}
	return nil
}

// ── Stats ──────────────────────────────────────────────────

// Stats returns a snapshot of all three maps.
func (ctl *Controller) Stats() map[string]interface{} {
	pidCount := 0
	iter := ctl.pidWhitelist.Iterate()
	var k uint32
	for iter.Next(&k, nil) {
		pidCount++
	}

	taintCount := 0
	iter2 := ctl.taintMap.Iterate()
	var pid uint32
	for iter2.Next(&pid, nil) {
		taintCount++
	}

	sampleCount := 0
	iter3 := ctl.sampleCounters.Iterate()
	var key uint64
	for iter3.Next(&key, nil) {
		sampleCount++
	}

	return map[string]interface{}{
		"pid_whitelist_entries":   pidCount,
		"tainted_processes":       taintCount,
		"active_sample_counters":  sampleCount,
	}
}
