// Package armor provides anti-rootkit defence mechanisms for
// ProvidAPT's eBPF monitoring infrastructure.
//
// It protects against attacks that try to disable or bypass
// eBPF monitoring, including:
//
//   1. Map integrity audit — detect unauthorised modifications
//      to BPF maps via iter programs.
//
//   2. Kernel symbol monitoring — detect unknown modules or
//      ftrace hooks that may be intercepting data flow.
//
//   3. Shadow monitoring — two mutually-watching eBPF modules
//      that detect if the primary monitor is tampered with.
package armor

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/audit"
)

// ═══════════════════════════════════════════════════════════════
// Map integrity audit
// ═══════════════════════════════════════════════════════════════

// AuditRecord captures the state of a single BPF map entry.
type AuditRecord struct {
	MapName  string `json:"map_name"`
	Key      string `json:"key"`
	Value    string `json:"value"`
	Expected string `json:"expected,omitempty"`
	Match    bool   `json:"match"`
}

// MapAuditor periodically checks BPF map integrity.
type MapAuditor struct {
	mu         sync.Mutex
	records    []AuditRecord
	anomalies  []AuditRecord
	checkPIDs  map[uint32]bool // known-good PID set
	auditStore *audit.Store
}

// SetAuditStore attaches an audit logging store.
func (ma *MapAuditor) SetAuditStore(as *audit.Store) {
	ma.mu.Lock()
	defer ma.mu.Unlock()
	ma.auditStore = as
}

// NewMapAuditor creates a map auditor.
func NewMapAuditor() *MapAuditor {
	return &MapAuditor{
		checkPIDs: make(map[uint32]bool),
	}
}

// RegisterKnownPID marks a PID as a known-good agent entry.
func (ma *MapAuditor) RegisterKnownPID(pid uint32) {
	ma.mu.Lock()
	defer ma.mu.Unlock()
	ma.checkPIDs[pid] = true
}

// AuditAgentMap checks the agent_pids BPF map for unexpected entries.
// In production, this reads from the actual BPF map via bpftool.
// Here we provide the audit logic framework.
func (ma *MapAuditor) AuditAgentMap() ([]AuditRecord, error) {
	ma.mu.Lock()
	defer ma.mu.Unlock()

	var records []AuditRecord

	// Dump the BPF map using bpftool (requires root)
	output, err := exec.Command("bpftool", "map", "dump",
		"pinned", "/sys/fs/bpf/providapt/agent_pids",
	).Output()
	if err != nil {
		// Fallback: try by name
		output, err = exec.Command("bpftool", "map", "dump",
			"name", "agent_pids",
		).Output()
		if err != nil {
			return nil, fmt.Errorf("bpftool dump: %w", err)
		}
	}

	// Parse output to find unexpected entries
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if !strings.Contains(line, "key:") {
			continue
		}
		// Extract PID from "key: 1234  value: 1"
		var pid uint32
		fmt.Sscanf(line, `key: %d`, &pid)

		record := AuditRecord{
			MapName:  "agent_pids",
			Key:      fmt.Sprintf("%d", pid),
			Value:    "present",
			Expected: "known agent",
		}

		if _, ok := ma.checkPIDs[pid]; ok {
			record.Match = true
		} else {
			record.Match = false
			ma.anomalies = append(ma.anomalies, record)
			log.Printf("[armor] MAP ANOMALY: unexpected PID %d in agent_pids", pid)
		}

		records = append(records, record)
	}

	return records, nil
}

// Anomalies returns the list of detected anomalies.
func (ma *MapAuditor) Anomalies() []AuditRecord {
	ma.mu.Lock()
	defer ma.mu.Unlock()
	out := make([]AuditRecord, len(ma.anomalies))
	copy(out, ma.anomalies)

	if len(out) > 0 && ma.auditStore != nil {
		details := make([]map[string]interface{}, 0, len(out))
		for _, a := range out {
			details = append(details, map[string]interface{}{
				"map_name": a.MapName,
				"key":      a.Key,
				"value":    a.Value,
				"expected": a.Expected,
				"match":    a.Match,
			})
		}
		ma.auditStore.Log(audit.Entry{
			Category: audit.CatSecurity,
			Severity: "WARNING",
			Message:  fmt.Sprintf("BPF map audit: %d anomalies detected", len(out)),
			Source:   "armor",
			Details: map[string]interface{}{
				"anomalies": details,
			},
		})
	}

	return out
}

// AnomalyCount returns the number of detected anomalies.
func (ma *MapAuditor) AnomalyCount() int {
	ma.mu.Lock()
	defer ma.mu.Unlock()
	return len(ma.anomalies)
}

// ═══════════════════════════════════════════════════════════════
// Kernel symbol table monitoring
// ═══════════════════════════════════════════════════════════════

// KallsymsSnapshot is a point-in-time snapshot of /proc/kallsyms.
type KallsymsSnapshot struct {
	Symbols map[string]uint64 // name → address
	Count   int
	Time    time.Time
}

// KallsymsMonitor watches /proc/kallsyms for changes.
type KallsymsMonitor struct {
	mu         sync.Mutex
	baseline   *KallsymsSnapshot
	anomalies  []string
	auditStore *audit.Store
}

// SetAuditStore attaches an audit logging store.
func (km *KallsymsMonitor) SetAuditStore(as *audit.Store) {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.auditStore = as
}

// NewKallsymsMonitor creates a kallsyms monitor.
func NewKallsymsMonitor() *KallsymsMonitor {
	return &KallsymsMonitor{}
}

// Capture reads and parses /proc/kallsyms.
func (km *KallsymsMonitor) Capture() (*KallsymsSnapshot, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, fmt.Errorf("open kallsyms: %w", err)
	}
	defer f.Close()

	snap := &KallsymsSnapshot{
		Symbols: make(map[string]uint64),
		Time:    time.Now(),
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		var addr uint64
		fmt.Sscanf(parts[0], "%x", &addr)
		if addr != 0 {
			snap.Symbols[parts[2]] = addr
		}
	}
	snap.Count = len(snap.Symbols)

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return snap, nil
}

// TakeBaseline captures the initial reference snapshot.
func (km *KallsymsMonitor) TakeBaseline() error {
	snap, err := km.Capture()
	if err != nil {
		return err
	}
	km.mu.Lock()
	km.baseline = snap
	km.mu.Unlock()
	log.Printf("[armor] kallsyms baseline: %d symbols", snap.Count)
	return nil
}

// Diff compares the current kallsyms against the baseline.
// Returns any new symbols that appeared.
func (km *KallsymsMonitor) Diff() ([]string, error) {
	km.mu.Lock()
	baseline := km.baseline
	km.mu.Unlock()

	if baseline == nil {
		return nil, fmt.Errorf("baseline not taken")
	}

	current, err := km.Capture()
	if err != nil {
		return nil, err
	}

	var changes []string
	for name, addr := range current.Symbols {
		if _, ok := baseline.Symbols[name]; !ok {
			// New symbol
			change := fmt.Sprintf("NEW: %s @ 0x%x", name, addr)
			changes = append(changes, change)
			km.anomalies = append(km.anomalies, change)
		}
	}

	// Check for removed symbols (unlikely but possible with module unload)
	for name := range baseline.Symbols {
		if _, ok := current.Symbols[name]; !ok {
			change := fmt.Sprintf("REMOVED: %s", name)
			changes = append(changes, change)
			km.anomalies = append(km.anomalies, change)
		}
	}

	if len(changes) > 0 {
		log.Printf("[armor] KALLSYMS CHANGES: %d", len(changes))
		for _, c := range changes {
			log.Printf("[armor]   %s", c)
		}
	}

	return changes, nil
}

// CheckSecurityHooks verifies that ProvidAPT's LSM hooks are still
// in place by checking key security_* symbols.
func (km *KallsymsMonitor) CheckSecurityHooks() []string {
	var issues []string
	keyHooks := []string{
		"security_file_open",
		"security_file_permission",
		"security_bprm_check",
		"security_task_alloc",
		"security_socket_connect",
	}

	current, err := km.Capture()
	if err != nil {
		return []string{fmt.Sprintf("capture error: %v", err)}
	}

	for _, hook := range keyHooks {
		if _, ok := current.Symbols[hook]; !ok {
			issues = append(issues, fmt.Sprintf("MISSING: %s", hook))
		}
	}
	return issues
}

// Anomalies returns detected kallsyms anomalies.
func (km *KallsymsMonitor) Anomalies() []string {
	km.mu.Lock()
	defer km.mu.Unlock()
	out := make([]string, len(km.anomalies))
	copy(out, km.anomalies)
	return out
}

// ─── ftrace check ───────────────────────────────────────────

// CheckFtraceTrampoline checks if ftrace is being used to intercept
// ProvidAPT's hook functions.
func CheckFtraceTrampoline() ([]string, error) {
	data, err := os.ReadFile("/sys/kernel/tracing/enabled_functions")
	if err != nil {
		return nil, fmt.Errorf("read enabled_functions: %w", err)
	}

	var issues []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "security_file_open") ||
			strings.Contains(line, "security_bprm_check") {
			// Check if it's our own filter
			if !strings.Contains(line, "providapt") {
				issues = append(issues, fmt.Sprintf(
					"FTRACE HOOK: %s (non-providapt tracer active)", line))
			}
		}
	}
	return issues, nil
}
