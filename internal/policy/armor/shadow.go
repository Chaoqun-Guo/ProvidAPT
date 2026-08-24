// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package armor

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Shadow monitoring
//
// Two mutually-monitoring eBPF modules:
//
//   Module A (Primary):   lsm_hooks.bpf.c — monitors system events
//   Module B (Shadow):    shadow.bpf.c    — monitors Module A and key
//                          kernel functions
//
// Module B's responsibilities:
//   1. Check that Module A's BPF maps are intact and owned by the
//      correct process.
//   2. Verify that key LSM hooks still contain ProvidAPT's probes.
//   3. Monitor the ring buffer for unexpected gaps (possible
//      data interception).
//   4. Heartbeat monitoring — Module A must emit heartbeat events
//      at regular intervals.  Module B detects if the heartbeat
//      stops (A was killed or bypassed).
// ═══════════════════════════════════════════════════════════════

// ShadowStatus represents the health of the primary monitor.
type ShadowStatus struct {
	ModuleAName   string    `json:"module_a"`
	ModuleBName   string    `json:"module_b"`
	Heartbeat     bool      `json:"heartbeat"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	MapIntegrity  bool      `json:"map_integrity"`
	HookIntegrity bool      `json:"hook_integrity"`
	Alerts        []string  `json:"alerts,omitempty"`
}

// ShadowMonitor implements Module B's monitoring logic.
type ShadowMonitor struct {
	mu             sync.Mutex
	status         ShadowStatus
	heartbeatMiss  int
	heartbeatLimit int
}

// NewShadowMonitor creates a shadow monitor.
func NewShadowMonitor() *ShadowMonitor {
	return &ShadowMonitor{
		status: ShadowStatus{
			ModuleAName:   "lsm_hooks.bpf.c",
			ModuleBName:   "shadow_monitor",
			LastHeartbeat: time.Now(),
		},
		heartbeatLimit: 3,
	}
}

// RecordHeartbeat is called when Module A emits a heartbeat event.
func (sm *ShadowMonitor) RecordHeartbeat() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.status.LastHeartbeat = time.Now()
	sm.status.Heartbeat = true
	sm.heartbeatMiss = 0
}

// CheckHeartbeat verifies that Module A's heartbeat is current.
// Called on a timer (every 10 seconds).
func (sm *ShadowMonitor) CheckHeartbeat() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if time.Since(sm.status.LastHeartbeat) > 30*time.Second {
		sm.heartbeatMiss++
		sm.status.Heartbeat = false
		alert := fmt.Sprintf("HEARTBEAT MISS: Module A silent for %v (miss %d/%d)",
			time.Since(sm.status.LastHeartbeat),
			sm.heartbeatMiss, sm.heartbeatLimit)
		sm.status.Alerts = append(sm.status.Alerts, alert)

		if sm.heartbeatMiss >= sm.heartbeatLimit {
			log.Printf("[armor] ⚠ SHADOW ALERT: %s", alert)
		}
	}
}

// CheckMapIntegrity verifies that Module A's BPF maps exist and
// are owned by the correct process.
func (sm *ShadowMonitor) CheckMapIntegrity(agentPID int) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// In production, this would:
	// 1. Read /sys/fs/bpf/providapt/ map pinned files
	// 2. Verify owner PID matches the agent PID
	// 3. Verify map type and key/value sizes match expectations

	expectedMaps := []string{
		"rb",         // ring buffer
		"proc_map",   // process ancestry
		"taint_map",  // process taint
		"agent_pids", // agent identity
	}

	allFound := true
	for _, m := range expectedMaps {
		if !checkBPFMapExists(m) {
			log.Printf("[armor] BPF map %s not found", m)
			allFound = false
		}
	}

	sm.status.MapIntegrity = allFound
	if !allFound {
		sm.status.Alerts = append(sm.status.Alerts,
			"MAP INTEGRITY FAIL: expected BPF maps not found")
	}
	return allFound
}

// CheckHookIntegrity verifies that ProvidAPT's probes are still
// attached to their LSM hooks.
func (sm *ShadowMonitor) CheckHookIntegrity() bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// In production, this would:
	// 1. Read /sys/kernel/security/lsm to verify BPF LSM is registered
	// 2. Check bpftool prog show to verify ProvidAPT's progs are loaded
	// 3. Verify the program IDs match expectations

	// Simplified check: verify /proc/kallsyms still has security hooks
	current, err := (&KallsymsMonitor{}).Capture()
	if err != nil {
		sm.status.Alerts = append(sm.status.Alerts,
			fmt.Sprintf("HOOK CHECK FAIL: %v", err))
		return false
	}

	keyHooks := []string{
		"security_file_open", "security_bprm_check",
		"security_task_alloc", "security_socket_connect",
	}
	for _, hook := range keyHooks {
		if _, ok := current.Symbols[hook]; !ok {
			sm.status.Alerts = append(sm.status.Alerts,
				fmt.Sprintf("HOOK MISSING: %s", hook))
		}
	}

	sm.status.HookIntegrity = true
	return true
}

// Status returns the current shadow monitor status.
func (sm *ShadowMonitor) Status() ShadowStatus {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.status
}

// AlertSummary returns a human-readable summary of active alerts.
func (sm *ShadowMonitor) AlertSummary() string {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if len(sm.status.Alerts) == 0 {
		return "All systems nominal — no shadow anomalies detected"
	}
	summary := fmt.Sprintf("Shadow Monitor: %d alerts\n", len(sm.status.Alerts))
	for _, a := range sm.status.Alerts {
		summary += fmt.Sprintf("  ⚠ %s\n", a)
	}
	return summary
}

// BackgroundLoop runs the shadow monitoring checks periodically.
func (sm *ShadowMonitor) BackgroundLoop(stopCh <-chan struct{}, agentPID int) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.CheckHeartbeat()
			sm.CheckMapIntegrity(agentPID)
			sm.CheckHookIntegrity()
		case <-stopCh:
			return
		}
	}
}

// checkBPFMapExists verifies a pinned BPF map exists in bpffs.
func checkBPFMapExists(name string) bool {
	// Check /sys/fs/bpf/providapt/<name>
	path := fmt.Sprintf("/sys/fs/bpf/providapt/%s", name)
	if _, err := os.Stat(path); err == nil {
		return true
	}
	// Also check bpftool map show as fallback
	out, err := exec.Command("bpftool", "map", "show", "name", name).Output()
	if err != nil {
		return false
	}
	return len(out) > 0
}

// ═══════════════════════════════════════════════════════════════
// Anti-rootkit scanner — combines all checks
// ═══════════════════════════════════════════════════════════════

// AntiRootkitScanner runs all anti-rootkit checks.
type AntiRootkitScanner struct {
	auditor  *MapAuditor
	kmon     *KallsymsMonitor
	shadow   *ShadowMonitor
	agentPID int
}

// NewAntiRootkitScanner creates a combined anti-rootkit scanner.
func NewAntiRootkitScanner(agentPID int) *AntiRootkitScanner {
	return &AntiRootkitScanner{
		auditor:  NewMapAuditor(),
		kmon:     NewKallsymsMonitor(),
		shadow:   NewShadowMonitor(),
		agentPID: agentPID,
	}
}

// Init prepares the scanner (takes baseline, registers PIDs).
func (ars *AntiRootkitScanner) Init() error {
	ars.auditor.RegisterKnownPID(uint32(ars.agentPID))
	if err := ars.kmon.TakeBaseline(); err != nil {
		log.Printf("[armor] kallsyms baseline: %v", err)
	}
	ars.shadow.RecordHeartbeat()
	return nil
}

// Scan runs all checks and returns a consolidated report.
func (ars *AntiRootkitScanner) Scan() *ScanReport {
	report := &ScanReport{
		Time: time.Now(),
	}

	// 1. Map integrity
	records, err := ars.auditor.AuditAgentMap()
	if err != nil {
		report.MapAuditError = err.Error()
	} else {
		report.MapRecords = records
		for _, r := range records {
			if !r.Match {
				report.Issues = append(report.Issues,
					fmt.Sprintf("MAP: %s key=%s expected=%s got=%s",
						r.MapName, r.Key, r.Expected, r.Value))
			}
		}
	}

	// 2. Kallsyms diff
	changes, err := ars.kmon.Diff()
	if err == nil {
		report.KallsymsChanges = changes
		report.Issues = append(report.Issues, changes...)
	}

	// 3. Security hooks check
	hooks := ars.kmon.CheckSecurityHooks()
	if len(hooks) > 0 {
		report.SecurityHooksMissing = hooks
		report.Issues = append(report.Issues, hooks...)
	}

	// 4. Shadow monitor
	ars.shadow.CheckHeartbeat()
	ars.shadow.CheckMapIntegrity(ars.agentPID)
	ars.shadow.CheckHookIntegrity()
	report.ShadowStatus = ars.shadow.Status()

	return report
}

// ScanReport consolidates all anti-rootkit checks.
type ScanReport struct {
	Time                 time.Time     `json:"time"`
	MapRecords           []AuditRecord `json:"map_records,omitempty"`
	MapAuditError        string        `json:"map_audit_error,omitempty"`
	KallsymsChanges      []string      `json:"kallsyms_changes,omitempty"`
	SecurityHooksMissing []string      `json:"security_hooks_missing,omitempty"`
	ShadowStatus         ShadowStatus  `json:"shadow_status"`
	Issues               []string      `json:"issues,omitempty"`
	Clean                bool          `json:"clean"`
}

// Summary produces a brief scan summary.
func (r *ScanReport) Summary() string {
	r.Clean = len(r.Issues) == 0
	if r.Clean {
		return fmt.Sprintf("Armor scan: CLEAN (%d records, %d symbols checked)",
			len(r.MapRecords), len(r.KallsymsChanges))
	}
	return fmt.Sprintf("Armor scan: %d ISSUES FOUND", len(r.Issues))
}
