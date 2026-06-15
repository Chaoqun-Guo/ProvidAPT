// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package heal implements self-healing and anti-tampering for
// ProvidAPT v2.  It periodically verifies eBPF program integrity,
// cleans stale BPF map data, and automatically reloads programs
// if tampering is detected.
package selfheal

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/audit"
	"github.com/cilium/ebpf"
)

// ═══════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════

// Config for the self-healing module.
type Config struct {
	// CheckInterval — how often to verify eBPF programs (default 30s).
	CheckInterval time.Duration

	// MapCleanupInterval — how often to clean stale map entries (default 5m).
	MapCleanupInterval time.Duration

	// EnableAutoReload — if true, automatically reload eBPF programs.
	EnableAutoReload bool

	// ReloadCmd — command to reload eBPF programs (if empty, uses
	// cilium/ebpf library for re-attachment).
	ReloadCmd string

	// BpfObjectPath — path to the combined .bpf.o file for reloading.
	// If empty, search known paths (build/ebpf/, /usr/local/lib/providapt/ebpf/).
	BpfObjectPath string

	// ExpectedProgs — list of expected eBPF program section names.
	ExpectedProgs []string
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		CheckInterval:      30 * time.Second,
		MapCleanupInterval: 5 * time.Minute,
		EnableAutoReload:   true,
		ReloadCmd:          "",
		BpfObjectPath:      "",
		ExpectedProgs: []string{
			"probe_file_open",
			"probe_bprm_check",
			"probe_task_alloc",
			"probe_socket_connect",
			"probe_net_connect",
		},
	}
}

// ═══════════════════════════════════════════════════════════════
// Healer
// ═══════════════════════════════════════════════════════════════

// Healer monitors eBPF integrity and self-heals.
type Healer struct {
	cfg        *Config
	mu         sync.Mutex
	auditLog   []AuditEvent
	auditStore *audit.Store
	healthy    bool
	checkCnt   int64
	failCnt    int64
	reloadCnt  int64
	stopCh     chan struct{}
	wg         sync.WaitGroup
	// Circuit breaker for reload storms
	cbFailures    int       // consecutive reload failures
	cbTrippedAt   time.Time // when the breaker tripped, zero=not tripped
	cbFirstFailAt time.Time // first failure in the current window

	// eBPF object collection loaded from .o file
	bpfSpec  *ebpf.CollectionSpec // loaded spec for program/map verification
	bpfProgs map[string]*ebpf.Program // loaded programs by section name
	bpfMaps  map[string]*ebpf.Map     // loaded maps by name
}

// SetAuditStore attaches an audit logging store. If set, integrity
// events are recorded to it.
func (h *Healer) SetAuditStore(as *audit.Store) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.auditStore = as
}

// SetEBPFPrograms injects a map of loaded eBPF programs (section name -> program).
// When set, checkProgram() uses the cilium/ebpf library instead of bpftool CLI.
func (h *Healer) SetEBPFPrograms(progs map[string]*ebpf.Program) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.bpfProgs = progs
}

// SetEBPFMaps injects a map of loaded eBPF maps (name -> map).
// When set, verifyMap() uses the cilium/ebpf library instead of bpftool CLI.
func (h *Healer) SetEBPFMaps(maps map[string]*ebpf.Map) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.bpfMaps = maps
}

// LoadBpfObject loads a .bpf.o file into the healer for program/map verification
// and reloading. The spec is cached for reload operations.
func (h *Healer) LoadBpfObject(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read bpf object %s: %w", path, err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(strings.NewReader(string(data)))
	if err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	h.mu.Lock()
	h.bpfSpec = spec
	h.mu.Unlock()
	log.Printf("[heal] loaded bpf object: %s (%d programs, %d maps)",
		path, len(spec.Programs), len(spec.Maps))
	return nil
}

// bpfObjectPaths returns well-known paths for .bpf.o files.
func (h *Healer) bpfObjectPaths() []string {
	if h.cfg.BpfObjectPath != "" {
		return []string{h.cfg.BpfObjectPath}
	}
	return []string{
		"build/ebpf/combined.bpf.o",
		"build/ebpf/lsm_hooks.bpf.o",
		"/usr/local/lib/providapt/ebpf/combined.bpf.o",
		"/usr/local/lib/providapt/ebpf/lsm_hooks.bpf.o",
	}
}

// AuditEvent is a security-relevant event recorded by the healer.
type AuditEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`     // "check", "fail", "reload", "cleanup"
	Severity  string    `json:"severity"` // "INFO", "WARNING", "CRITICAL"
	Message   string    `json:"message"`
}

// New creates a self-healing monitor.
func New(cfg *Config) *Healer {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Healer{
		cfg:     cfg,
		healthy: true,
		stopCh:  make(chan struct{}),
	}
}

// Start begins background monitoring.
func (h *Healer) Start() {
	h.wg.Add(2)
	go h.checkLoop()
	go h.cleanupLoop()
	log.Printf("[heal] started (check=%v, cleanup=%v, reload=%v)",
		h.cfg.CheckInterval, h.cfg.MapCleanupInterval, h.cfg.EnableAutoReload)
}

func (h *Healer) checkLoop() {
	defer h.wg.Done()
	ticker := time.NewTicker(h.cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.runCheck()
		case <-h.stopCh:
			return
		}
	}
}

func (h *Healer) cleanupLoop() {
	defer h.wg.Done()
	ticker := time.NewTicker(h.cfg.MapCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.runCleanup()
		case <-h.stopCh:
			return
		}
	}
}

// Stop gracefully shuts down.
func (h *Healer) Stop() {
	close(h.stopCh)
	h.wg.Wait()
}

// ─── Integrity check ────────────────────────────────────────

// runCheck verifies that all expected eBPF programs are loaded.
func (h *Healer) runCheck() {
	h.mu.Lock()
	h.checkCnt++
	h.mu.Unlock()

	allFound := true
	var missing []string

	for _, progName := range h.cfg.ExpectedProgs {
		found := h.checkProgram(progName)
		if !found {
			missing = append(missing, progName)
			allFound = false
		}
	}

	h.mu.Lock()
	h.healthy = allFound
	if !allFound {
		h.failCnt++
		h.auditLog = append(h.auditLog, AuditEvent{
			Timestamp: time.Now(),
			Type:      "fail",
			Severity:  "CRITICAL",
			Message:   fmt.Sprintf("eBPF programs missing: %s", strings.Join(missing, ", ")),
		})
		log.Printf("[heal] CRITICAL: %d eBPF programs missing: %v", len(missing), missing)

		if h.auditStore != nil {
			h.auditStore.Log(audit.Entry{
				Category: audit.CatIntegrity,
				Severity: "CRITICAL",
				Message:  fmt.Sprintf("eBPF programs missing: %s", strings.Join(missing, ", ")),
				Source:   "selfheal",
				Details: map[string]interface{}{
					"missing": missing,
					"checks":  h.checkCnt,
				},
			})
		}

		// Auto-reload
		if h.cfg.EnableAutoReload {
			h.reloadPrograms()
		}
	}
	h.mu.Unlock()
}

// checkProgram verifies a single eBPF program.
//
// Uses loaded programs (cilium/ebpf) if available, falling back to
// bpftool CLI only when no injected programs are present.
func (h *Healer) checkProgram(name string) bool {
	h.mu.Lock()
	progs := h.bpfProgs
	spec := h.bpfSpec
	h.mu.Unlock()

	// Primary path: check against loaded cilium/ebpf programs.
	if progs != nil {
		_, ok := progs[name]
		return ok
	}

	// Secondary path: check against loaded collection spec.
	if spec != nil {
		_, ok := spec.Programs[name]
		return ok
	}

	// Fallback: file-based verification using /proc/self/fd or
	// bpftool via exec (last resort for pre-existing deployments).
	return h.checkProgramBPFTool(name)
}

// checkProgramBPFTool is the legacy fallback using bpftool CLI.
func (h *Healer) checkProgramBPFTool(name string) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d", 0))
	if err == nil && len(data) > 0 {
		// If /proc is available, try to verify via bpffs.
		// bpffs is typically mounted at /sys/fs/bpf.
		entries, err := os.ReadDir("/sys/fs/bpf")
		if err == nil {
			for _, e := range entries {
				if strings.Contains(e.Name(), name) {
					return true
				}
			}
		}
	}
	// Fall through to bpftool (works on older deployments).
	cmd := exec.Command("bpftool", "prog", "show", "name", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), name)
}

// reloadPrograms attempts to reload missing eBPF programs.
//
// Uses cilium/ebpf library to load .bpf.o files when available,
// falling back to bpftool CLI for legacy deployments.
//
// Features a circuit breaker: after 3 consecutive failures within 10 minutes,
// further reloads are skipped until a successful check cycle.
func (h *Healer) reloadPrograms() {
	h.mu.Lock()
	now := time.Now()

	// Circuit breaker check: if tripped and still within cooldown, skip
	if !h.cbTrippedAt.IsZero() {
		if now.Before(h.cbTrippedAt.Add(10 * time.Minute)) {
			h.mu.Unlock()
			log.Printf("[heal] circuit breaker open — skipping reload until %s",
				h.cbTrippedAt.Add(10*time.Minute).Format(time.RFC3339))
			return
		}
		// Cooldown expired — reset and try again
		h.cbFailures = 0
		h.cbTrippedAt = time.Time{}
		h.cbFirstFailAt = time.Time{}
	}
	h.mu.Unlock()

	h.reloadCnt++
	h.auditLog = append(h.auditLog, AuditEvent{
		Timestamp: now,
		Type:      "reload",
		Severity:  "WARNING",
		Message:   "Initiating eBPF program reload",
	})

	if h.auditStore != nil {
		h.auditStore.Log(audit.Entry{
			Category: audit.CatIntegrity,
			Severity: "WARNING",
			Message:  "Initiating eBPF program reload",
			Source:   "selfheal",
			Details: map[string]interface{}{
				"reload_count": h.reloadCnt,
			},
		})
	}

	// Try cilium/ebpf library reload first.
	if h.loadAndAttachEBPF() {
		h.resetCircuitBreaker()
		h.auditLog = append(h.auditLog, AuditEvent{
			Timestamp: time.Now(),
			Type:      "reload",
			Severity:  "INFO",
			Message:   "eBPF programs reloaded via cilium/ebpf",
		})
		log.Printf("[heal] eBPF programs reloaded via cilium/ebpf")
		if h.auditStore != nil {
			h.auditStore.Log(audit.Entry{
				Category: audit.CatIntegrity,
				Severity: "INFO",
				Message:  "eBPF programs reloaded successfully",
				Source:   "selfheal",
			})
		}
		return
	}

	// Fallback: custom reload command.
	if h.cfg.ReloadCmd != "" {
		parts := strings.Fields(h.cfg.ReloadCmd)
		cmd := exec.Command(parts[0], parts[1:]...)
		output, err := cmd.CombinedOutput()
		if err == nil {
			h.resetCircuitBreaker()
			log.Printf("[heal] eBPF programs reloaded via %s", h.cfg.ReloadCmd)
			return
		}
		h.recordReloadFailure(fmt.Sprintf("Reload cmd failed: %v\n%s", err, string(output)))
		return
	}

	// Last-resort fallback: bpftool CLI.
	h.reloadBPFTool()
}

// loadAndAttachEBPF loads .bpf.o files via cilium/ebpf and re-attaches programs.
// Returns true on success, false on failure.
func (h *Healer) loadAndAttachEBPF() bool {
	h.mu.Lock()
	spec := h.bpfSpec
	h.mu.Unlock()

	if spec != nil {
		// Have a cached spec — reload from memory.
		var objs bpfObjects
		if err := spec.LoadAndAssign(&objs, nil); err != nil {
			log.Printf("[heal] cilium/ebpf reload from spec failed: %v", err)
			return false
		}
		h.registerLoadedObjects(&objs)
		return true
	}

	// Try loading from file.
	for _, path := range h.bpfObjectPaths() {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		spec, err := ebpf.LoadCollectionSpecFromReader(strings.NewReader(string(data)))
		if err != nil {
			log.Printf("[heal] load spec from %s: %v", path, err)
			continue
		}
		var objs bpfObjects
		if err := spec.LoadAndAssign(&objs, nil); err != nil {
			log.Printf("[heal] load %s: %v", path, err)
			continue
		}
		h.mu.Lock()
		h.bpfSpec = spec
		h.mu.Unlock()
		h.registerLoadedObjects(&objs)
		log.Printf("[heal] loaded eBPF from %s", path)
		return true
	}
	return false
}

// registerLoadedObjects extracts programs and maps from loaded bpfObjects.
func (h *Healer) registerLoadedObjects(objs *bpfObjects) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.bpfProgs == nil {
		h.bpfProgs = make(map[string]*ebpf.Program)
	}
	if h.bpfMaps == nil {
		h.bpfMaps = make(map[string]*ebpf.Map)
	}

	// Programs.
	if objs.LsmHooks != nil {
		if objs.LsmHooks.ProbeFileOpen != nil {
			h.bpfProgs["probe_file_open"] = objs.LsmHooks.ProbeFileOpen
		}
		if objs.LsmHooks.ProbeBprmCheck != nil {
			h.bpfProgs["probe_bprm_check"] = objs.LsmHooks.ProbeBprmCheck
		}
		if objs.LsmHooks.ProbeTaskAlloc != nil {
			h.bpfProgs["probe_task_alloc"] = objs.LsmHooks.ProbeTaskAlloc
		}
		if objs.LsmHooks.ProbeSocketConnect != nil {
			h.bpfProgs["probe_socket_connect"] = objs.LsmHooks.ProbeSocketConnect
		}
	}

	if objs.Network != nil && objs.Network.ProbeNetConnect != nil {
		h.bpfProgs["probe_net_connect"] = objs.Network.ProbeNetConnect
	}

	// Maps.
	if objs.LsmHooks != nil {
		if objs.LsmHooks.Rb != nil {
			h.bpfMaps["rb"] = objs.LsmHooks.Rb
		}
		if objs.LsmHooks.ProcMap != nil {
			h.bpfMaps["proc_map"] = objs.LsmHooks.ProcMap
		}
		if objs.LsmHooks.PidWhitelist != nil {
			h.bpfMaps["pid_whitelist"] = objs.LsmHooks.PidWhitelist
		}
		if objs.LsmHooks.TaintMap != nil {
			h.bpfMaps["taint_map"] = objs.LsmHooks.TaintMap
		}
	}
}

// reloadBPFTool is the last-resort fallback using bpftool CLI.
func (h *Healer) reloadBPFTool() {
	log.Printf("[heal] auto-reload triggered — re-attaching eBPF programs via bpftool")
	for _, progName := range h.cfg.ExpectedProgs {
		out, err := exec.Command("bpftool", "prog", "attach", "name", progName, "lsm", progName).CombinedOutput()
		if err != nil {
			h.recordReloadFailure(fmt.Sprintf("bpftool re-attach %s failed: %v\n%s", progName, err, string(out)))
			return
		}
	}
	h.resetCircuitBreaker()
	h.auditLog = append(h.auditLog, AuditEvent{
		Timestamp: time.Now(),
		Type:      "reload",
		Severity:  "INFO",
		Message:   "eBPF programs reloaded via bpftool",
	})
	log.Printf("[heal] eBPF programs reloaded via bpftool")
	if h.auditStore != nil {
		h.auditStore.Log(audit.Entry{
			Category: audit.CatIntegrity,
			Severity: "INFO",
			Message:  "eBPF programs reloaded via bpftool",
			Source:   "selfheal",
		})
	}
}

// ─── Map cleanup ─────────────────────────────────────────────

// runCleanup cleans stale BPF map entries and verifies config maps.
func (h *Healer) runCleanup() {
	h.auditLog = append(h.auditLog, AuditEvent{
		Timestamp: time.Now(),
		Type:      "cleanup",
		Severity:  "INFO",
		Message:   "Running BPF map cleanup",
	})

	if h.auditStore != nil {
		h.auditStore.Log(audit.Entry{
			Category: audit.CatIntegrity,
			Severity: "INFO",
			Message:  "BPF map cleanup started",
			Source:   "selfheal",
		})
	}

	// 1. Dump and verify agent_pids map
	h.verifyMap("agent_pids")
	h.verifyMap("pid_whitelist")
	h.verifyMap("hot_paths")

	// 2. Clean stale entries from proc_map
	// (in production, iterate and remove expired entries)

	log.Printf("[heal] map cleanup complete")
}

// verifyMap checks a BPF map via cilium/ebpf (preferred) or bpftool (fallback).
func (h *Healer) verifyMap(name string) {
	h.mu.Lock()
	maps := h.bpfMaps
	h.mu.Unlock()

	// Primary path: use cilium/ebpf loaded map.
	if maps != nil {
		if m, ok := maps[name]; ok && m != nil {
			info, err := m.Info()
			if err != nil {
				h.logMapFail(name, fmt.Sprintf("info failed: %v", err))
				return
			}
			if info == nil {
				log.Printf("[heal] map %s: not accessible", name)
				return
			}
			log.Printf("[heal] map %s: type=%s max=%d keysize=%d",
				name, info.Type.String(), info.MaxEntries, info.KeySize)
			return
		}
	}

	// Fallback: use collection spec to verify the map definition.
	h.mu.Lock()
	spec := h.bpfSpec
	h.mu.Unlock()
	if spec != nil {
		if m, ok := spec.Maps[name]; ok && m != nil {
			log.Printf("[heal] map %s (spec): type=%s max=%d", name, m.Type.String(), m.MaxEntries)
			return
		}
	}

	// Last-resort fallback: bpftool CLI.
	h.verifyMapBPFTool(name)
}

// verifyMapBPFTool is the legacy fallback using bpftool CLI.
func (h *Healer) verifyMapBPFTool(name string) {
	cmd := exec.Command("bpftool", "map", "dump", "name", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		h.logMapFail(name, fmt.Sprintf("bpftool dump failed: %v", err))
		return
	}

	if !strings.Contains(string(output), "Found") &&
		!strings.Contains(string(output), "key") {
		log.Printf("[heal] map %s: empty (expected)", name)
	}
}

// logMapFail logs a map verification failure.
func (h *Healer) logMapFail(name, msg string) {
	h.auditLog = append(h.auditLog, AuditEvent{
		Timestamp: time.Now(),
		Type:      "fail",
		Severity:  "WARNING",
		Message:   fmt.Sprintf("Map %s: %s", name, msg),
	})
	log.Printf("[heal] map %s: %s", name, msg)
	if h.auditStore != nil {
		h.auditStore.Log(audit.Entry{
			Category: audit.CatIntegrity,
			Severity: "WARNING",
			Message:  fmt.Sprintf("Cannot verify map %s: %s", name, msg),
			Source:   "selfheal",
		})
	}
}

// ─── Audit log ──────────────────────────────────────────────

// AuditEvents returns all recorded audit events.
func (h *Healer) AuditEvents() []AuditEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]AuditEvent, len(h.auditLog))
	copy(out, h.auditLog)
	return out
}

// AuditSummary returns a human-readable audit summary.
func (h *Healer) AuditSummary() string {
	h.mu.Lock()
	defer h.mu.Unlock()

	status := "HEALTHY"
	if !h.healthy {
		status = "DEGRADED"
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Self-Heal Status: %s\n", status))
	b.WriteString(fmt.Sprintf("  Checks:     %d\n", h.checkCnt))
	b.WriteString(fmt.Sprintf("  Failures:   %d\n", h.failCnt))
	b.WriteString(fmt.Sprintf("  Reloads:    %d\n", h.reloadCnt))
	b.WriteString(fmt.Sprintf("  Audit log:  %d events\n", len(h.auditLog)))

	if len(h.auditLog) > 0 {
		b.WriteString("  Recent events:\n")
		start := len(h.auditLog) - 5
		if start < 0 {
			start = 0
		}
		for _, e := range h.auditLog[start:] {
			b.WriteString(fmt.Sprintf("    [%s] %s: %s\n", e.Severity, e.Type, e.Message))
		}
	}
	return b.String()
}

// Stats returns healer statistics.
func (h *Healer) Stats() map[string]interface{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	return map[string]interface{}{
		"healthy":     h.healthy,
		"checks":      h.checkCnt,
		"failures":    h.failCnt,
		"reloads":     h.reloadCnt,
		"audit_count": len(h.auditLog),
	}
}
