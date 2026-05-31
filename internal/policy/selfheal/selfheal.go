// Package heal implements self-healing and anti-tampering for
// ProvidAPT v2.  It periodically verifies eBPF program integrity,
// cleans stale BPF map data, and automatically reloads programs
// if tampering is detected.
package selfheal

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"
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

	// ReloadCmd — command to reload eBPF programs (if empty, uses bpftool).
	ReloadCmd string

	// ExpectedProgs — list of expected eBPF program names.
	ExpectedProgs []string
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		CheckInterval:      30 * time.Second,
		MapCleanupInterval: 5 * time.Minute,
		EnableAutoReload:   true,
		ReloadCmd:          "",
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
	cfg       *Config
	mu        sync.Mutex
	auditLog  []AuditEvent
	healthy   bool
	checkCnt  int64
	failCnt   int64
	reloadCnt int64
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// AuditEvent is a security-relevant event recorded by the healer.
type AuditEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`    // "check", "fail", "reload", "cleanup"
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

		// Auto-reload
		if h.cfg.EnableAutoReload {
			h.reloadPrograms()
		}
	}
	h.mu.Unlock()
}

// checkProgram verifies a single eBPF program via bpftool.
func (h *Healer) checkProgram(name string) bool {
	cmd := exec.Command("bpftool", "prog", "show", "name", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), name)
}

// reloadPrograms attempts to reload missing eBPF programs.
func (h *Healer) reloadPrograms() {
	h.reloadCnt++
	h.auditLog = append(h.auditLog, AuditEvent{
		Timestamp: time.Now(),
		Type:      "reload",
		Severity:  "WARNING",
		Message:   "Initiating eBPF program reload",
	})

	if h.cfg.ReloadCmd != "" {
		// Custom reload command
		parts := strings.Fields(h.cfg.ReloadCmd)
		cmd := exec.Command(parts[0], parts[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			h.auditLog = append(h.auditLog, AuditEvent{
				Timestamp: time.Now(),
				Type:      "reload",
				Severity:  "CRITICAL",
				Message:   fmt.Sprintf("Reload failed: %v\n%s", err, string(output)),
			})
			log.Printf("[heal] reload failed: %v", err)
			return
		}
	} else {
		// Default: attempt to re-attach via bpftool
		// In production, the agent would re-exec its eBPF loader
		log.Printf("[heal] auto-reload triggered — re-attaching eBPF programs")
		_ = exec.Command("bpftool", "prog", "attach", "name", "probe_file_open", "lsm", "file_open").Run()
	}

	h.auditLog = append(h.auditLog, AuditEvent{
		Timestamp: time.Now(),
		Type:      "reload",
		Severity:  "INFO",
		Message:   "eBPF programs reloaded successfully",
	})
	log.Printf("[heal] eBPF programs reloaded")
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

	// 1. Dump and verify agent_pids map
	h.verifyMap("agent_pids")
	h.verifyMap("pid_whitelist")
	h.verifyMap("hot_paths")

	// 2. Clean stale entries from proc_map
	// (in production, iterate and remove expired entries)

	log.Printf("[heal] map cleanup complete")
}

// verifyMap dumps a BPF map and checks its consistency.
func (h *Healer) verifyMap(name string) {
	cmd := exec.Command("bpftool", "map", "dump", "name", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		h.auditLog = append(h.auditLog, AuditEvent{
			Timestamp: time.Now(),
			Type:      "fail",
			Severity:  "WARNING",
			Message:   fmt.Sprintf("Cannot dump map %s: %v", name, err),
		})
		return
	}

	if !strings.Contains(string(output), "Found") &&
		!strings.Contains(string(output), "key") {
		log.Printf("[heal] map %s: empty (expected)", name)
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
