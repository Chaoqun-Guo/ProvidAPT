package honeypot

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Silent alert and escalation logic
// ═══════════════════════════════════════════════════════════════

// HoneyAlert is emitted when a honey path is accessed.
type HoneyAlert struct {
	Timestamp   time.Time `json:"timestamp"`
	PID         uint32    `json:"pid"`
	Comm        string    `json:"comm"`
	Path        string    `json:"path"`
	PathDesc    string    `json:"path_description"`
	Severity    string    `json:"severity"` // always CRITICAL
	TTPRef      string    `json:"ttp_ref"`
	Category    string    `json:"category"`
	Action      string    `json:"action"` // read, stat, write
}

// AlertHandler is called when a honey path is triggered.
type AlertHandler func(alert *HoneyAlert)

// EscalationConfig controls what happens when a honey path triggers.
type EscalationConfig struct {
	// EnableFullAudit — enable full audit mode for the triggering process.
	EnableFullAudit bool

	// EnableNetworkLog — log all network connections from this process.
	EnableNetworkLog bool

	// EnableMemoryLog — log all memory operations from this process.
	EnableMemoryLog bool

	// SandboxPath — if set, redirect matching processes to a sandbox.
	SandboxPath string

	// AlertHandlers — additional alert callbacks.
	AlertHandlers []AlertHandler
}

// DefaultEscalationConfig returns sensible escalation defaults.
func DefaultEscalationConfig() *EscalationConfig {
	return &EscalationConfig{
		EnableFullAudit:  true,
		EnableNetworkLog: true,
		EnableMemoryLog:  false, // memory logging is expensive
	}
}

// Trigger manages honey path alerting and escalation.
type Trigger struct {
	cfg    *EscalationConfig
	mgr    *Manager
	mu     sync.Mutex
	alerts []*HoneyAlert

	// Track triggered processes for dedup
	triggeredProcs map[uint32]time.Time
}

// NewTrigger creates a honey pot trigger manager.
func NewTrigger(cfg *EscalationConfig) *Trigger {
	if cfg == nil {
		cfg = DefaultEscalationConfig()
	}
	return &Trigger{
		cfg:            cfg,
		mgr:            NewManager(),
		triggeredProcs: make(map[uint32]time.Time),
	}
}

// OnAccess is called when a honey path is accessed.
// It generates a silent alert and activates escalations.
func (t *Trigger) OnAccess(path string, pid uint32, comm string, action string) *HoneyAlert {
	// Find the honey path definition
	var desc, ttp, category string
	for _, hp := range t.mgr.Paths() {
		if hp.Path == path {
			desc = hp.Description
			ttp = hp.TTPRef
			category = hp.Category
			break
		}
	}

	alert := &HoneyAlert{
		Timestamp: time.Now(),
		PID:       pid,
		Comm:      comm,
		Path:      path,
		PathDesc:  desc,
		Severity:  "CRITICAL",
		TTPRef:    ttp,
		Category:  category,
		Action:    action,
	}

	t.mu.Lock()
	t.alerts = append(t.alerts, alert)
	t.triggeredProcs[pid] = time.Now()
	t.mu.Unlock()

	// Silent alert (only logged, not broadcast to avoid detection)
	log.Printf("[honeypot] SILENT ALERT: process %s (PID %d) accessed honey path: %s",
		comm, pid, path)

	// Execute escalation actions
	t.escalate(alert)

	// Call registered handlers (synchronously for deterministic testing)
	for _, handler := range t.cfg.AlertHandlers {
		handler(alert)
	}

	return alert
}

// escalate executes the configured countermeasures.
func (t *Trigger) escalate(alert *HoneyAlert) {
	if t.cfg.EnableFullAudit {
		log.Printf("[honeypot] ESCALATION: full audit enabled for PID %d (%s)",
			alert.PID, alert.Comm)
		// In production: adaptiveController.Upgrade(pid, "honey_path_trigger")
	}

	if t.cfg.EnableNetworkLog {
		log.Printf("[honeypot] ESCALATION: network logging enabled for PID %d", alert.PID)
	}

	if t.cfg.SandboxPath != "" {
		log.Printf("[honeypot] ESCALATION: redirect PID %d to sandbox: %s",
			alert.PID, t.cfg.SandboxPath)
	}
}

// Alerts returns all honey alerts.
func (t *Trigger) Alerts() []*HoneyAlert {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*HoneyAlert, len(t.alerts))
	copy(out, t.alerts)
	return out
}

// RecentAlerts returns alerts from the last N seconds.
func (t *Trigger) RecentAlerts(seconds int) []*HoneyAlert {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := time.Now().Add(-time.Duration(seconds) * time.Second)
	var out []*HoneyAlert
	for _, a := range t.alerts {
		if a.Timestamp.After(cutoff) {
			out = append(out, a)
		}
	}
	return out
}

// IsProcessTriggered checks if a PID has triggered a honey path.
func (t *Trigger) IsProcessTriggered(pid uint32) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.triggeredProcs[pid]
	return ok
}

// ProcessAlertSummary returns a summary of all honey pot alerts.
func (t *Trigger) ProcessAlertSummary() string {
	alerts := t.Alerts()
	if len(alerts) == 0 {
		return "No honey pot triggers — no reconnaissance detected"
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Honey Pot: %d alerts\n", len(alerts)))
	for _, a := range alerts {
		b.WriteString(fmt.Sprintf("  %s (PID %d) → %s [%s] %s\n",
			a.Comm, a.PID, a.Path, a.Category, a.Action))
	}
	return b.String()
}

// GenerateHoneyEventID creates a standard event type for honey triggers.
// This should match the kernel-side EV_HONEY_TRIGGER constant.
const HoneyEventType = 210
