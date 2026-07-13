// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package taint implements dynamic taint tracking for ProvidAPT.
//
// Taint sources:  socket_read from non-internal IPs
// Propagation: tainted process -files it writes, processes it forks
//
// tainted file -processes that read it
//
// Decay:          crypto/signing operations can clear taint
// Alert:          tainted process touching /etc/shadow, ptrace, etc.
package taint

import (
	"fmt"
	"log"
	"net"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Taint levels

// Level describes how strongly a node is tainted.
type Level int

const (
	Clean         Level = 0
	Suspicious    Level = 1
	Tainted       Level = 2
	HighlyTainted Level = 3
)

func (l Level) String() string {
	switch l {
	case Clean:
		return "CLEAN"
	case Suspicious:
		return "SUSPICIOUS"
	case Tainted:
		return "TAINTED"
	case HighlyTainted:
		return "HIGH_TAINT"
	default:
		return fmt.Sprintf("TAINT_%d", l)
	}
}

// Taint state

// State holds the taint status of a node.
type State struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // "process", "file"
	Level     Level     `json:"level"`
	Source    string    `json:"source"`    // how it got tainted
	SourceIP  string    `json:"source_ip"` // originating IP
	UpdatedAt time.Time `json:"updated_at"`
}

// Config

// Config for the taint engine.
type Config struct {
	// NonInternalPrefixes -IP prefixes considered external.
	NonInternalPrefixes []string

	// CleanCommands -exec commands that can clear taint.
	CleanCommands []string

	// SensitivePaths -paths that trigger alerts when accessed by tainted procs.
	SensitivePaths []string

	// TaintDecayAfter -how long before taint auto-decays (0 = never).
	TaintDecayAfter time.Duration

	// EnableAlerting -if true, emit alerts on taint+trigger.
	EnableAlerting bool
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		NonInternalPrefixes: []string{
			"10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
			"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
			"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
			"127.", "169.254.",
		},
		CleanCommands: []string{
			"openssl", "gpg", "signify", "ssh-keygen",
			"rpmkeys", "dpkg-sig", "debsig-verify",
		},
		SensitivePaths: []string{
			"/etc/shadow", "/etc/passwd", "/etc/sudoers",
			"/etc/ssh/", "/root/.ssh/", "/.aws/credentials",
		},
		TaintDecayAfter: 30 * time.Minute,
		EnableAlerting:  true,
	}
}

// MatchTaint performs case-insensitive pattern matching for taint rules.
// Patterns ending with "*" use prefix matching; otherwise exact match.
// Returns true if value matches the pattern.
func MatchTaint(pattern, value string) bool {
	if pattern == "" {
		return false
	}
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		if len(value) < len(prefix) {
			return false
		}
		return strings.EqualFold(value[:len(prefix)], prefix)
	}
	return strings.EqualFold(value, pattern)
}

// TaintEngine

// TaintEngine manages taint propagation and alerting.
type TaintEngine struct {
	cfg     *Config
	mu      sync.RWMutex
	states  map[string]*State // nodeID -> taint state
	alerts  []TaintAlert
	alertID atomic.Int64
}

// TaintAlert is emitted when a tainted process triggers a sensitive action.
type TaintAlert struct {
	ID          int64     `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	ProcessID   string    `json:"process_id"`
	ProcessComm string    `json:"process_comm"`
	TaintLevel  Level     `json:"taint_level"`
	TaintSource string    `json:"taint_source"`
	TaintIP     string    `json:"taint_ip"`
	Action      string    `json:"action"`
	Target      string    `json:"target"`
	Severity    string    `json:"severity"` // "HIGH", "CRITICAL"
}

// New creates a taint engine.
func New(cfg *Config) *TaintEngine {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &TaintEngine{
		cfg:    cfg,
		states: make(map[string]*State),
	}
}

// Taint source detection

// IsExternalIP checks if an IP is not in the internal prefixes list.
// IsExternalIP checks whether a given IP string is external (not in private ranges).
// Supports both IPv4 and IPv6. Invalid IP strings are returned as internal (safe default).
func (te *TaintEngine) IsExternalIP(ipStr string) bool {
	// Parse as IP to validate format and normalize
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false // invalid IPs are not external (safe default)
	}

	// Check if it's a private/loopback/link-local IPv4
	// net.IP.IsPrivate() handles all RFC 1918 + RFC 6598 + ULA
	// net.IP.IsLoopback() handles 127.0.0.1/8 and ::1
	// net.IP.IsLinkLocalUnicast() handles 169.254.0.0/16 and fe80::/10
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}

	// For IPv4, also check the configured prefix list (may include custom ranges)
	if ip4 := ip.To4(); ip4 != nil {
		for _, prefix := range te.cfg.NonInternalPrefixes {
			if strings.HasPrefix(ipStr, prefix) {
				return false
			}
		}
		return true
	}

	// IPv6 is external unless caught by IsPrivate/IsLoopback/IsLinkLocalUnicast above
	return true
}

// MarkSocketSource marks a process as tainted from an external network source.
// Returns the taint state.
func (te *TaintEngine) MarkSocketSource(processID, comm, sourceIP string) *State {
	state := &State{
		ID:        processID,
		Type:      "process",
		Level:     Tainted,
		Source:    "socket_read:" + sourceIP,
		SourceIP:  sourceIP,
		UpdatedAt: time.Now(),
	}

	te.mu.Lock()
	te.states[processID] = state
	te.mu.Unlock()

	log.Printf("[taint] SOURCE: %s tainted by external IP %s", processID, sourceIP)
	return state
}

// Propagation

// PropagateRead is called when a process reads a file.
// If the file is tainted, the process becomes tainted.
func (te *TaintEngine) PropagateRead(processID, fileID, comm string) *State {
	return te.propagate(processID, "process", fileID, "file",
		fmt.Sprintf("read_tainted_file:%s", fileID))
}

// PropagateWrite is called when a process writes a file.
// If the process is tainted, the file becomes tainted.
func (te *TaintEngine) PropagateWrite(processID, fileID string) *State {
	return te.propagate(fileID, "file", processID, "process",
		fmt.Sprintf("written_by_tainted:%s", processID))
}

// PropagateFork is called when a process forks.
// If the parent is tainted, the child inherits taint.
func (te *TaintEngine) PropagateFork(parentID, childID string) *State {
	te.mu.RLock()
	parent, ok := te.states[parentID]
	te.mu.RUnlock()
	if !ok || parent.Level < Tainted {
		return nil
	}

	child := &State{
		ID:        childID,
		Type:      "process",
		Level:     parent.Level,
		Source:    fmt.Sprintf("forked_from_tainted:%s", parentID),
		SourceIP:  parent.SourceIP,
		UpdatedAt: time.Now(),
	}

	te.mu.Lock()
	te.states[childID] = child
	te.mu.Unlock()

	log.Printf("[taint] FORK: %s tainted by parent %s", childID, parentID)
	return child
}

// propagate implements the core taint propagation: if sourceNode is tainted,
// targetNode becomes tainted at the same level.
func (te *TaintEngine) propagate(targetID, targetType string,
	sourceID, sourceType, reason string) *State {

	te.mu.RLock()
	source, ok := te.states[sourceID]
	te.mu.RUnlock()
	if !ok || source.Level < Tainted {
		return nil
	}

	state := &State{
		ID:        targetID,
		Type:      targetType,
		Level:     source.Level,
		Source:    reason,
		SourceIP:  source.SourceIP,
		UpdatedAt: time.Now(),
	}

	te.mu.Lock()
	// Don't downgrade existing higher taint
	if existing, exists := te.states[targetID]; exists && existing.Level >= source.Level {
		te.mu.Unlock()
		return existing
	}
	te.states[targetID] = state
	te.mu.Unlock()

	level := "TAINTED"
	if state.Level >= HighlyTainted {
		level = "HIGH_TAINT"
	}
	log.Printf("[taint] PROPAGATE: %s ->-%s (level=%s, reason=%s)",
		sourceID, targetID, level, reason)

	return state
}

// Taint decay and cleaning

// IsCleanCommand checks if a command can clear taint.
func (te *TaintEngine) IsCleanCommand(comm string) bool {
	for _, clean := range te.cfg.CleanCommands {
		if strings.EqualFold(comm, clean) {
			return true
		}
	}
	return false
}

// CleanTaint removes taint from a node (called after crypto/signing ops).
func (te *TaintEngine) CleanTaint(nodeID string) {
	te.mu.Lock()
	state, ok := te.states[nodeID]
	if ok && state.Level > Clean {
		state.Level = Clean
		state.Source = "cleaned:legitimate_operation"
		log.Printf("[taint] CLEAN: %s taint cleared", nodeID)
	}
	te.mu.Unlock()
}

// DecayTaint aged taint levels.  Call periodically.
func (te *TaintEngine) DecayTaint() int {
	if te.cfg.TaintDecayAfter <= 0 {
		return 0
	}
	cutoff := time.Now().Add(-te.cfg.TaintDecayAfter)
	decayed := 0

	te.mu.Lock()
	for id, state := range te.states {
		if state.UpdatedAt.Before(cutoff) && state.Level > Suspicious {
			state.Level = Suspicious // decay to suspicious
			state.Source = "decayed:age"
			decayed++
			log.Printf("[taint] DECAY: %s level reduced (aged)", id)
		}
	}
	te.mu.Unlock()

	return decayed
}

// Sensitive action checking and alerting

// IsSensitivePath checks if a path triggers alerts.
// Uses path.Clean to normalize path traversal (e.g. /etc/../etc/shadow).
func (te *TaintEngine) IsSensitivePath(rawPath string) bool {
	cleaned := path.Clean(rawPath)
	for _, sp := range te.cfg.SensitivePaths {
		if strings.HasPrefix(cleaned, sp) || cleaned == sp {
			return true
		}
	}
	return false
}

// CheckAction checks if a tainted process is performing a sensitive action.
// If so, emits a TaintAlert.
func (te *TaintEngine) CheckAction(processID, comm, action, target string) *TaintAlert {
	te.mu.RLock()
	state, ok := te.states[processID]
	te.mu.RUnlock()
	if !ok || state.Level < Tainted {
		return nil
	}

	// Only alert if it's a sensitive path action
	sensitive := te.IsSensitivePath(target)
	if !sensitive && action == "read" {
		return nil // non-sensitive read doesn't trigger alert
	}
	if !sensitive && action != "ptrace" && action != "exec" {
		return nil
	}

	alert := TaintAlert{
		ID:          te.alertID.Add(1),
		Timestamp:   time.Now(),
		ProcessID:   processID,
		ProcessComm: comm,
		TaintLevel:  state.Level,
		TaintSource: state.Source,
		TaintIP:     state.SourceIP,
		Action:      action,
		Target:      target,
		Severity:    "HIGH",
	}
	if state.Level >= HighlyTainted || sensitive {
		alert.Severity = "CRITICAL"
	}

	if te.cfg.EnableAlerting {
		te.mu.Lock()
		te.alerts = append(te.alerts, alert)
		te.mu.Unlock()
		log.Printf("[taint] ALERT [%s] tainted process %s(%s) %s ->-%s (IP: %s)",
			alert.Severity, comm, processID, action, target, state.SourceIP)
	}

	return &alert
}

// Queries

// GetTaint returns the taint state of a node.
func (te *TaintEngine) GetTaint(nodeID string) *State {
	te.mu.RLock()
	defer te.mu.RUnlock()
	return te.states[nodeID]
}

// Alerts returns all taint alerts.
func (te *TaintEngine) Alerts() []TaintAlert {
	te.mu.Lock()
	defer te.mu.Unlock()
	out := make([]TaintAlert, len(te.alerts))
	copy(out, te.alerts)
	return out
}

// Stats returns taint engine statistics.
func (te *TaintEngine) Stats() map[string]interface{} {
	te.mu.RLock()
	defer te.mu.RUnlock()
	var tainted, files, procs int
	for _, s := range te.states {
		if s.Level >= Tainted {
			tainted++
			if s.Type == "file" {
				files++
			} else {
				procs++
			}
		}
	}
	return map[string]interface{}{
		"tainted_nodes": tainted,
		"tainted_procs": procs,
		"tainted_files": files,
		"total_tracked": len(te.states),
		"total_alerts":  len(te.alerts),
	}
}
