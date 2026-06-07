// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package appsync implements application-layer provenance enhancement
// for ProvidAPT.  It uses eBPF uprobes to instrument common applications
// (Nginx, Apache, MySQL, Go programs) and correlates application-level
// transactions with system-level events.
//
// This bridges the "semantic gap" between raw syscall sequences and
// high-level user actions (e.g., "HTTP GET /admin/config" instead of
// "connect → write → read → close").
package appsync

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// ═══════════════════════════════════════════════════════════════
// Application detection and uprobe injection
// ═══════════════════════════════════════════════════════════════

// AppProbe describes a single uprobe attachment point.
type AppProbe struct {
	AppName string // "nginx", "apache2", "mysql", "go"
	Symbol  string // function to probe (e.g., "SSL_read")
	Type    string // "entry", "return"
	Args    []ArgDef // function arguments to capture
}

// ArgDef describes a function argument to capture.
type ArgDef struct {
	Index  int    // argument position (0-based)
	Name   string // semantic name (e.g., "buf", "len", "fd")
	IsStr  bool   // true if this is a string pointer
	Size   int    // max bytes to read for strings
}

// DetectedApp holds information about a running application.
type DetectedApp struct {
	PID      int
	AppName  string
	Binary   string // path to the binary (for uprobe)
	Probes   []AppProbe
}

// ProbeManager handles uprobe injection and lifecycle.
type ProbeManager struct {
	detected []DetectedApp
	probes   []AppProbe
}

// NewProbeManager creates a probe manager with known application probes.
func NewProbeManager() *ProbeManager {
	pm := &ProbeManager{}
	pm.registerDefaultProbes()
	return pm
}

// registerDefaultProbes defines the standard uprobe set.
func (pm *ProbeManager) registerDefaultProbes() {
	// Nginx / OpenSSL
	pm.probes = append(pm.probes, []AppProbe{
		{AppName: "nginx", Symbol: "SSL_read", Type: "entry",
			Args: []ArgDef{{Index: 0, Name: "ssl", IsStr: false},
				{Index: 1, Name: "buf", IsStr: true, Size: 4096}}},
		{AppName: "nginx", Symbol: "SSL_write", Type: "entry",
			Args: []ArgDef{{Index: 0, Name: "ssl"},
				{Index: 1, Name: "buf", IsStr: true, Size: 4096}}},
		{AppName: "nginx", Symbol: "ngx_http_process_request", Type: "entry",
			Args: []ArgDef{{Index: 0, Name: "r", IsStr: false}}},
	}...)

	// Apache / OpenSSL
	pm.probes = append(pm.probes, []AppProbe{
		{AppName: "apache2", Symbol: "SSL_read", Type: "entry",
			Args: []ArgDef{{Index: 1, Name: "buf", IsStr: true, Size: 4096}}},
		{AppName: "apache2", Symbol: "ap_process_request", Type: "entry",
			Args: []ArgDef{{Index: 0, Name: "r"}}},
	}...)

	// MySQL
	pm.probes = append(pm.probes, []AppProbe{
		{AppName: "mysqld", Symbol: "mysql_parse", Type: "entry",
			Args: []ArgDef{{Index: 1, Name: "query", IsStr: true, Size: 4096}}},
		{AppName: "mysqld", Symbol: "dispatch_command", Type: "entry",
			Args: []ArgDef{{Index: 0, Name: "command"},
				{Index: 1, Name: "query", IsStr: true, Size: 4096}}},
	}...)
}

// DetectRunningApps scans /proc for known applications.
func (pm *ProbeManager) DetectRunningApps() ([]DetectedApp, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	appNames := pm.knownAppNames()
	pm.detected = nil

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if pid[0] < '0' || pid[0] > '9' {
			continue
		}

		// Read the executable path
		exe, err := os.Readlink(filepath.Join("/proc", pid, "exe"))
		if err != nil {
			continue
		}
		base := filepath.Base(exe)

		for _, appName := range appNames {
			if base == appName || strings.Contains(base, appName) {
				// Check if already detected (by binary path)
				alreadySeen := false
				for _, d := range pm.detected {
					if d.Binary == exe {
						alreadySeen = true
						break
					}
				}
				if !alreadySeen {
					probes := pm.probesForApp(appName)
					pm.detected = append(pm.detected, DetectedApp{
						PID:     parsePID(pid),
						AppName: appName,
						Binary:  exe,
						Probes:  probes,
					})
					log.Printf("[appsync] detected %s: pid=%d binary=%s probes=%d",
						appName, parsePID(pid), exe, len(probes))
				}
				break
			}
		}
	}

	return pm.detected, nil
}

// AttachAll attaches uprobes to all detected applications.
// In production, this uses cilium/ebpf/link.Uprobe().
// Here we provide the attachment plan.
func (pm *ProbeManager) AttachAll() []AttachmentPlan {
	var plans []AttachmentPlan
	for _, app := range pm.detected {
		for _, probe := range app.Probes {
			plans = append(plans, AttachmentPlan{
				Binary:  app.Binary,
				Symbol:  probe.Symbol,
				Type:    probe.Type,
				PID:     app.PID,
				AppName: app.AppName,
			})
		}
	}
	return plans
}

// AttachmentPlan describes where and how to attach a uprobe.
type AttachmentPlan struct {
	Binary  string `json:"binary"`
	Symbol  string `json:"symbol"`
	Type    string `json:"type"` // "entry" or "return"
	PID     int    `json:"pid,omitempty"`
	AppName string `json:"app_name"`
}

// Summary returns a human-readable summary of detected apps.
func (pm *ProbeManager) Summary() string {
	var lines []string
	for _, app := range pm.detected {
		lines = append(lines, fmt.Sprintf("  %s (PID %d, binary=%s, %d probes)",
			app.AppName, app.PID, app.Binary, len(app.Probes)))
	}
	if len(lines) == 0 {
		return "No supported applications detected"
	}
	return strings.Join(lines, "\n")
}

// ── Internal helpers ────────────────────────────────────────

func (pm *ProbeManager) knownAppNames() []string {
	names := make(map[string]bool)
	for _, p := range pm.probes {
		names[p.AppName] = true
	}
	var result []string
	for n := range names {
		result = append(result, n)
	}
	return result
}

func (pm *ProbeManager) probesForApp(appName string) []AppProbe {
	var result []AppProbe
	for _, p := range pm.probes {
		if p.AppName == appName {
			result = append(result, p)
		}
	}
	return result
}

func parsePID(s string) int {
	var pid int
	fmt.Sscanf(s, "%d", &pid)
	return pid
}
