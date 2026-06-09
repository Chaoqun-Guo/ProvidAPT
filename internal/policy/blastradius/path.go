// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package detect implements lateral movement detection on the global
// provenance graph for ProvidAPT.
//
// Detection algorithms:
//  1. Anomalous path identification 鈥-non-typical cross-host jumps
//  2. Credential theft correlation 鈥-LSASS + remote login linking
//  3. Global blast radius 鈥-datacenter-wide impact analysis
package blastradius

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺-// Path templates 鈥-known good paths
// 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺-
// PathTemplate defines a known legitimate cross-host path.
type PathTemplate struct {
	Name     string   `json:"name"`
	Segments []string `json:"segments"` // ordered host roles
}

// DefaultPathTemplates are known good paths in an enterprise network.
var DefaultPathTemplates = []PathTemplate{
	{Name: "user鈫抴eb鈫抋pi鈫抎b", Segments: []string{"user-pc", "web-server", "api-server", "database"}},
	{Name: "dev鈫抰est鈫抪rod", Segments: []string{"developer-pc", "test-server", "production-server"}},
	{Name: "admin鈫抝ump鈫抰arget", Segments: []string{"admin-pc", "jump-server", "target-server"}},
	{Name: "monitoring鈫抰arget", Segments: []string{"monitoring-server", "target-server"}},
}

// AnomalousPathDetector finds lateral movement via non-typical paths.
type AnomalousPathDetector struct {
	mu        sync.Mutex
	templates []PathTemplate
	alerts    []PathAlert
}

// PathAlert is emitted when an anomalous path is detected.
type PathAlert struct {
	ID          string    `json:"id"`
	Path        []string  `json:"path"` // host1 鈫-host2 鈫-host3
	Description string    `json:"description"`
	Suspected   string    `json:"suspected"` // "jump", "escalation"
	Severity    string    `json:"severity"`
	Timestamp   time.Time `json:"timestamp"`
}

// NewAnomalousPathDetector creates a path anomaly detector.
func NewAnomalousPathDetector() *AnomalousPathDetector {
	return &AnomalousPathDetector{
		templates: DefaultPathTemplates,
	}
}

// CheckPath evaluates a cross-host path against known templates.
// Returns an alert if the path is anomalous.
func (apd *AnomalousPathDetector) CheckPath(path []string, roles []string) *PathAlert {
	if len(path) < 2 {
		return nil
	}

	// Build jump description
	jumps := describeJumps(path, roles)

	// Check against templates
	matched := false
	for _, tmpl := range apd.templates {
		if apd.matchTemplate(roles, tmpl.Segments) {
			matched = true
			break
		}
	}

	if matched {
		return nil // expected path
	}

	// Anomalous path detected
	alert := &PathAlert{
		ID:          fmt.Sprintf("PATH-%d", time.Now().UnixNano()),
		Path:        path,
		Description: fmt.Sprintf("Anomalous path: %s", strings.Join(jumps, " 鈫-")),
		Suspected:   classifyAnomaly(roles),
		Severity:    "HIGH",
		Timestamp:   time.Now(),
	}

	apd.mu.Lock()
	apd.alerts = append(apd.alerts, *alert)
	apd.mu.Unlock()

	log.Printf("[detect] ANOMALOUS PATH: %s (%s)", alert.Description, alert.Suspected)
	return alert
}

// matchTemplate checks if host roles match a known path template.
func (apd *AnomalousPathDetector) matchTemplate(roles []string, template []string) bool {
	if len(roles) != len(template) {
		return false
	}
	for i, role := range roles {
		if role != template[i] {
			return false
		}
	}
	return true
}

// describeJumps builds a human-readable path description.
func describeJumps(path, roles []string) []string {
	jumps := make([]string, len(path))
	for i := range path {
		if i < len(roles) {
			jumps[i] = fmt.Sprintf("%s(%s)", path[i], roles[i])
		} else {
			jumps[i] = path[i]
		}
	}
	return jumps
}

// classifyAnomaly determines what type of anomaly was detected.
func classifyAnomaly(roles []string) string {
	for _, role := range roles {
		if role == "jump-server" || role == "bastion" {
			return "jump"
		}
		if role == "production-server" || role == "database" {
			return "escalation"
		}
	}
	return "unexpected_path"
}

// Alerts returns all path alerts.
func (apd *AnomalousPathDetector) Alerts() []PathAlert {
	apd.mu.Lock()
	defer apd.mu.Unlock()
	out := make([]PathAlert, len(apd.alerts))
	copy(out, apd.alerts)
	return out
}
