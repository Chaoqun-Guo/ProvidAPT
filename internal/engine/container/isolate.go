// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package container — multi-tenant isolation analysis.
//
// Detects unexpected inter-pod communications (lateral movement)
// by analyzing provenance edges between different K8s namespaces
// and pods on the same host.
package container

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Lateral movement detection
// ═══════════════════════════════════════════════════════════════

// CrossPodEdge represents a provenance edge between two pods.
type CrossPodEdge struct {
	SourcePod       string `json:"source_pod"`
	SourceNamespace string `json:"source_namespace"`
	TargetPod       string `json:"target_pod"`
	TargetNamespace string `json:"target_namespace"`
	Relation        string `json:"relation"`  // "connect", "fork", "file_access"
	PID             uint32 `json:"pid"`
	Comm            string `json:"comm"`
	Timestamp       time.Time `json:"timestamp"`
	Suspicious      bool   `json:"suspicious"`
	Reason          string `json:"reason,omitempty"`
}

// IsolationAnalyzer detects unexpected inter-pod communications.
type IsolationAnalyzer struct {
	mu          sync.Mutex
	edges       []CrossPodEdge
	alerts      []CrossPodAlert
	namespaces  map[string]bool // known namespaces
}

// CrossPodAlert is emitted when suspicious inter-pod activity is detected.
type CrossPodAlert struct {
	Timestamp   time.Time `json:"timestamp"`
	SourcePod   string    `json:"source_pod"`
	TargetPod   string    `json:"target_pod"`
	Direction   string    `json:"direction"` // "same-ns", "cross-ns", "host-to-pod"
	Action      string    `json:"action"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
}

// NewIsolationAnalyzer creates a multi-tenant analyzer.
func NewIsolationAnalyzer() *IsolationAnalyzer {
	return &IsolationAnalyzer{
		namespaces: make(map[string]bool),
	}
}

// RecordEdge records a provenance edge between two entities
// and checks for cross-pod violations.
func (ia *IsolationAnalyzer) RecordEdge(src, dst *EnrichedEvent, relation string) *CrossPodAlert {
	edge := CrossPodEdge{
		SourcePod:       src.PodLabel(),
		SourceNamespace: src.Namespace,
		TargetPod:       dst.PodLabel(),
		TargetNamespace: dst.Namespace,
		Relation:        relation,
		PID:             src.PID,
		Comm:            src.Comm,
		Timestamp:       time.Now(),
	}

	ia.mu.Lock()
	ia.edges = append(ia.edges, edge)
	ia.namespaces[src.Namespace] = true
	ia.namespaces[dst.Namespace] = true
	ia.mu.Unlock()

	// Check for violations
	return ia.checkViolation(src, dst, relation)
}

// checkViolation examines whether an inter-pod edge is suspicious.
//
// Rules:
//   1. cross-namespace connect → suspicious (lateral movement)
//   2. host process → pod connect → moderate (container escape)
//   3. pod → pod same-ns exec → normal (expected)
//   4. pod → host file write → suspicious (container escape)
func (ia *IsolationAnalyzer) checkViolation(src, dst *EnrichedEvent, relation string) *CrossPodAlert {
	// Same pod → always normal
	if src.PodLabel() == dst.PodLabel() && src.Namespace == dst.Namespace {
		return nil
	}

	// Same namespace, different pods → check relation
	if src.Namespace == dst.Namespace && src.PodName != dst.PodName {
		if relation == "connect" || relation == "exec" {
			return ia.alert(src, dst, "same-ns", relation, "MEDIUM",
				fmt.Sprintf("Pod %s → %s within same namespace", src.PodName, dst.PodName))
		}
		return nil // file access within same NS is normal
	}

	// Cross-namespace → suspicious (potential lateral movement)
	if src.Namespace != "" && dst.Namespace != "" && src.Namespace != dst.Namespace {
		return ia.alert(src, dst, "cross-ns", relation, "HIGH",
			fmt.Sprintf("Cross-namespace lateral movement: %s/%s → %s/%s",
				src.Namespace, src.PodName, dst.Namespace, dst.PodName))
	}

	// Host → Pod (or Pod → Host)
	if src.PodName == "" && dst.PodName != "" {
		return ia.alert(src, dst, "host-to-pod", relation, "HIGH",
			fmt.Sprintf("Host process → pod %s: possible container escape", dst.PodName))
	}
	if src.PodName != "" && dst.PodName == "" {
		if relation == "file_access" && strings.Contains(dst.Pathname, "/etc/") {
			return ia.alert(src, dst, "pod-to-host", relation, "CRITICAL",
				fmt.Sprintf("Pod %s writing host /etc/: container escape suspected", src.PodName))
		}
	}

	return nil
}

func (ia *IsolationAnalyzer) alert(src, dst *EnrichedEvent, direction, action, severity, desc string) *CrossPodAlert {
	alert := &CrossPodAlert{
		Timestamp:   time.Now(),
		SourcePod:   src.PodLabel(),
		TargetPod:   dst.PodLabel(),
		Direction:   direction,
		Action:      action,
		Severity:    severity,
		Description: desc,
	}

	ia.mu.Lock()
	ia.alerts = append(ia.alerts, *alert)
	ia.mu.Unlock()

	log.Printf("[isolate] ALERT [%s] %s", severity, desc)
	return alert
}

// Alerts returns all isolation alerts.
func (ia *IsolationAnalyzer) Alerts() []CrossPodAlert {
	ia.mu.Lock()
	defer ia.mu.Unlock()
	out := make([]CrossPodAlert, len(ia.alerts))
	copy(out, ia.alerts)
	return out
}

// Stats returns analyzer statistics.
func (ia *IsolationAnalyzer) Stats() map[string]interface{} {
	ia.mu.Lock()
	defer ia.mu.Unlock()
	bySeverity := map[string]int{}
	for _, a := range ia.alerts {
		bySeverity[a.Severity]++
	}
	return map[string]interface{}{
		"edges_recorded":  len(ia.edges),
		"alerts_total":    len(ia.alerts),
		"namespaces":      len(ia.namespaces),
		"alerts_critical": bySeverity["CRITICAL"],
		"alerts_high":     bySeverity["HIGH"],
		"alerts_medium":   bySeverity["MEDIUM"],
	}
}
