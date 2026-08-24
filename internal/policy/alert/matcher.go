// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package alert provides advanced alerting for ProvenAPT with
// graph pattern matching, incident aggregation, and context-aware
// summaries for webhook delivery.
package alert

import (
	"strings"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ─── Graph pattern ──────────────────────────────────────────

// PatternStep is one hop in an attack pattern.
type PatternStep struct {
	SourceType  string // "process", "file", "network", etc.
	SourceMatch string // process comm or file path pattern
	Relation    string // "used", "wasGeneratedBy", "wasInformedBy"
	TargetType  string
	TargetMatch string
}

// AttackPattern is a multi-step graph pattern that indicates an APT attack.
type AttackPattern struct {
	ID          string
	Name        string
	Description string
	Severity    string
	Steps       []PatternStep
}

// DefaultPatterns returns built-in APT patterns.
func DefaultPatterns() []AttackPattern {
	return []AttackPattern{
		{
			ID: "APT-WEB-SHELL", Name: "Web Shell Attack Chain",
			Description: "Web server → shell execution → config write → C2 connect",
			Severity:    "CRITICAL",
			Steps: []PatternStep{
				{SourceType: "process", SourceMatch: "nginx|apache|httpd", Relation: "wasInformedBy", TargetType: "process", TargetMatch: "bash|sh"},
				{SourceType: "process", SourceMatch: "bash|sh", Relation: "wasGeneratedBy", TargetType: "file", TargetMatch: "/etc/|/root/"},
				{SourceType: "process", SourceMatch: "bash|sh", Relation: "used", TargetType: "network", TargetMatch: ""},
			},
		},
		{
			ID: "APT-LOL-EXEC", Name: "Living-off-the-Land Execution",
			Description: "Network tool downloads payload, writes to /tmp, executes it",
			Severity:    "CRITICAL",
			Steps: []PatternStep{
				{SourceType: "process", SourceMatch: "curl|wget|nc|python", Relation: "wasGeneratedBy", TargetType: "file", TargetMatch: "/tmp/"},
				{SourceType: "process", SourceMatch: "bash|sh|python", Relation: "used", TargetType: "file", TargetMatch: "/tmp/"},
			},
		},
		{
			ID: "APT-CRED-EXFIL", Name: "Credential Exfiltration",
			Description: "Process accesses shadow file and connects to external IP",
			Severity:    "HIGH",
			Steps: []PatternStep{
				{SourceType: "process", SourceMatch: "", Relation: "used", TargetType: "file", TargetMatch: "shadow|passwd"},
				{SourceType: "process", SourceMatch: "", Relation: "used", TargetType: "network", TargetMatch: ""},
			},
		},
	}
}

// PatternMatcher detects attack patterns in the provenance graph.
type PatternMatcher struct {
	patterns []AttackPattern
}

// NewPatternMatcher creates a pattern matcher with default patterns.
func NewPatternMatcher() *PatternMatcher {
	return &PatternMatcher{patterns: DefaultPatterns()}
}

// MatchResult is returned when a pattern matches.
type MatchResult struct {
	Pattern    AttackPattern
	Nodes      []string // node IDs along the path
	Confidence float64
}

// MatchAll checks all patterns against the graph.
func (pm *PatternMatcher) MatchAll(graph *provenance.Graph) []*MatchResult {
	var results []*MatchResult
	edges := graph.Edges()

	for _, pattern := range pm.patterns {
		if match := pm.matchPattern(graph, edges, pattern); match != nil {
			results = append(results, match)
		}
	}
	return results
}

// matchPattern checks if a specific pattern exists in the graph.
func (pm *PatternMatcher) matchPattern(graph *provenance.Graph,
	edges []*provenance.Edge, pattern AttackPattern) *MatchResult {

	if len(pattern.Steps) == 0 {
		return nil
	}

	// Find starting nodes that match the first step
	startNodes := pm.findStartNodes(graph, pattern.Steps[0])
	if len(startNodes) == 0 {
		return nil
	}

	// For each start node, try to follow the full path
	for _, startID := range startNodes {
		if path := pm.tracePath(graph, startID, pattern.Steps, 0, 1); path != nil {
			return &MatchResult{
				Pattern:    pattern,
				Nodes:      path,
				Confidence: float64(len(path)) / float64(len(pattern.Steps)+1),
			}
		}
	}
	return nil
}

// findStartNodes finds nodes matching the first step of a pattern.
func (pm *PatternMatcher) findStartNodes(graph *provenance.Graph, step PatternStep) []string {
	var matches []string
	for _, n := range graph.Nodes() {
		if step.SourceType != "" && n.Subtype != step.SourceType {
			continue
		}
		if step.SourceMatch != "" && !patternMatch(step.SourceMatch, n.Label) {
			continue
		}
		matches = append(matches, n.ID)
	}
	return matches
}

// tracePath attempts to trace a pattern path from a start node.
// It checks both outgoing edges (e.Source == nodeID) and incoming
// edges (e.Target == nodeID), since PROV relations like wasInformedBy
// and wasGeneratedBy may flow in either direction relative to the
// trace direction.
func (pm *PatternMatcher) tracePath(graph *provenance.Graph,
	nodeID string, steps []PatternStep, stepIdx int, depth int) []string {

	if stepIdx >= len(steps) {
		return []string{nodeID}
	}
	if depth > 10 {
		return nil
	}

	step := steps[stepIdx]
	for _, e := range graph.Edges() {
		// Check outgoing: node is the source, step target is the edge's target
		if e.Source == nodeID {
			if step.Relation != "" && !relMatch(step.Relation, e.Relation) {
				goto incoming
			}
			target, ok := graph.LookupNode(e.Target)
			if !ok || target == nil {
				goto incoming
			}
			if step.TargetType != "" && target.Subtype != step.TargetType {
				goto incoming
			}
			if step.TargetMatch != "" && !patternMatch(step.TargetMatch, target.Label) {
				goto incoming
			}
			rest := pm.tracePath(graph, target.ID, steps, stepIdx+1, depth+1)
			if rest != nil {
				return append([]string{nodeID}, rest...)
			}
		}

	incoming:
		// Check incoming: node is the target, step target is the edge's source
		if e.Target == nodeID {
			if step.Relation != "" && !relMatch(step.Relation, e.Relation) {
				continue
			}
			src, ok := graph.LookupNode(e.Source)
			if !ok || src == nil {
				continue
			}
			if step.TargetType != "" && src.Subtype != step.TargetType {
				continue
			}
			if step.TargetMatch != "" && !patternMatch(step.TargetMatch, src.Label) {
				continue
			}
			rest := pm.tracePath(graph, src.ID, steps, stepIdx+1, depth+1)
			if rest != nil {
				return append([]string{nodeID}, rest...)
			}
		}
	}
	return nil
}

func patternMatch(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	parts := strings.Split(pattern, "|")
	for _, p := range parts {
		if strings.Contains(strings.ToLower(value), strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func relMatch(pattern, rel string) bool {
	switch pattern {
	case "used":
		return rel == "prov:used"
	case "wasGeneratedBy":
		return rel == "prov:wasGeneratedBy"
	case "wasInformedBy":
		return rel == "prov:wasInformedBy"
	case "forked":
		return rel == "prov:wasInformedBy"
	}
	return false
}
