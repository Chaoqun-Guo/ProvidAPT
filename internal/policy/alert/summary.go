// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package alert

import (
	"fmt"
	"strings"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ═══════════════════════════════════════════════════════════════
// Context summary extraction
// ═══════════════════════════════════════════════════════════════

// AlertSummary is a concise, human-readable alert for webhook delivery.
type AlertSummary struct {
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Timestamp   string   `json:"timestamp"`
	AttackPath  string   `json:"attack_path"`
	NodeCount   int      `json:"node_count"`
	KeyEntities []string `json:"key_entities"`
	Description string   `json:"description"`
}

// SummaryGenerator extracts concise summaries from the graph.
type SummaryGenerator struct {
	graph *provenance.Graph
}

// NewSummaryGenerator creates a summary generator.
func NewSummaryGenerator(graph *provenance.Graph) *SummaryGenerator {
	return &SummaryGenerator{graph: graph}
}

// Generate produces an alert summary from an incident.
func (sg *SummaryGenerator) Generate(inc *Incident) *AlertSummary {
	summary := &AlertSummary{
		Title:       fmt.Sprintf("%s — %s", inc.PatternName, inc.Severity),
		Severity:    inc.Severity,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		AttackPath:  strings.Join(inc.Nodes, " → "),
		Description: inc.PatternID,
	}

	// Extract key entities from the path nodes
	for _, nodeID := range inc.Nodes {
		if n, ok := sg.graph.LookupNode(nodeID); ok && n != nil {
			label := n.Label
			if label == "" {
				label = n.ID
			}
			entity := fmt.Sprintf("%s (%s)", label, n.Subtype)
			summary.KeyEntities = append(summary.KeyEntities, entity)
		}
	}
	summary.NodeCount = len(summary.KeyEntities)

	return summary
}

// GenerateFromMatch produces an alert summary directly from a match.
func (sg *SummaryGenerator) GenerateFromMatch(match *MatchResult) *AlertSummary {
	now := time.Now().UTC()
	summary := &AlertSummary{
		Title:       fmt.Sprintf("%s — %s", match.Pattern.Name, match.Pattern.Severity),
		Severity:    match.Pattern.Severity,
		Timestamp:   now.Format(time.RFC3339),
		AttackPath:  strings.Join(match.Nodes, " → "),
		Description: match.Pattern.Description,
	}

	for _, nodeID := range match.Nodes {
		if n, ok := sg.graph.LookupNode(nodeID); ok && n != nil {
			label := n.Label
			if label == "" {
				label = n.ID
			}
			summary.KeyEntities = append(summary.KeyEntities,
				fmt.Sprintf("%s (%s)", label, n.Subtype))
		}
	}
	summary.NodeCount = len(summary.KeyEntities)
	return summary
}

// Text returns a plain text version of the summary.
func (as *AlertSummary) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "🚨 %s\n", as.Title)
	fmt.Fprintf(&b, "Severity: %s\n", as.Severity)
	fmt.Fprintf(&b, "Time:     %s\n", as.Timestamp)
	fmt.Fprintf(&b, "Path:     %s\n", as.AttackPath)
	fmt.Fprintf(&b, "Entities: %d\n", as.NodeCount)
	for _, e := range as.KeyEntities {
		fmt.Fprintf(&b, "  • %s\n", e)
	}
	return b.String()
}

// Markdown returns a markdown-formatted summary (for Slack, Teams, etc.).
func (as *AlertSummary) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "## 🚨 ProvidAPT Alert: %s\n\n", as.Title)
	fmt.Fprintf(&b, "**Severity:** `%s`  \n", as.Severity)
	fmt.Fprintf(&b, "**Time:** %s  \n", as.Timestamp)
	fmt.Fprintf(&b, "**Attack Path:** `%s`  \n\n", as.AttackPath)
	b.WriteString("### Key Entities  \n")
	for _, e := range as.KeyEntities {
		fmt.Fprintf(&b, "- %s  \n", e)
	}
	return b.String()
}
