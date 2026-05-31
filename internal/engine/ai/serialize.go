// Package ai provides an LLM-powered analysis interpreter for
// ProvidAPT provenance graphs.  It converts complex graph structures
// into natural language descriptions, attack path explanations,
// and remediation recommendations.
package ai

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ═══════════════════════════════════════════════════════════════
// Graph serialization for LLM consumption
// ═══════════════════════════════════════════════════════════════

// LLMGraph is a simplified graph structure designed for LLM input.
// It converts provenance nodes and edges into a lightweight,
// semantically clear format.
type LLMGraph struct {
	Title       string       `json:"title"`
	Description string       `json:"description"`
	AlertInfo   *AlertInfo   `json:"alert_info,omitempty"`
	Nodes       []LLMNode    `json:"nodes"`
	Edges       []LLMEdge    `json:"edges"`
	Timeline    []LLMEvent   `json:"timeline,omitempty"`
}

// LLMNode is a simplified node for LLM consumption.
type LLMNode struct {
	ID      string `json:"id"`
	Type    string `json:"type"`    // process, file, network, etc.
	Label   string `json:"label"`   // comm name, file path, IP
	Details string `json:"details,omitempty"` // extra info
}

// LLMEdge is a simplified edge for LLM consumption.
type LLMEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Action string `json:"action"` // READ, WROTE, FORKED, CONNECTED
	Count  int    `json:"count,omitempty"` // how many times
}

// LLMEvent is a single event in the timeline.
type LLMEvent struct {
	Time   string `json:"time"`
	Action string `json:"action"`
	Source string `json:"source"`
	Target string `json:"target"`
}

// AlertInfo provides context about the alert.
type AlertInfo struct {
	AlertID  string  `json:"alert_id"`
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
	Rule     string  `json:"rule,omitempty"`
}

// SerializeGraph converts a provenance graph into an LLM-friendly structure.
func SerializeGraph(nodes []*provenance.Node, edges []*provenance.Edge, alert *AlertInfo) *LLMGraph {
	g := &LLMGraph{
		AlertInfo: alert,
	}

	// Convert nodes
	for _, n := range nodes {
		ln := LLMNode{
			ID:    n.ID,
			Type:  n.Subtype,
			Label: n.Label,
		}
		// Build details string from attributes
		var attrs []string
		for k, v := range n.Attributes {
			attrs = append(attrs, fmt.Sprintf("%s=%v", k, v))
		}
		if len(attrs) > 0 {
			ln.Details = strings.Join(attrs, ", ")
		}
		g.Nodes = append(g.Nodes, ln)
	}

	// Convert edges and build timeline
	for _, e := range edges {
		action := shortAction(e.Relation)
		le := LLMEdge{
			Source: e.Source,
			Target: e.Target,
			Action: action,
			Count:  e.Count,
		}
		g.Edges = append(g.Edges, le)

		// Timeline entry
		g.Timeline = append(g.Timeline, LLMEvent{
			Time:   e.Timestamp.Format(time.RFC3339Nano),
			Action: action,
			Source: e.Source,
			Target: e.Target,
		})
	}

	return g
}

// ToJSON serializes the LLM graph to indented JSON.
func (g *LLMGraph) ToJSON() (string, error) {
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ShortText creates a one-line summary of the graph.
func (g *LLMGraph) ShortText() string {
	nodes := len(g.Nodes)
	edges := len(g.Edges)
	processes := 0
	files := 0
	networks := 0
	for _, n := range g.Nodes {
		switch n.Type {
		case "process":
			processes++
		case "file":
			files++
		case "network":
			networks++
		}
	}
	return fmt.Sprintf("Provenance subgraph: %d nodes (%d processes, %d files, %d network), %d edges",
		nodes, processes, files, networks, edges)
}

// shortAction maps PROV relations to short action names.
func shortAction(rel string) string {
	switch rel {
	case "prov:used":
		return "READ"
	case "prov:wasGeneratedBy":
		return "WROTE"
	case "prov:wasInformedBy":
		return "FORKED"
	case "prov:wasDerivedFrom":
		return "DERIVED"
	case "prov:hadSecurityContext":
		return "CONTEXT"
	default:
		return rel
	}
}
