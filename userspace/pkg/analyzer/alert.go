package analyzer

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/provenance"
)

// ═══════════════════════════════════════════════════════════════
// Severity
// ═══════════════════════════════════════════════════════════════

type Severity int

const (
	SeverityInfo     Severity = 10
	SeverityLow      Severity = 20
	SeverityMedium   Severity = 30
	SeverityHigh     Severity = 40
	SeverityCritical Severity = 50
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	}
	return "UNKNOWN"
}

// ═══════════════════════════════════════════════════════════════
// Alert
// ═══════════════════════════════════════════════════════════════

// Alert describes a detected APT-relevant anomaly.
type Alert struct {
	Pattern     PatternID
	Severity    Severity
	Headline    string // single-line summary
	Reason      string // detailed explanation
	AlertNodeID string // node that triggered the alert
	DetectedAt  time.Time

	// Subgraph is the extracted provenance fragment showing the
	// attack path. Populated by ExtractSubgraph.
	Subgraph *AlertSubgraph
}

// AlertSubgraph is a minimal provenance graph showing only the
// nodes and edges involved in the suspicious activity.
type AlertSubgraph struct {
	Nodes []*provenance.Node `json:"nodes"`
	Edges []*provenance.Edge `json:"edges"`

	// PathNodeIDs lists node IDs along the main attack path,
	// in chronological / causal order (source → alert node).
	PathNodeIDs []string `json:"path_node_ids"`

	// AlertNodeID is the node that triggered the alert,
	// typically at the "effect" end of the path.
	AlertNodeID string `json:"alert_node_id"`
}

// ═══════════════════════════════════════════════════════════════
// Subgraph extraction
// ═══════════════════════════════════════════════════════════════

// ExtractSubgraph builds a minimal provenance subgraph showing the
// propagation path that led to this alert.
//
// The algorithm:
//  1. Trace the taint path from alert node back to initial source
//     via TaintNode.PrevID pointers.
//  2. Collect all nodes along the path.
//  3. Collect all edges whose both endpoints are path nodes.
//  4. Add 1-hop context: direct neighbours of path nodes.
func (a *Alert) ExtractSubgraph(te *TaintEngine) {
	pathIDs := te.PropagationPath(a.AlertNodeID)
	if len(pathIDs) == 0 {
		pathIDs = []string{a.AlertNodeID}
	}

	// Build a set for fast lookup
	onPath := make(map[string]bool)
	for _, id := range pathIDs {
		onPath[id] = true
	}

	// 1-hop context: direct neighbours of path nodes
	context := make(map[string]bool)
	for _, id := range pathIDs {
		for _, e := range te.forward[id] {
			context[e.Target] = true
		}
		for _, e := range te.reverse[id] {
			context[e.Source] = true
		}
	}
	// Remove duplicates already on path
	for id := range onPath {
		delete(context, id)
	}

	// Collect nodes
	seenNode := make(map[string]bool)
	var nodes []*provenance.Node
	addNode := func(id string) {
		if seenNode[id] {
			return
		}
		seenNode[id] = true
		if n := te.nodes[id]; n != nil {
			nodes = append(nodes, n)
		}
	}
	for _, id := range pathIDs {
		addNode(id)
	}
	for id := range context {
		addNode(id)
	}

	// Collect edges whose endpoints are in the set
	keepEdge := func(src, tgt string) bool {
		return onPath[src] || onPath[tgt] || (context[src] && onPath[tgt]) || (onPath[src] && context[tgt])
	}
	seenEdge := make(map[string]bool)
	var edges []*provenance.Edge
	for _, e := range te.allEdges() {
		if !keepEdge(e.Source, e.Target) {
			continue
		}
		if seenEdge[e.ID] {
			continue
		}
		seenEdge[e.ID] = true
		edges = append(edges, e)
	}

	a.Subgraph = &AlertSubgraph{
		Nodes:       nodes,
		Edges:       edges,
		PathNodeIDs: pathIDs,
		AlertNodeID: a.AlertNodeID,
	}
}

// allEdges returns all edges from the taint engine's index.
func (te *TaintEngine) allEdges() []*provenance.Edge {
	var out []*provenance.Edge
	seen := make(map[string]bool)
	for _, list := range te.forward {
		for _, e := range list {
			if !seen[e.ID] {
				seen[e.ID] = true
				out = append(out, e)
			}
		}
	}
	return out
}

// ═══════════════════════════════════════════════════════════════
// Alert formatting
// ═══════════════════════════════════════════════════════════════

func (a *Alert) String() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("[%s] [%s] %s\n",
		a.DetectedAt.Format(time.RFC3339),
		a.Severity, a.Pattern))
	b.WriteString(fmt.Sprintf("  %s\n", a.Headline))
	if a.Subgraph != nil {
		b.WriteString(fmt.Sprintf("  subgraph: %d nodes, %d edges, path=%d hops\n",
			len(a.Subgraph.Nodes), len(a.Subgraph.Edges),
			len(a.Subgraph.PathNodeIDs)))
	}
	return b.String()
}

// ═══════════════════════════════════════════════════════════════
// JSON alert serialization
// ═══════════════════════════════════════════════════════════════

// alertEnvelope is the JSON-serializable alert wrapper.
type alertEnvelope struct {
	Pattern     string         `json:"pattern"`
	Severity    string         `json:"severity"`
	Headline    string         `json:"headline"`
	Reason      string         `json:"reason"`
	AlertNodeID string         `json:"alert_node_id"`
	DetectedAt  time.Time      `json:"detected_at"`
	Subgraph    *alertSubgraph `json:"subgraph,omitempty"`
}

type alertSubgraph struct {
	Nodes       []jsonNode `json:"nodes"`
	Edges       []jsonEdge `json:"edges"`
	PathNodeIDs []string   `json:"path_node_ids"`
	AlertNodeID string     `json:"alert_node_id"`
}

type jsonNode struct {
	ID      string                 `json:"id"`
	Type    string                 `json:"prov_type"`
	Subtype string                 `json:"subtype"`
	Label   string                 `json:"label"`
	Attrs   map[string]interface{} `json:"attributes,omitempty"`
}

type jsonEdge struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	Relation string `json:"relation"`
}

// SerializeAlertJSON writes a list of alerts with their subgraphs
// as a JSON array.
func SerializeAlertJSON(w io.Writer, alerts []*Alert) error {
	out := make([]alertEnvelope, 0, len(alerts))
	for _, a := range alerts {
		env := alertEnvelope{
			Pattern:     string(a.Pattern),
			Severity:    a.Severity.String(),
			Headline:    a.Headline,
			Reason:      a.Reason,
			AlertNodeID: a.AlertNodeID,
			DetectedAt:  a.DetectedAt,
		}
		if a.Subgraph != nil {
			sg := a.Subgraph
			env.Subgraph = &alertSubgraph{
				PathNodeIDs: sg.PathNodeIDs,
				AlertNodeID: sg.AlertNodeID,
			}
			for _, n := range sg.Nodes {
				env.Subgraph.Nodes = append(env.Subgraph.Nodes, jsonNode{
					ID:      n.ID,
					Type:    n.ProvType,
					Subtype: n.Subtype,
					Label:   n.Label,
					Attrs:   n.Attributes,
				})
			}
			for _, e := range sg.Edges {
				env.Subgraph.Edges = append(env.Subgraph.Edges, jsonEdge{
					ID:       e.ID,
					Source:   e.Source,
					Target:   e.Target,
					Relation: e.Relation,
				})
			}
		}
		out = append(out, env)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// register io and json imports at package level — already included above.
// Note: if you see "io" or "json" not imported, these are used
// indirectly via the alertEnvelope struct tags in SerializeAlertJSON.
