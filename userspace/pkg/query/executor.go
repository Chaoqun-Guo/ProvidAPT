package query

import (
	"fmt"
	"strings"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/provenance"
)

// ═══════════════════════════════════════════════════════════════
// Query executor
//
// Translates a ProvQL AST into DFS traversals on the provenance
// graph.  Supports:
//   - Label-based node matching
//   - Edge traversal (forward only)
//   - WHERE clause filtering
//   - DURING time window
//   - RETURN projection
// ═══════════════════════════════════════════════════════════════

// Executor runs ProvQL queries against a provenance graph.
type Executor struct {
	graph *provenance.Graph
}

// NewExecutor creates a query executor attached to a graph.
func NewExecutor(graph *provenance.Graph) *Executor {
	return &Executor{graph: graph}
}

// Execute parses and runs a ProvQL query.
func (e *Executor) Execute(queryStr string) (*Result, error) {
	q, err := Parse(queryStr)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return e.Run(q)
}

// Run executes a parsed query.
func (e *Executor) Run(q *Query) (*Result, error) {
	start := time.Now()
	result := &Result{}

	// Determine projected column names
	for _, p := range q.Return {
		if p.Field != "" {
			result.Columns = append(result.Columns, p.Variable+"."+p.Field)
		} else {
			result.Columns = append(result.Columns, p.Variable)
		}
	}

	// DFS traversal from the first node pattern
	firstNode := q.Match.Nodes[0]
	subtype := labelToSubtype[firstNode.Label]

	// Find candidate starting nodes
	var candidates []*provenance.Node
	for _, n := range e.graph.Nodes() {
		if subtype != "" && n.Subtype != subtype {
			continue
		}
		if !e.matchesWhere(n, firstNode.Variable, q.Where) {
			continue
		}
		candidates = append(candidates, n)
	}

	// For each candidate, traverse the path
	for _, startNode := range candidates {
		rows := e.traverse(startNode, q.Match, 0, 0, q.Where, q.During, make(map[string]*provenance.Node))
		result.Rows = append(result.Rows, rows...)
	}

	result.Elapsed = time.Since(start)
	return result, nil
}

// traverse performs DFS along the pattern path.
func (e *Executor) traverse(
	node *provenance.Node,
	path *PathPattern,
	nodeIdx int,
	edgeIdx int,
	where []Condition,
	during *TimeWindow,
	bindings map[string]*provenance.Node,
) []*ResultRow {

	// Bind this node
	bindings[path.Nodes[nodeIdx].Variable] = node

	// If we've matched all nodes, produce a result
	if nodeIdx >= len(path.Nodes)-1 {
		return []*ResultRow{e.buildRow(bindings, path)}
	}

	// Get the expected edge relation
	edgeRel := path.Edges[edgeIdx].Relation
	provRel := relationMapping[edgeRel]

	// Get next node label
	nextLabel := path.Nodes[nodeIdx+1].Label
	nextSubtype := labelToSubtype[nextLabel]

	// Traverse forward edges
	var rows []*ResultRow
	for _, e := range e.graph.Edges() {
		if e.Source != node.ID {
			continue
		}
		if provRel != "" && e.Relation != provRel {
			continue
		}

		targetNode, ok := e.graph.LookupNode(e.Target)
		if !ok || targetNode == nil {
			continue
		}
		if nextSubtype != "" && targetNode.Subtype != nextSubtype {
			continue
		}

		// Apply WHERE on target
		if !e.matchesWhere(targetNode, path.Nodes[nodeIdx+1].Variable, where) {
			continue
		}

		// Apply DURING filter on edge timestamp
		if during != nil {
			if e.Timestamp.Before(during.Start) || e.Timestamp.After(during.End) {
				continue
			}
		}

		// Recurse
		childRows := e.traverse(targetNode, path, nodeIdx+1, edgeIdx+1, where, during, copyBindings(bindings))
		rows = append(rows, childRows...)
	}

	return rows
}

// matchesWhere checks a node against WHERE conditions for its variable.
func (e *Executor) matchesWhere(n *provenance.Node, variable string, where []Condition) bool {
	for _, c := range where {
		if !strings.HasPrefix(c.Field, variable+".") {
			continue
		}
		field := strings.TrimPrefix(c.Field, variable+".")
		val := e.getField(n, field)
		if !e.evaluate(val, c.Op, c.Value) {
			return false
		}
	}
	return true
}

// getField extracts a named field from a node.
func (e *Executor) getField(n *provenance.Node, field string) string {
	switch strings.ToLower(field) {
	case "id":
		return n.ID
	case "label", "name", "comm":
		return n.Label
	case "type", "subtype":
		return n.Subtype
	case "pid":
		return fmt.Sprintf("%v", n.Attributes["pid"])
	case "uid":
		return fmt.Sprintf("%v", n.Attributes["uid"])
	case "inode":
		return fmt.Sprintf("%v", n.Attributes["inode"])
	case "path":
		return n.Label
	case "mode":
		return fmt.Sprintf("%v", n.Attributes["mode"])
	default:
		return fmt.Sprintf("%v", n.Attributes[field])
	}
}

// evaluate compares a node field value against a condition.
func (e *Executor) evaluate(actual string, op Op, expected string) bool {
	switch op {
	case OpEQ:
		return actual == expected
	case OpSTARTSWITH:
		return strings.HasPrefix(actual, expected)
	case OpCONTAINS:
		return strings.Contains(actual, expected)
	default:
		return actual == expected
	}
}

// buildRow creates a ResultRow from the current bindings.
func (e *Executor) buildRow(bindings map[string]*provenance.Node, path *PathPattern) *ResultRow {
	row := &ResultRow{Values: make(map[string]interface{})}
	for _, np := range path.Nodes {
		if n, ok := bindings[np.Variable]; ok && n != nil {
			row.Values[np.Variable] = n.ID
			row.Values[np.Variable+".id"] = n.ID
			row.Values[np.Variable+".label"] = n.Label
			row.Values[np.Variable+".type"] = n.Subtype
			for k, v := range n.Attributes {
				row.Values[np.Variable+"."+k] = v
			}
		}
	}
	return row
}

func copyBindings(src map[string]*provenance.Node) map[string]*provenance.Node {
	dst := make(map[string]*provenance.Node, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
