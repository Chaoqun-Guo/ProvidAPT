// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package dsl

import (
	"fmt"
	"strings"

	store "github.com/Chaoqun-Guo/ProvidAPT/internal/storage/pebblestore"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/storage/schema"
)

// ═══════════════════════════════════════════════════════════════
// Query executor with RocksDB prefix-scan acceleration
// ═══════════════════════════════════════════════════════════════

// Executor runs chain queries against the RocksDB store.
type Executor struct {
	store *store.Store
}

// NewExecutor creates a query executor.
func NewExecutor(st *store.Store) *Executor {
	return &Executor{store: st}
}

// ChainNode is a single node in the aggregated result chain.
type ChainNode struct {
	ID       string `json:"id"`
	Type     string `json:"type"`  // "process", "file", "network"
	Label    string `json:"label"` // comm, file path, IP
	PID      uint32 `json:"pid,omitempty"`
	Depth    int    `json:"depth"`
	Relation string `json:"relation,omitempty"` // how we reached this node
}

// ChainResult is the aggregated output.
type ChainResult struct {
	Chain []ChainNode `json:"chain"`
	Total int         `json:"total"`
	Query string      `json:"query"`
}

// Execute runs a parsed chain query.
func (exe *Executor) Execute(q *Query) (*ChainResult, error) {
	if len(q.Steps) == 0 {
		return nil, fmt.Errorf("empty query")
	}

	result := &ChainResult{Query: q.String()}

	// Step 1: Find initial nodes
	first := q.Steps[0]
	if first.Action != "find" {
		return nil, fmt.Errorf("query must start with find")
	}

	nodes, err := exe.findNodes(first)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return result, nil
	}

	// Add initial nodes to result
	for _, n := range nodes {
		n.Depth = 0
		result.Chain = append(result.Chain, n)
	}

	// Step 2+: Follow chain for each node
	currentNodes := nodes
	for stepIdx := 1; stepIdx < len(q.Steps); stepIdx++ {
		step := q.Steps[stepIdx]
		var nextNodes []ChainNode

		for _, cn := range currentNodes {
			children, err := exe.executeStep(cn, step, stepIdx)
			if err != nil {
				return nil, err
			}
			nextNodes = append(nextNodes, children...)
		}

		result.Chain = append(result.Chain, nextNodes...)
		currentNodes = nextNodes
	}

	result.Total = len(result.Chain)
	return result, nil
}

// findNodes resolves the initial find step.
func (exe *Executor) findNodes(step QueryStep) ([]ChainNode, error) {
	var nodes []ChainNode
	prefix := schema.NodePrefix()

	// Use RocksDB prefix scan for efficient node lookup
	// In production, iterate over the store's node keys
	iter, err := exe.store.GetDB().NewIter(nil)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	for iter.SeekGE([]byte(prefix)); iter.Valid(); iter.Next() {
		key := string(iter.Key())
		if !strings.HasPrefix(key, prefix) {
			break
		}

		// Parse node type from key: "n:<type>:<id>"
		rest := strings.TrimPrefix(key, prefix)
		parts := strings.SplitN(rest, ":", 2)
		if len(parts) < 2 {
			continue
		}
		nodeType := parts[0]
		nodeID := parts[1]

		// Filter by requested node type
		if !matchType(nodeType, step.NodeType) {
			continue
		}

		// Filter by where clause (field matching)
		if step.Field != "" && !matchField(step.Field, step.Value, key, nil) {
			continue
		}

		cn := ChainNode{
			ID:    nodeID,
			Type:  nodeType,
			Label: nodeID,
		}
		nodes = append(nodes, cn)
	}

	if nodes == nil {
		nodes = []ChainNode{} // empty, not nil
	}
	return nodes, nil
}

// executeStep runs one chain step from a source node.
func (exe *Executor) executeStep(source ChainNode, step QueryStep, depth int) ([]ChainNode, error) {
	switch step.Action {
	case "follow":
		return exe.followEdges(source, step.Direction, depth)
	case "edge":
		return exe.followRelation(source, step.Relation, depth)
	case "find":
		return exe.findLinked(source, step, depth)
	default:
		return nil, fmt.Errorf("unknown action: %s", step.Action)
	}
}

// followEdges traverses child or parent edges via prefix scan.
func (exe *Executor) followEdges(source ChainNode, direction string, depth int) ([]ChainNode, error) {
	prefix := schema.EdgePrefix()
	iter, err := exe.store.GetDB().NewIter(nil)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	seen := make(map[string]bool)
	var nodes []ChainNode

	for iter.SeekGE([]byte(prefix)); iter.Valid(); iter.Next() {
		key := string(iter.Key())
		if !strings.HasPrefix(key, prefix) {
			break
		}

		src, tgt, _, ok := schema.ParseEdgeKey(key)
		if !ok {
			continue
		}

		targetID := ""
		switch direction {
		case "child":
			if src == source.ID {
				targetID = tgt
			}
		case "parent":
			if tgt == source.ID {
				targetID = src
			}
		}

		if targetID != "" && !seen[targetID] {
			seen[targetID] = true
			nodes = append(nodes, ChainNode{
				ID:       targetID,
				Type:     inferType(targetID),
				Label:    targetID,
				Depth:    depth,
				Relation: direction,
			})
		}
	}
	return nodes, nil
}

// followRelation filters edges by relation type (read/write/connect/fork).
func (exe *Executor) followRelation(source ChainNode, relation string, depth int) ([]ChainNode, error) {
	prefix := schema.EdgePrefix()
	iter, err := exe.store.GetDB().NewIter(nil)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	provRel := relationToPROV(relation)
	seen := make(map[string]bool)
	var nodes []ChainNode

	for iter.SeekGE([]byte(prefix)); iter.Valid(); iter.Next() {
		key := string(iter.Key())
		if !strings.HasPrefix(key, prefix) {
			break
		}
		if !strings.Contains(key, source.ID) {
			continue
		}

		src, tgt, _, ok := schema.ParseEdgeKey(key)
		if !ok {
			continue
		}

		targetID := ""
		if src == source.ID {
			targetID = tgt
		} else if tgt == source.ID && provRel == "used" {
			targetID = src
		}

		if targetID != "" && !seen[targetID] {
			seen[targetID] = true
			nodes = append(nodes, ChainNode{
				ID:       targetID,
				Type:     inferType(targetID),
				Label:    targetID,
				Depth:    depth,
				Relation: relation,
			})
		}
	}
	return nodes, nil
}

// findLinked finds nodes of a specific type linked to the source.
func (exe *Executor) findLinked(source ChainNode, step QueryStep, depth int) ([]ChainNode, error) {
	children, err := exe.followEdges(source, "child", depth)
	if err != nil {
		return nil, err
	}
	var filtered []ChainNode
	for _, cn := range children {
		if matchType(cn.Type, step.NodeType) {
			if step.Field == "" || matchField(step.Field, step.Value, cn.ID, &cn) {
				filtered = append(filtered, cn)
			}
		}
	}
	return filtered, nil
}

// ─── Chain formatting ───────────────────────────────────────

// FormatChain returns a human-readable chain visualization.
func FormatChain(result *ChainResult) string {
	if len(result.Chain) == 0 {
		return "No results found."
	}

	var b strings.Builder
	currentDepth := 0
	b.WriteString("Provenance Chain:\n")

	for _, cn := range result.Chain {
		if cn.Depth > currentDepth {
			currentDepth = cn.Depth
		}
		prefix := "  "
		for i := 0; i < cn.Depth; i++ {
			prefix += "  "
		}

		marker := "├─"
		if cn.Depth == 0 {
			marker = "●"
		}

		line := fmt.Sprintf("%s%s [%s] %s", prefix, marker, cn.Type, cn.Label)
		if cn.Relation != "" {
			line += fmt.Sprintf(" (%s)", cn.Relation)
		}
		if cn.PID > 0 {
			line += fmt.Sprintf(" pid=%d", cn.PID)
		}
		b.WriteString(line + "\n")
	}

	return b.String()
}

// ─── Helpers ────────────────────────────────────────────────

func matchType(nodeType, pattern string) bool {
	if pattern == "" {
		return true
	}
	switch pattern {
	case "process":
		return strings.HasPrefix(nodeType, "p")
	case "file":
		return strings.HasPrefix(nodeType, "f")
	case "network":
		return strings.HasPrefix(nodeType, "n")
	default:
		return nodeType == pattern
	}
}

func matchField(field, value, key string, cn *ChainNode) bool {
	// Simple field matching: check if the value appears in the key
	switch field {
	case "name", "comm", "label":
		return strings.Contains(key, value)
	case "pid":
		return strings.Contains(key, ":"+value)
	case "path":
		return strings.Contains(key, value)
	case "addr", "ip":
		return strings.Contains(key, value)
	default:
		return true
	}
}

func inferType(id string) string {
	if len(id) == 0 {
		return "unknown"
	}
	switch id[0] {
	case 'p':
		return "process"
	case 'f':
		return "file"
	case 'n':
		return "network"
	case 'v':
		return "version"
	default:
		return "entity"
	}
}

func relationToPROV(rel string) string {
	switch rel {
	case "read":
		return "used"
	case "write":
		return "wasGeneratedBy"
	case "fork":
		return "wasInformedBy"
	case "connect":
		return "used"
	default:
		return ""
	}
}
