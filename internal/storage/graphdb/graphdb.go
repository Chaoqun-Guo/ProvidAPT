// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package store implements the central server storage layer for ProvidAPT v2.2.
//
// Features:
//   1. Graph database connector — Neo4j/JanusGraph for global graph
//   2. Global indexing — HostID, Identity, IP for millisecond backtracking
//   3. Data lifecycle — 30-day archive, hot/cold separation
package graphdb

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Graph database abstraction
// ═══════════════════════════════════════════════════════════════

// GraphDB is the interface for graph database operations.
// Supports Neo4j, JanusGraph, or any Cypher-compatible backend.
type GraphDB interface {
	// CreateNode creates a global node and returns its ID.
	CreateNode(nodeType, id, label string, props map[string]interface{}) (string, error)

	// CreateEdge creates a global edge between two nodes.
	CreateEdge(sourceID, targetID, relation string, props map[string]interface{}) (string, error)

	// QueryNodes finds nodes matching the given criteria.
	QueryNodes(label string, props map[string]interface{}) ([]map[string]interface{}, error)

	// QueryPaths finds paths between two nodes within maxHops.
	QueryPaths(sourceID, targetID string, maxHops int) ([]map[string]interface{}, error)

	// Close shuts down the connection.
	Close() error
}

// GlobalNode is the universal node format for the global graph.
type GlobalNode struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"` // "process", "file", "network"
	Label     string                 `json:"label"`
	HostID    string                 `json:"host_id"`
	AgentID   string                 `json:"agent_id"`
	Props     map[string]interface{} `json:"props,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// GlobalEdge is the universal edge format for the global graph.
type GlobalEdge struct {
	Source   string                 `json:"source"`
	Target   string                 `json:"target"`
	Relation string                 `json:"relation"`
	HostID   string                 `json:"host_id"`
	Props    map[string]interface{} `json:"props,omitempty"`
	Time     time.Time              `json:"time"`
}

// ─── In-memory graph database (fallback) ───────────────────

// MemGraphDB is an in-memory graph database for development/testing.
// In production, replace with Neo4j/JanusGraph connector.
type MemGraphDB struct {
	mu    sync.RWMutex
	nodes map[string]*GlobalNode
	edges []*GlobalEdge
}

// NewMemGraphDB creates an in-memory graph database.
func NewMemGraphDB() *MemGraphDB {
	return &MemGraphDB{
		nodes: make(map[string]*GlobalNode),
	}
}

func (db *MemGraphDB) CreateNode(nodeType, id, label string, props map[string]interface{}) (string, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	node := &GlobalNode{
		ID:        id,
		Type:      nodeType,
		Label:     label,
		Props:     props,
		CreatedAt: time.Now(),
	}
	if hostID, ok := props["host_id"].(string); ok {
		node.HostID = hostID
	}
	if agentID, ok := props["agent_id"].(string); ok {
		node.AgentID = agentID
	}

	db.nodes[id] = node
	log.Printf("[graphdb] node: %s (%s) host=%s", label, nodeType, node.HostID)
	return id, nil
}

func (db *MemGraphDB) CreateEdge(sourceID, targetID, relation string, props map[string]interface{}) (string, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	edge := &GlobalEdge{
		Source:   sourceID,
		Target:   targetID,
		Relation: relation,
		Props:    props,
		Time:     time.Now(),
	}
	if hostID, ok := props["host_id"].(string); ok {
		edge.HostID = hostID
	}
	db.edges = append(db.edges, edge)

	return fmt.Sprintf("e:%s-%s-%s", sourceID, targetID, relation), nil
}

func (db *MemGraphDB) QueryNodes(label string, props map[string]interface{}) ([]map[string]interface{}, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var results []map[string]interface{}
	for _, node := range db.nodes {
		if strings.EqualFold(node.Type, label) || label == "" {
			if matchProps(node.Props, props) {
				results = append(results, map[string]interface{}{
					"id": node.ID, "type": node.Type, "label": node.Label,
					"host_id": node.HostID, "agent_id": node.AgentID,
				})
			}
		}
	}
	return results, nil
}

func (db *MemGraphDB) QueryPaths(sourceID, targetID string, maxHops int) ([]map[string]interface{}, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// BFS to find paths between source and target
	type bfsItem struct {
		id    string
		path  []string
		depth int
	}
	visited := make(map[string]bool)
	queue := []bfsItem{{id: sourceID, path: []string{sourceID}, depth: 0}}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if visited[curr.id] {
			continue
		}
		visited[curr.id] = true

		for _, edge := range db.edges {
			var next string
			if edge.Source == curr.id {
				next = edge.Target
			} else if edge.Target == curr.id {
				next = edge.Source
			} else {
				continue
			}

			if next == targetID {
				path := append(curr.path, next)
				return []map[string]interface{}{
					{"path": path, "length": len(path)},
				}, nil
			}

			if curr.depth < maxHops && !visited[next] {
				newPath := make([]string, len(curr.path)+1)
				copy(newPath, curr.path)
				newPath[len(curr.path)] = next
				queue = append(queue, bfsItem{id: next, path: newPath, depth: curr.depth + 1})
			}
		}
	}
	return nil, nil
}

func (db *MemGraphDB) Close() error { return nil }

func matchProps(nodeProps map[string]interface{}, query map[string]interface{}) bool {
	for k, v := range query {
		if nodeVal, ok := nodeProps[k]; !ok || fmt.Sprint(nodeVal) != fmt.Sprint(v) {
			return false
		}
	}
	return true
}

// ─── Insert subgraph ─────────────────────────────────────────

// InsertSubgraph inserts an agent-reported subgraph into the global graph.
func InsertSubgraph(db GraphDB, nodes []GlobalNode, edges []GlobalEdge) error {
	for _, n := range nodes {
		props := map[string]interface{}{
			"host_id":  n.HostID,
			"agent_id": n.AgentID,
		}
		for k, v := range n.Props {
			props[k] = v
		}
		if _, err := db.CreateNode(n.Type, n.ID, n.Label, props); err != nil {
			return fmt.Errorf("create node: %w", err)
		}
	}
	for _, e := range edges {
		props := map[string]interface{}{
			"host_id": e.HostID,
		}
		for k, v := range e.Props {
			props[k] = v
		}
		if _, err := db.CreateEdge(e.Source, e.Target, e.Relation, props); err != nil {
			return fmt.Errorf("create edge: %w", err)
		}
	}
	return nil
}

// Stats returns graph database statistics.
func (db *MemGraphDB) Stats() map[string]interface{} {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return map[string]interface{}{
		"nodes": len(db.nodes),
		"edges": len(db.edges),
	}
}
