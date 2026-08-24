// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package graphdb

import (
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Global indexes — HostID, Identity, IP
// ═══════════════════════════════════════════════════════════════

// GlobalIndex provides millisecond-level lookup for cross-host backtracking.
type GlobalIndex struct {
	mu       sync.RWMutex
	byHostID map[string]map[string]*IndexEntry // hostID → {nodeID → entry}
	byIP     map[string]map[string]*IndexEntry // IP → {nodeID → entry}
	byIdent  map[string]map[string]*IndexEntry // identity → {nodeID → entry}
}

// IndexEntry stores the minimum metadata for index lookup.
type IndexEntry struct {
	NodeID    string    `json:"node_id"`
	NodeType  string    `json:"node_type"`
	Label     string    `json:"label"`
	HostID    string    `json:"host_id"`
	AgentID   string    `json:"agent_id"`
	Timestamp time.Time `json:"timestamp"`
}

// NewGlobalIndex creates a global index.
func NewGlobalIndex() *GlobalIndex {
	return &GlobalIndex{
		byHostID: make(map[string]map[string]*IndexEntry),
		byIP:     make(map[string]map[string]*IndexEntry),
		byIdent:  make(map[string]map[string]*IndexEntry),
	}
}

// IndexNode indexes a node by HostID, Identity, and IP.
func (gi *GlobalIndex) IndexNode(node *GlobalNode) {
	gi.mu.Lock()
	defer gi.mu.Unlock()

	entry := &IndexEntry{
		NodeID:    node.ID,
		NodeType:  node.Type,
		Label:     node.Label,
		HostID:    node.HostID,
		AgentID:   node.AgentID,
		Timestamp: time.Now(),
	}

	// By HostID
	if node.HostID != "" {
		if gi.byHostID[node.HostID] == nil {
			gi.byHostID[node.HostID] = make(map[string]*IndexEntry)
		}
		gi.byHostID[node.HostID][node.ID] = entry
	}

	// By Identity (from props)
	if ident, ok := node.Props["identity"].(string); ok && ident != "" {
		if gi.byIdent[ident] == nil {
			gi.byIdent[ident] = make(map[string]*IndexEntry)
		}
		gi.byIdent[ident][node.ID] = entry
	}

	// By IP (from label or props)
	ips := extractIPs(node)
	for _, ip := range ips {
		if gi.byIP[ip] == nil {
			gi.byIP[ip] = make(map[string]*IndexEntry)
		}
		gi.byIP[ip][node.ID] = entry
	}
}

// QueryByHostID returns all nodes from a host.
func (gi *GlobalIndex) QueryByHostID(hostID string) []*IndexEntry {
	gi.mu.RLock()
	defer gi.mu.RUnlock()
	return gi.collect(gi.byHostID[hostID])
}

// QueryByIP returns all nodes associated with an IP.
func (gi *GlobalIndex) QueryByIP(ip string) []*IndexEntry {
	gi.mu.RLock()
	defer gi.mu.RUnlock()
	return gi.collect(gi.byIP[ip])
}

// QueryByIdentity returns all nodes associated with a user identity.
func (gi *GlobalIndex) QueryByIdentity(identity string) []*IndexEntry {
	gi.mu.RLock()
	defer gi.mu.RUnlock()
	return gi.collect(gi.byIdent[identity])
}

// GlobalBacktrack finds the origin host for a given node ID.
// Returns the host path: ["host-a", "host-b", ...]
func (gi *GlobalIndex) GlobalBacktrack(nodeID string) []string {
	gi.mu.RLock()
	defer gi.mu.RUnlock()

	// Search all indexes for the node ID
	for hostID, entries := range gi.byHostID {
		if _, ok := entries[nodeID]; ok {
			return []string{hostID}
		}
	}
	return nil
}

func (gi *GlobalIndex) collect(m map[string]*IndexEntry) []*IndexEntry {
	if m == nil {
		return nil
	}
	out := make([]*IndexEntry, 0, len(m))
	for _, entry := range m {
		out = append(out, entry)
	}
	return out
}

// extractIPs extracts IP addresses from a node.
func extractIPs(node *GlobalNode) []string {
	var ips []string

	// Check label for IP pattern
	label := node.Label
	if strings.Contains(label, ".") && !strings.Contains(label, "/") {
		ips = append(ips, label)
	}

	// Check props for IP fields
	for _, key := range []string{"ip", "src_ip", "dst_ip", "addr"} {
		if v, ok := node.Props[key].(string); ok && v != "" {
			ips = append(ips, v)
		}
	}

	return ips
}

// Stats returns index statistics.
func (gi *GlobalIndex) Stats() map[string]interface{} {
	gi.mu.RLock()
	defer gi.mu.RUnlock()
	return map[string]interface{}{
		"by_host_id":  len(gi.byHostID),
		"by_ip":       len(gi.byIP),
		"by_identity": len(gi.byIdent),
	}
}
