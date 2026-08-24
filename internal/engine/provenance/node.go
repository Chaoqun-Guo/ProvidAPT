// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package provenance

import "time"

// Node is a vertex in the provenance graph, typed according to
// the W3C PROV data model.
type Node struct {
	// ID is the unique identifier within this graph instance.
	// Format: <prefix>:<key>  (e.g. "p:1234", "f:1024:8:3")
	ID string `json:"id"`

	// ProvType is the PROV type: prov:Activity, prov:Entity, or prov:Agent.
	ProvType string `json:"prov_type"`

	// Subtype is our domain-specific refinement: process, file, or network.
	Subtype string `json:"subtype"`

	// Label is a human-readable name (comm, pathname, or address).
	Label string `json:"label"`

	// FirstSeen / LastSeen bound the node's lifetime in the graph.
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	// Attributes carry domain-specific metadata.
	// Examples: pid, uid, inode, mode, device, f_flags.
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// newNode creates a Node and initializes its attribute map.
func newNode(id, provType, subtype, label string, ts time.Time) *Node {
	return &Node{
		ID:         id,
		ProvType:   provType,
		Subtype:    subtype,
		Label:      label,
		FirstSeen:  ts,
		LastSeen:   ts,
		Attributes: make(map[string]interface{}),
	}
}

// touch updates the LastSeen timestamp.
func (n *Node) touch(ts time.Time) {
	if ts.After(n.LastSeen) {
		n.LastSeen = ts
	}
}

// setAttr sets an attribute if not already present (first-write-wins).
func (n *Node) setAttr(k string, v interface{}) {
	if _, ok := n.Attributes[k]; !ok {
		n.Attributes[k] = v
	}
}

// upsertAttr sets or overwrites an attribute.
func (n *Node) upsertAttr(k string, v interface{}) {
	n.Attributes[k] = v
}
