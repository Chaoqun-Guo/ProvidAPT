// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package provenance

import "time"

// Edge is a directed relation in the provenance graph.
// It follows the W3C PROV semantics:
//
//   prov:used           Activity → Entity         (process read a file)
//   prov:wasGeneratedBy Entity   → Activity         (file was written by process)
//   prov:wasInformedBy  Activity → Activity         (child was informed by parent)
//
// In the internal representation:
//   Source and Target are Node IDs.
//   The direction is the natural PROV direction (source → target in the
//   PROV statement sense, not necessarily the temporal arrow).
type Edge struct {
	// ID is a unique edge identifier (relation + source → target + dedup count).
	ID string `json:"id"`

	// Source node ID (the subject of the PROV statement).
	Source string `json:"source"`

	// Target node ID (the object of the PROV statement).
	Target string `json:"target"`

	// Relation is the PROV relation type.
	Relation string `json:"relation"`

	// Timestamp when the relation was observed.
	Timestamp time.Time `json:"timestamp"`

	// Count aggregates duplicate edges (same relation, source, target).
	// Useful when a process reads the same file many times.
	Count int `json:"count"`

	// Attributes carry additional metadata about the relation.
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// newEdge creates an Edge with count=1.
func newEdge(id, relation, source, target string, ts time.Time) *Edge {
	return &Edge{
		ID:         id,
		Source:     source,
		Target:     target,
		Relation:   relation,
		Timestamp:  ts,
		Count:      1,
		Attributes: make(map[string]interface{}),
	}
}

// merge absorbs another occurrence of the same logical edge.
func (e *Edge) merge(ts time.Time) {
	e.Count++
	if ts.After(e.Timestamp) {
		e.Timestamp = ts
	}
}
