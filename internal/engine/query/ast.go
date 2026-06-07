// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package query implements a declarative graph query language (ProvQL)
// for threat hunting on provenance data.
//
// Syntax (inspired by Neo4j Cypher):
//
//   MATCH (p:Process)-[:WROTE]->(f:File)
//   WHERE f.path STARTSWITH '/etc'
//   DURING [2025-01-01T00:00:00Z, 2025-01-02T00:00:00Z]
//   RETURN p.pid, p.comm, f.path
//
// The query is translated to DFS traversals on the in-memory graph
// and/or RocksDB index scans with time-range filtering.
package query

import "time"

// ═══════════════════════════════════════════════════════════════
// Query AST
// ═══════════════════════════════════════════════════════════════

// Query is the root AST node.
type Query struct {
	Match    *PathPattern
	Where    []Condition
	During   *TimeWindow
	Return   []Projection
}

// PathPattern describes a graph traversal path:
// (node)-[edge]->(node)-[edge]->(node)
type PathPattern struct {
	Nodes []NodePattern  // sequence of node patterns
	Edges []EdgePattern  // edges between nodes (len = len(Nodes)-1)
}

// NodePattern matches a graph node.
type NodePattern struct {
	Variable string // binding variable name (e.g., "p", "f")
	Label    string // node type: Process, File, Network, Pipe, Memory, Credential
}

// EdgePattern matches a directed edge.
type EdgePattern struct {
	Relation string // WROTE, READ, FORKED, CONNECTED, DERIVED
}

// Condition is a WHERE clause predicate.
type Condition struct {
	Field    string   // e.g., "p.path", "f.path"
	Op       Op       // EQ, STARTSWITH, CONTAINS, GT, LT
	Value    string   // literal comparison value
}

// Op is a comparison operator.
type Op int

const (
	OpEQ        Op = iota // =
	OpSTARTSWITH          // STARTSWITH
	OpCONTAINS            // CONTAINS
	OpGT                  // >
	OpLT                  // <
	OpGTE                 // >=
	OpLTE                 // <=
)

func (o Op) String() string {
	switch o {
	case OpEQ:
		return "="
	case OpSTARTSWITH:
		return "STARTSWITH"
	case OpCONTAINS:
		return "CONTAINS"
	case OpGT:
		return ">"
	case OpLT:
		return "<"
	case OpGTE:
		return ">="
	case OpLTE:
		return "<="
	default:
		return "?"
	}
}

// TimeWindow bounds a query to a time range.
type TimeWindow struct {
	Start time.Time
	End   time.Time
}

// Projection selects fields to return.
type Projection struct {
	Variable string // node variable, e.g., "p"
	Field    string // field name, e.g., "pid", "comm", "path"
}

// ── Query result ────────────────────────────────────────────

// ResultRow is a single match row.
type ResultRow struct {
	Values map[string]interface{} // field name → value
}

// Result holds all matching rows.
type Result struct {
	Columns []string      // projected field names
	Rows    []*ResultRow
	Elapsed time.Duration
}

// ── Map PROV labels to internal types ─────────────────────

var labelToSubtype = map[string]string{
	"Process":     "process",
	"File":        "file",
	"Network":     "network",
	"Pipe":        "pipe",
	"Memory":      "memory",
	"Credential":  "credential",
}

var labelToProvType = map[string]string{
	"Process":    "prov:Activity",
	"File":       "prov:Entity",
	"Network":    "prov:Entity",
	"Pipe":       "prov:Entity",
	"Memory":     "prov:Entity",
	"Credential": "prov:Entity",
}

// relationMapping maps query relation names to PROV relations.
var relationMapping = map[string]string{
	"WROTE":     "prov:wasGeneratedBy",
	"READ":      "prov:used",
	"FORKED":    "prov:wasInformedBy",
	"CONNECTED": "prov:used",
	"DERIVED":   "prov:wasDerivedFrom",
	"CONTEXT":   "prov:hadSecurityContext",
}

// ReverseRelation maps PROV relations to query names.
var ReverseRelation = map[string]string{
	"prov:used":              "READ",
	"prov:wasGeneratedBy":    "WROTE",
	"prov:wasInformedBy":     "FORKED",
	"prov:wasDerivedFrom":   "DERIVED",
	"prov:hadSecurityContext": "CONTEXT",
}
