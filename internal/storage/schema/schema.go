// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package schema defines the RocksDB key encoding for ProvidAPT v2.
//
// Key space design (all keys are lexicographically sortable strings):
//
//	Node storage:
//	  n:<type>:<id>           → protobuf(Node)         // Primary node storage
//
//	Edge storage (time-range ordered):
//	  e:<ts_hex>:<src>:<tgt>  → protobuf(Edge)         // Primary edge, ordered by time
//	  r:<tgt>:<ts_hex>:<src>  → protobuf(Edge)         // Reverse index for backward traversal
//
//	Secondary indexes:
//	  idx:pid:<pid>:<node_id>  → ""                     // PID → Node lookup
//	  idx:inode:<inode>:<dev_major>:<dev_minor>:<node_id> → ""  // Inode → Node lookup
//
//	Metadata:
//	  meta:<key>              → string                 // System metadata (version, etc.)
//
// The <ts_hex> field is a 16-character lowercase hex string
// representing the upper 64 bits of the nanosecond timestamp,
// enabling efficient time-range prefix scans.
package schema

import (
	"fmt"
	"strings"
)

// Constants
const (
	nodePrefix     = "n:"
	edgePrefix     = "e:"
	reversePrefix  = "r:"
	idxPIDPrefix   = "idx:pid:"
	idxInodePrefix = "idx:inode:"
	metaPrefix     = "meta:"
)

// ─── Key builders ──────────────────────────────────────────

// NodeKey returns the storage key for a node.
// Format: "n:<type>:<id>"
// Example: "n:process:p:1234", "n:file:f:5000:8:3"
func NodeKey(nodeType, nodeID string) string {
	return fmt.Sprintf("%s%s:%s", nodePrefix, nodeType, nodeID)
}

// EdgeKey returns a time-ordered storage key for an edge.
// Format: "e:<16-hex-ts>|<source>|<target>"
// Uses | as delimiter after timestamp since source/target IDs may contain colons.
// The 16-hex-ts prefix enables range scans by time.
func EdgeKey(timestamp uint64, source, target string) string {
	ts := fmt.Sprintf("%016x", timestamp)
	return fmt.Sprintf("%s%s|%s|%s", edgePrefix, ts, source, target)
}

// ReverseEdgeKey returns a reverse-index key for backward traversal.
// Format: "r:<target>|<16-hex-ts>|<source>"
// Target comes first to enable prefix scans for all edges pointing to a target.
func ReverseEdgeKey(timestamp uint64, target, source string) string {
	ts := fmt.Sprintf("%016x", timestamp)
	return fmt.Sprintf("%s%s|%s|%s", reversePrefix, target, ts, source)
}

// PIDIndexKey returns the index key for a PID.
// Format: "idx:pid:<pid>:<node_id>"
func PIDIndexKey(pid uint32, nodeID string) string {
	return fmt.Sprintf("%s%d:%s", idxPIDPrefix, pid, nodeID)
}

// InodeIndexKey returns the index key for an inode.
// Format: "idx:inode:<inode>:<dev_major>:<dev_minor>:<node_id>"
func InodeIndexKey(inode uint64, devMajor, devMinor uint32, nodeID string) string {
	return fmt.Sprintf("%s%d:%d:%d:%s", idxInodePrefix, inode, devMajor, devMinor, nodeID)
}

// MetaKey returns a metadata key.
func MetaKey(key string) string {
	return metaPrefix + key
}

// ─── Key parsing ──────────────────────────────────────────

// ParseNodeKey extracts type and ID from a node key.
func ParseNodeKey(key string) (nodeType, nodeID string, ok bool) {
	rest, found := strings.CutPrefix(key, nodePrefix)
	if !found {
		return "", "", false
	}
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// EdgeTimeRange returns the start and end keys for a time-range scan.
// Scans [startKey, endKey) for edges in [startNs, endNs).
func EdgeTimeRange(startNs, endNs uint64) (startKey, endKey string) {
	startKey = fmt.Sprintf("%s%016x|", edgePrefix, startNs)
	endKey = fmt.Sprintf("%s%016x|", edgePrefix, endNs)
	return
}

// ─── Prefix scanners ──────────────────────────────────────

// EdgePrefix returns the prefix for all edge keys.
func EdgePrefix() string { return edgePrefix }

// NodePrefix returns the prefix for all node keys.
func NodePrefix() string { return nodePrefix }

// PIDIndexPrefix returns the prefix for all PID index entries.
func PIDIndexPrefix(pid uint32) string {
	return fmt.Sprintf("%s%d:", idxPIDPrefix, pid)
}

// InodeIndexPrefix returns the prefix for an inode index.
func InodeIndexPrefix(inode uint64) string {
	return fmt.Sprintf("%s%d:", idxInodePrefix, inode)
}

// ─── Source node ID extraction ───────────────────────────

// ParseEdgeKey extracts source, target, and timestamp from an edge key.
// Format: "e:<16-hex-ts>|<source>|<target>"
func ParseEdgeKey(key string) (source, target string, ts uint64, ok bool) {
	rest, found := strings.CutPrefix(key, edgePrefix)
	if !found || len(rest) < 17 || rest[16] != '|' {
		return "", "", 0, false
	}
	tsHex := rest[:16]
	if _, err := fmt.Sscanf(tsHex, "%x", &ts); err != nil {
		return "", "", 0, false
	}
	remaining := rest[17:] // skip ts + delimiter
	if remaining == "" {
		return "", "", 0, false
	}
	parts := strings.SplitN(remaining, "|", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", 0, false
	}
	return parts[0], parts[1], ts, true
}
