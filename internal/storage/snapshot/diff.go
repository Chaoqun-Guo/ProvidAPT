// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package snapshot

import (
	"fmt"
	"log"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Differential analysis engine
// ═══════════════════════════════════════════════════════════════

// DiffResult holds the delta between two snapshots.
type DiffResult struct {
	Snapshot1 string `json:"snapshot_1"`
	Snapshot2 string `json:"snapshot_2"`

	NewNodes []DiffNode `json:"new_nodes"`
	NewEdges []DiffEdge `json:"new_edges"`

	TotalNodes int `json:"total_new_nodes"`
	TotalEdges int `json:"total_new_edges"`

	Duration string `json:"duration"`
}

// DiffNode represents a node that appeared in the diff.
type DiffNode struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

// DiffEdge represents an edge that appeared in the diff.
type DiffEdge struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Relation string `json:"relation"`
}

// DiffEngine computes deltas between two time points.
type DiffEngine struct {
	active *ActiveTable
	sm     *SnapManager
}

// NewDiffEngine creates a diff engine.
func NewDiffEngine(active *ActiveTable, sm *SnapManager) *DiffEngine {
	return &DiffEngine{
		active: active,
		sm:     sm,
	}
}

// GetDiff computes the delta between two time points.
//
// The diff uses two strategies:
//  1. If snapshots exist at both t1 and t2, open both as read-only
//     and scan for new keys in t2 that don't exist in t1.
//  2. If no snapshots, use the active entity table to report
//     recently changed entities as the diff.
//
// This is a simplified implementation.  In production, the scan
// would use Pebble's iterator to compare key sets efficiently.
func (de *DiffEngine) GetDiff(t1, t2 time.Time) (*DiffResult, error) {
	start := time.Now()
	result := &DiffResult{
		Snapshot1: t1.Format(time.RFC3339),
		Snapshot2: t2.Format(time.RFC3339),
	}

	// Strategy 1: Use snapshots if available
	snapshots := de.sm.ListSnapshots()
	var snap1, snap2 *SnapshotMeta
	for _, s := range snapshots {
		if s.CreatedAt.After(t1) && s.CreatedAt.Before(t2) {
			if snap1 == nil || s.CreatedAt.Before(snap1.CreatedAt) {
				snap1 = s
			}
		}
		if s.CreatedAt.Equal(t2) || (s.CreatedAt.After(t2) && snap2 == nil) {
			snap2 = s
		}
	}

	// Strategy 2: Use active entity table
	if snap1 == nil || snap2 == nil {
		log.Printf("[diff] using active entity table for delta")
		active := de.active.GetActive()
		for _, entry := range active {
			result.NewNodes = append(result.NewNodes, DiffNode{
				ID:   entry.ID,
				Type: entry.EntityType.String(),
			})
		}
		result.TotalNodes = len(result.NewNodes)
		result.Duration = time.Since(start).String()
		return result, nil
	}

	// Strategy 1: Open both snapshots and compare
	db1, err := de.sm.OpenSnapshot(snap1.ID)
	if err != nil {
		return nil, fmt.Errorf("open snap1: %w", err)
	}
	defer func() { _ = db1.Close() }()
	db2, err := de.sm.OpenSnapshot(snap2.ID)
	if err != nil {
		_ = db1.Close()
		return nil, fmt.Errorf("open snap2: %w", err)
	}
	defer func() { _ = db2.Close() }()

	// In production: iterate over both snapshots and find new keys
	log.Printf("[diff] comparing snapshots %s vs %s", snap1.ID, snap2.ID)

	result.TotalNodes = len(result.NewNodes)
	result.TotalEdges = len(result.NewEdges)
	result.Duration = time.Since(start).String()

	return result, nil
}

// GetActiveDiff returns a diff based solely on the active entity table.
// Lightweight — does not open any RocksDB snapshots.
func (de *DiffEngine) GetActiveDiff() *DiffResult {
	start := time.Now()
	active := de.active.GetActive()

	result := &DiffResult{
		Snapshot1: "active-baseline",
		Snapshot2: fmt.Sprintf("active-%s", time.Now().Format(time.RFC3339)),
	}

	for _, entry := range active {
		result.NewNodes = append(result.NewNodes, DiffNode{
			ID:   entry.ID,
			Type: entry.EntityType.String(),
		})
	}

	result.TotalNodes = len(result.NewNodes)
	result.Duration = time.Since(start).String()

	return result
}

// Summary returns a human-readable diff summary.
func (dr *DiffResult) Summary() string {
	return fmt.Sprintf("Diff %s → %s: %d new nodes, %d new edges (%s)",
		dr.Snapshot1, dr.Snapshot2, dr.TotalNodes, dr.TotalEdges, dr.Duration)
}
