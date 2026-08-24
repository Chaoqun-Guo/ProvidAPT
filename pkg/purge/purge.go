// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package purge provides secure data destruction for ProvidAPT's PebbleDB store.
// It supports three modes: by time range, by capacity threshold, and compliance wipe.
package purge

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/cockroachdb/pebble"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/storage/store"
)

// PurgeMode defines the strategy for data deletion.
type PurgeMode int

const (
	// PurgeByTime deletes all data older than Cutoff.
	PurgeByTime PurgeMode = iota
	// PurgeByCapacity deletes oldest data until RemainingSize <= MaxBytes.
	PurgeByCapacity
	// PurgeCompliance performs a complete wipe of all data keys (preserves meta:*).
	PurgeCompliance
)

func (m PurgeMode) String() string {
	switch m {
	case PurgeByTime:
		return "by_time"
	case PurgeByCapacity:
		return "by_capacity"
	case PurgeCompliance:
		return "compliance"
	default:
		return "unknown"
	}
}

// PurgeConfig controls the purge operation.
type PurgeConfig struct {
	Mode      PurgeMode
	StorePath string    // Path to PebbleDB directory
	Cutoff    time.Time // For PurgeByTime: delete data older than this
	MaxBytes  int64     // For PurgeByCapacity: target remaining size
	DryRun    bool      // If true, only report what would be deleted
	EncKey    []byte    // Encryption key (nil = no encryption)
}

// PurgeReport contains the results of a purge operation.
type PurgeReport struct {
	NodesDeleted        int
	EdgesDeleted        int
	ReverseEdgesDeleted int
	TotalKeysDeleted    int
	BytesFreed          int64
	RemainingSize       int64
	Duration            time.Duration
	Mode                string
	DryRun              bool
}

// Execute performs a purge operation according to the given config.
func Execute(cfg *PurgeConfig) (*PurgeReport, error) {
	start := time.Now()

	// Open the store
	st, err := store.Open(cfg.StorePath, cfg.EncKey)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = st.Close() }()

	// Get initial disk usage
	before := st.DiskUsage()

	report := &PurgeReport{
		Mode:   cfg.Mode.String(),
		DryRun: cfg.DryRun,
	}

	// Retrieve the underlying pebble.DB for direct iteration
	db := st.UnderlyingDB()

	switch cfg.Mode {
	case PurgeByTime:
		err = purgeByTime(db, cfg, report)
	case PurgeByCapacity:
		err = purgeByCapacity(db, cfg, report)
	case PurgeCompliance:
		err = purgeCompliance(db, cfg, report)
	default:
		return nil, fmt.Errorf("unknown purge mode: %v", cfg.Mode)
	}

	if err != nil {
		return nil, err
	}

	// Flush pending writes if not dry-run
	if !cfg.DryRun {
		if err := db.Flush(); err != nil {
			return nil, fmt.Errorf("flush after purge: %w", err)
		}
	}

	report.Duration = time.Since(start)
	report.RemainingSize = st.DiskUsage()
	report.BytesFreed = before - report.RemainingSize
	if report.BytesFreed < 0 {
		report.BytesFreed = 0
	}

	log.Printf("[purge] %s: deleted %d keys (%d edges, %d reverse, %d nodes), freed %d bytes, remaining %d bytes (dry_run=%v, duration=%v)",
		cfg.Mode, report.TotalKeysDeleted, report.EdgesDeleted, report.ReverseEdgesDeleted, report.NodesDeleted,
		report.BytesFreed, report.RemainingSize, cfg.DryRun, report.Duration)

	return report, nil
}

// purgeByTime deletes all edges older than the cutoff time, plus orphaned nodes.
func purgeByTime(db *pebble.DB, cfg *PurgeConfig, r *PurgeReport) error {
	cutoffNano := uint64(cfg.Cutoff.UnixNano())
	// Format cutoff as zero-padded for comparison with edge keys
	cutoffKey := fmt.Sprintf("e:%020d", cutoffNano)

	iter, err := db.NewIter(nil)
	if err != nil {
		return fmt.Errorf("create iterator: %w", err)
	}
	defer func() { _ = iter.Close() }()

	// Track orphaned node IDs
	orphanNodes := make(map[string]bool)

	// Scan edges
	prefix := []byte("e:")
	for iter.SeekGE(prefix); iter.Valid(); iter.Next() {
		key := string(iter.Key())
		if !strings.HasPrefix(key, "e:") {
			break
		}
		if key >= cutoffKey {
			break // past the cutoff, remaining edges are newer
		}

		// Parse edge key format: e:<020d-ts>:<source>:<target>
		// Extract source and target from the edge
		parts := strings.SplitN(key, ":", 4)
		if len(parts) < 4 {
			continue
		}
		source := parts[2]
		target := parts[3]

		// Mark nodes as potentially orphaned
		orphanNodes[source] = true
		orphanNodes[target] = true

		if !cfg.DryRun {
			if err := db.Delete([]byte(key), pebble.NoSync); err != nil {
				return fmt.Errorf("delete edge %s: %w", key, err)
			}
		}
		r.EdgesDeleted++
		r.TotalKeysDeleted++

		// Delete reverse index: r:<target>:<020d-ts>:<source>
		revKey := fmt.Sprintf("r:%s:%020d:%s", target, cutoffNano, source)
		if !cfg.DryRun {
			if err := db.Delete([]byte(revKey), pebble.NoSync); err != nil {
				return fmt.Errorf("delete reverse edge %s: %w", revKey, err)
			}
		}
		r.ReverseEdgesDeleted++
		r.TotalKeysDeleted++
	}

	// Clean orphaned nodes — check if they still have any edges
	if len(orphanNodes) > 0 {
		for nodeID := range orphanNodes {
			hasRefs := hasRemainingEdges(db, nodeID)
			if !hasRefs {
				if !cfg.DryRun {
					nodeKey := "n:" + nodeID
					if err := db.Delete([]byte(nodeKey), pebble.NoSync); err != nil {
						return fmt.Errorf("delete orphan node %s: %w", nodeID, err)
					}
				}
				r.NodesDeleted++
				r.TotalKeysDeleted++
			}
		}
	}

	return nil
}

// purgeByCapacity deletes oldest data until disk usage is below MaxBytes.
func purgeByCapacity(db *pebble.DB, cfg *PurgeConfig, r *PurgeReport) error {
	// Get current metrics
	m := db.Metrics()
	currentSize := int64(m.DiskSpaceUsage())

	if currentSize <= cfg.MaxBytes {
		log.Printf("[purge] current size %d <= target %d, nothing to purge", currentSize, cfg.MaxBytes)
		return nil
	}

	targetFree := currentSize - cfg.MaxBytes
	var freed int64

	iter, err := db.NewIter(nil)
	if err != nil {
		return fmt.Errorf("create iterator: %w", err)
	}
	defer func() { _ = iter.Close() }()

	prefix := []byte("e:")
	for iter.SeekGE(prefix); iter.Valid(); iter.Next() {
		if freed >= targetFree {
			break
		}

		key := string(iter.Key())
		if !strings.HasPrefix(key, "e:") {
			break
		}

		valSize := int64(len(iter.Value()))
		keySize := int64(len(key))

		// Parse for reverse key
		parts := strings.SplitN(key, ":", 4)
		if len(parts) < 4 {
			continue
		}
		ts := parts[1]
		source := parts[2]
		target := parts[3]
		revKey := fmt.Sprintf("r:%s:%s:%s", target, ts, source)

		if !cfg.DryRun {
			if err := db.Delete([]byte(key), pebble.NoSync); err != nil {
				return fmt.Errorf("delete edge %s: %w", key, err)
			}
			if err := db.Delete([]byte(revKey), pebble.NoSync); err != nil {
				return fmt.Errorf("delete reverse %s: %w", revKey, err)
			}
		}
		r.EdgesDeleted++
		r.ReverseEdgesDeleted++
		r.TotalKeysDeleted += 2
		freed += keySize + valSize + int64(len(revKey)) + valSize

		// Delete orphan node
		orphanNodeKey := "n:" + source
		if !cfg.DryRun {
			if err := db.Delete([]byte(orphanNodeKey), pebble.NoSync); err != nil {
				return fmt.Errorf("delete node %s: %w", source, err)
			}
		}
		r.NodesDeleted++
		r.TotalKeysDeleted++
	}

	return nil
}

// purgeCompliance performs a complete wipe of all data keys (n:, e:, r:, idx:),
// preserving only meta: keys for operational continuity.
func purgeCompliance(db *pebble.DB, cfg *PurgeConfig, r *PurgeReport) error {
	prefixes := []string{"n:", "e:", "r:", "idx:"}

	iter, err := db.NewIter(nil)
	if err != nil {
		return fmt.Errorf("create iterator: %w", err)
	}
	defer func() { _ = iter.Close() }()

	for _, prefix := range prefixes {
		p := []byte(prefix)
		for iter.SeekGE(p); iter.Valid(); iter.Next() {
			key := string(iter.Key())
			if !strings.HasPrefix(key, prefix) {
				break
			}
			if !cfg.DryRun {
				if err := db.Delete([]byte(key), pebble.NoSync); err != nil {
					return fmt.Errorf("delete %s: %w", key, err)
				}
			}
			r.TotalKeysDeleted++
		}
	}

	r.NodesDeleted = r.TotalKeysDeleted // rough count for compliance, all keys are "data"
	return nil
}

// hasRemainingEdges checks if a node ID still has any edges referencing it.
func hasRemainingEdges(db *pebble.DB, nodeID string) bool {
	// Check forward edges referencing this node as source
	srcPrefix := []byte("e:")
	srcIter, err := db.NewIter(nil)
	if err != nil {
		return true // assume referenced on error
	}
	defer func() { _ = srcIter.Close() }()
	for srcIter.SeekGE(srcPrefix); srcIter.Valid(); srcIter.Next() {
		key := string(srcIter.Key())
		if !strings.HasPrefix(key, "e:") {
			break
		}
		if strings.Contains(key, ":"+nodeID) {
			return true
		}
	}

	// Check reverse edges referencing this node as target
	revPrefix := []byte("r:" + nodeID)
	revIter, err := db.NewIter(nil)
	if err != nil {
		return true
	}
	defer func() { _ = revIter.Close() }()
	return revIter.SeekGE(revPrefix) && revIter.Valid() && strings.HasPrefix(string(revIter.Key()), "r:"+nodeID)
}
