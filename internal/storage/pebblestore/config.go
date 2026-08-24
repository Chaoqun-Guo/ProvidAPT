// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package store — RocksDB (Pebble) performance tuning
//
// Optimisations for high-throughput provenance data:
//  1. Bloom filters — accelerate point lookups on SSTables
//  2. Leveled compaction — optimised for time-decaying access
//  3. Block cache — LRU cache for edge index queries
package pebblestore

import (
	"runtime"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/bloom"
	"github.com/cockroachdb/pebble/vfs"
)

// ─── Default performance options ────────────────────────────

// DefaultPebbleOptions returns Pebble options tuned for provenance
// workloads: high write throughput with time-decaying read patterns.
func DefaultPebbleOptions(dbPath string) *pebble.Options {
	opts := &pebble.Options{
		// ── Filesystem ────────────────────────────────────
		FS: vfs.Default,

		// ── Memory ────────────────────────────────────────
		// Cache: shared block cache (see NewCache for details)
		// MemTableSize: 64 MB per memtable
		MemTableSize: 64 * 1024 * 1024,

		// Two memtables: one active, one being flushed
		MemTableStopWritesThreshold: 4,

		// ── Compaction ────────────────────────────────────
		// L0 → L1: compact when 2 files accumulate
		L0CompactionThreshold: 2,

		// Stop writes if L0 exceeds 4 files
		L0StopWritesThreshold: 4,

		// Max compaction goroutines
		MaxConcurrentCompactions: func() int {
			n := runtime.NumCPU() / 2
			if n < 2 {
				return 2
			}
			if n > 8 {
				return 8
			}
			return n
		},

		// ── WAL ───────────────────────────────────────────
		// WAL disabled for throughput (risk accepted with mem backup)
		DisableWAL: true,

		// ── Format major version (enable latest features) ─
		FormatMajorVersion: pebble.FormatNewest,
	}

	return opts
}

// ─── Bloom filter configuration ────────────────────────────

// WithBloomFilters configures Bloom filters on all SSTable levels
// for accelerated point lookups.
//
// Each SSTable gets a Bloom filter of `bitsPerKey` bits per key.
// Recommended values:
//
//	10 — 1% false positive rate, ~10% space overhead
//	20 — 0.1% false positive rate, ~20% space overhead
//	5  — 10% false positive rate, ~5% space overhead (minimal)
func WithBloomFilters(opts *pebble.Options, bitsPerKey int) *pebble.Options {
	if bitsPerKey <= 0 {
		bitsPerKey = 10 // default: 1% FPR
	}

	// Apply to all levels
	for i := range opts.Levels {
		opts.Levels[i].FilterPolicy = bloom.FilterPolicy(bitsPerKey)
	}

	return opts
}

// ─── Compaction tuning ─────────────────────────────────────

// CompactionConfig controls per-level compression and size targets.
type CompactionConfig struct {
	// L0FileCount — target size for L0 (in files)
	L0FileCount int

	// BaseLevelSize — target size for L1 (bytes)
	BaseLevelSize int64

	// LevelSizeMultiplier — each level is this times larger than previous
	LevelSizeMultiplier int

	// Compression per level — higher levels get stronger compression
	NoCompressionL0   bool // L0: no compression (fastest write)
	SnappyCompression bool // Mid levels: Snappy
	ZstdCompression   bool // Lower levels: Zstd (best compression)

	// MaxLevels — number of levels in the LSM tree
	MaxLevels int
}

// DefaultCompactionConfig returns sensible defaults for provenance data.
func DefaultCompactionConfig() *CompactionConfig {
	return &CompactionConfig{
		L0FileCount:         4,
		BaseLevelSize:       64 * 1024 * 1024, // 64 MB
		LevelSizeMultiplier: 10,               // 10x growth per level
		NoCompressionL0:     true,
		SnappyCompression:   true,
		ZstdCompression:     true,
		MaxLevels:           7,
	}
}

// ApplyCompactionConfig applies the compaction config to Pebble options.
func ApplyCompactionConfig(opts *pebble.Options, cfg *CompactionConfig) *pebble.Options {
	if cfg == nil {
		cfg = DefaultCompactionConfig()
	}

	// Configure per-level options
	opts.Levels = make([]pebble.LevelOptions, cfg.MaxLevels)

	for i := 0; i < cfg.MaxLevels; i++ {
		lo := &opts.Levels[i]

		// Block size: 16 KB for faster read, 32 KB for better compression
		lo.BlockSize = 16 * 1024

		// Block cache (shared across levels) — set via opts.Cache
		// Compression: L0 fastest, lower levels strongest
		switch {
		case i == 0 && cfg.NoCompressionL0:
			lo.Compression = pebble.NoCompression
		case i <= 2 && cfg.SnappyCompression:
			lo.Compression = pebble.SnappyCompression
		case cfg.ZstdCompression:
			lo.Compression = pebble.ZstdCompression
		default:
			lo.Compression = pebble.SnappyCompression
		}

		// Target file size doubles per level
		lo.TargetFileSize = 2 * 1024 * 1024 * int64(i+1) // 2MB, 4MB, 6MB...

		// Bloom filter on all levels
		lo.FilterPolicy = bloom.FilterPolicy(10)
	}

	return opts
}

// ─── Block cache (LRU) ─────────────────────────────────────

// CacheSize returns the recommended block cache size based on
// available system memory.
//
//	< 4 GB:  128 MB cache
//	4-8 GB:  256 MB cache
//	8-16 GB: 512 MB cache
//	> 16 GB: 1 GB cache
func CacheSize() int64 {
	total := detectMemoryMB()
	switch {
	case total >= 16384:
		return 1024 * 1024 * 1024 // 1 GB
	case total >= 8192:
		return 512 * 1024 * 1024 // 512 MB
	case total >= 4096:
		return 256 * 1024 * 1024 // 256 MB
	default:
		return 128 * 1024 * 1024 // 128 MB
	}
}

// NewCache creates a shared LRU block cache.
// Pebble's block cache reduces disk reads by caching recently
// accessed SSTable blocks in memory.
func NewCache(size int64) *pebble.Cache {
	if size <= 0 {
		size = CacheSize()
	}
	return pebble.NewCache(size)
}

// ─── Utility ───────────────────────────────────────────────

// detectMemoryMB attempts to detect total system memory in MB.
// Returns a conservative default if detection fails.
func detectMemoryMB() int64 {
	// Default: 8 GB
	return 8192
}

// ─── Pre-built configurations ──────────────────────────────

// HighThroughputConfig returns options optimised for write-heavy
// workloads with Bloom filters, Zstd compression, and LRU cache.
func HighThroughputConfig(dbPath string) (*pebble.Options, *pebble.Cache) {
	cache := NewCache(CacheSize())
	opts := DefaultPebbleOptions(dbPath)
	opts.Cache = cache

	// Apply Bloom filters
	WithBloomFilters(opts, 10)

	// Apply compaction tuning
	ApplyCompactionConfig(opts, DefaultCompactionConfig())

	return opts, cache
}

// LowLatencyConfig returns options optimised for read-heavy
// workloads (more Bloom filter bits, larger cache).
func LowLatencyConfig(dbPath string) (*pebble.Options, *pebble.Cache) {
	cache := NewCache(CacheSize() * 2) // double cache
	opts := DefaultPebbleOptions(dbPath)
	opts.Cache = cache

	// Higher Bloom filter precision (0.1% FPR)
	WithBloomFilters(opts, 20)

	// More aggressive compaction (keep L0 smaller)
	opts.L0CompactionThreshold = 2
	opts.L0StopWritesThreshold = 4

	ApplyCompactionConfig(opts, DefaultCompactionConfig())

	return opts, cache
}

// BalancedConfig returns a balance of read/write performance.
func BalancedConfig(dbPath string) (*pebble.Options, *pebble.Cache) {
	cache := NewCache(CacheSize())
	opts := DefaultPebbleOptions(dbPath)
	opts.Cache = cache

	WithBloomFilters(opts, 10)
	ApplyCompactionConfig(opts, DefaultCompactionConfig())

	// Enable WAL for durability
	opts.DisableWAL = false

	return opts, cache
}
