// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package pebblestore

import (
	"testing"

	"github.com/cockroachdb/pebble"
)

func TestDefaultPebbleOptions(t *testing.T) {
	opts := DefaultPebbleOptions("/tmp/test")
	if opts == nil {
		t.Fatal("nil options")
	}
	if opts.MemTableSize != 64*1024*1024 {
		t.Errorf("MemTableSize = %d", opts.MemTableSize)
	}
	if !opts.DisableWAL {
		t.Error("expected WAL disabled")
	}
}

func TestWithBloomFilters(t *testing.T) {
	opts := DefaultPebbleOptions("/tmp/test")
	opts = WithBloomFilters(opts, 10)

	for i, level := range opts.Levels {
		if level.FilterPolicy == nil {
			t.Errorf("level %d: no bloom filter", i)
		}
	}
}

func TestCompactionConfig(t *testing.T) {
	opts := DefaultPebbleOptions("/tmp/test")
	cfg := DefaultCompactionConfig()

	if cfg.L0FileCount != 4 {
		t.Errorf("L0FileCount = %d", cfg.L0FileCount)
	}
	if cfg.BaseLevelSize != 64*1024*1024 {
		t.Errorf("BaseLevelSize = %d", cfg.BaseLevelSize)
	}
	if cfg.LevelSizeMultiplier != 10 {
		t.Errorf("LevelSizeMultiplier = %d", cfg.LevelSizeMultiplier)
	}

	opts = ApplyCompactionConfig(opts, cfg)
	if len(opts.Levels) != cfg.MaxLevels {
		t.Errorf("levels = %d, want %d", len(opts.Levels), cfg.MaxLevels)
	}
}

func TestLevelCompression(t *testing.T) {
	cfg := DefaultCompactionConfig()
	opts := DefaultPebbleOptions("/tmp/test")
	opts = ApplyCompactionConfig(opts, cfg)

	// L0 should be uncompressed
	if opts.Levels[0].Compression != pebble.NoCompression {
		t.Errorf("L0 compression = %v", opts.Levels[0].Compression)
	}

	// Mid levels should be Snappy
	if opts.Levels[1].Compression != pebble.SnappyCompression {
		t.Errorf("L1 compression = %v", opts.Levels[1].Compression)
	}
}

func TestCacheSize(t *testing.T) {
	size := CacheSize()
	if size <= 0 {
		t.Error("cache size <= 0")
	}
	if size > 2*1024*1024*1024 {
		t.Errorf("cache size too large: %d", size)
	}
	t.Logf("Recommended cache size: %d MB", size/1024/1024)
}

func TestNewCache(t *testing.T) {
	cache := NewCache(64 * 1024 * 1024) // 64 MB
	if cache == nil {
		t.Fatal("nil cache")
	}
	cache.Unref()
}

func TestHighThroughputConfig(t *testing.T) {
	opts, cache := HighThroughputConfig("/tmp/test")
	if opts == nil || cache == nil {
		t.Fatal("nil options or cache")
	}
	defer cache.Unref()

	if opts.Cache != cache {
		t.Error("cache not attached to options")
	}
}

func TestLowLatencyConfig(t *testing.T) {
	opts, cache := LowLatencyConfig("/tmp/test")
	if opts == nil || cache == nil {
		t.Fatal("nil options or cache")
	}
	defer cache.Unref()

	// Low latency should have more bloom bits
	for i, level := range opts.Levels {
		if level.FilterPolicy == nil {
			t.Errorf("level %d: no filter", i)
		}
	}
}

func TestBalancedConfig(t *testing.T) {
	opts, cache := BalancedConfig("/tmp/test")
	if opts == nil || cache == nil {
		t.Fatal("nil options or cache")
	}
	defer cache.Unref()

	if opts.DisableWAL {
		t.Error("balanced config should enable WAL")
	}
}

func TestOpenWithConfig(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir + "/pebble")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	if st.cache == nil {
		t.Error("store should have cache")
	}
}

func TestConcurrentCompactions(t *testing.T) {
	opts := DefaultPebbleOptions("/tmp/test")
	n := opts.MaxConcurrentCompactions()
	if n < 2 || n > 8 {
		t.Errorf("unexpected compaction count: %d", n)
	}
	t.Logf("MaxConcurrentCompactions: %d", n)
}

func TestBloomFilterBits(t *testing.T) {
	// 10 bits/key ≈ 1% false positive rate
	opts := DefaultPebbleOptions("/tmp/test")
	WithBloomFilters(opts, 10)

	// Verify the filter policy is set correctly
	for i, level := range opts.Levels {
		policy := level.FilterPolicy
		if policy == nil {
			t.Errorf("level %d missing filter", i)
		}
	}
}
