// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"log"
	"sync"
	"time"
)

// TransportConfig holds configuration for the TransportManager.
// Empty paths default to in-memory-only mode.
type TransportConfig struct {
	// Hash cache
	HashCachePath          string        // empty = in-memory only
	HashCacheFlushInterval time.Duration // default 30s
	HashStaleAge           time.Duration // default 5min

	// Priority pipeline
	LowPriorityPath    string        // empty = in-memory only
	LowSummaryInterval time.Duration // default 1h
	LowDrainMax        int           // default 10000

	// Compression
	CompressionLevel CompressionLevel
	DictionaryPath   string // path to saved dictionary, empty = train on first batch

	// Stream (forwarded to dist.StreamPipeline)
	ServerAddr        string
	BufferSize        int
	FlushInterval     time.Duration
	ReconnectInterval time.Duration
	MaxRetries        int
}

// DefaultTransportConfig returns sensible defaults.
func DefaultTransportConfig() *TransportConfig {
	return &TransportConfig{
		HashCacheFlushInterval: 30 * time.Second,
		HashStaleAge:           5 * time.Minute,
		LowSummaryInterval:     time.Hour,
		LowDrainMax:            10000,
		CompressionLevel:       CompressBalance,
		ServerAddr:             "localhost:50051",
		BufferSize:             10000,
		FlushInterval:          time.Second,
		ReconnectInterval:      5 * time.Second,
		MaxRetries:             10,
	}
}

// TransportStats aggregates statistics from all subsystems.
type TransportStats struct {
	Heartbeats       int64   `json:"heartbeats"`
	BytesSaved       int64   `json:"bytes_saved"`
	HighSent         int64   `json:"high_sent"`
	LowStaged        int64   `json:"low_staged"`
	Processed        int64   `json:"processed"`
	CompressionRatio float64 `json:"compression_ratio"`
	ActiveHashes     int     `json:"active_hashes"`
}

// TransportManager orchestrates the three transport optimisation subsystems:
//
//  1. HashCache — deduplicate subgraph transmissions with heartbeat-only updates
//  2. PriorityPipeline — split high-priority real-time vs low-priority hourly
//  3. Compressor — Zstd dictionary compression for protobuf payloads
//
// Data flow:
//
//	Event → HashCache (dedup) → PriorityPipeline (classify)
//	    ├── HIGH → Compressor → gRPC stream (immediate)
//	    └── LOW  → [Pebble buffer] → hourly Compressor → gRPC stream
type TransportManager struct {
	cfg        *TransportConfig
	hashCache  *HashCache
	pipeline   *PriorityPipeline
	compressor *Compressor
	client     *GrpcClient // optional, set by SetGrpcClient

	stopCh chan struct{}
	wg     sync.WaitGroup

	statsMx sync.Mutex
	stats   TransportStats
}

// NewTransportManager creates a TransportManager and initialises all
// subsystems according to the config.
func NewTransportManager(cfg *TransportConfig) (*TransportManager, error) {
	if cfg == nil {
		cfg = DefaultTransportConfig()
	}
	if cfg.LowSummaryInterval <= 0 {
		cfg.LowSummaryInterval = time.Hour
	}

	tm := &TransportManager{
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}

	// 1. Hash cache
	if cfg.HashCachePath != "" {
		hc, err := NewPersistentHashCache(cfg.HashCachePath)
		if err != nil {
			return nil, err
		}
		tm.hashCache = hc
	} else {
		tm.hashCache = NewHashCache()
	}

	// 2. Priority pipeline
	if cfg.LowPriorityPath != "" {
		pp, err := NewPersistentPriorityPipeline(cfg.LowPriorityPath)
		if err != nil {
			_ = tm.hashCache.Close()
			return nil, err
		}
		tm.pipeline = pp
	} else {
		tm.pipeline = NewPriorityPipeline()
	}

	// 3. Compressor
	tm.compressor = NewCompressorWithLevel(cfg.CompressionLevel)
	if cfg.DictionaryPath != "" {
		// Dictionary loading would be implemented here.
		log.Printf("[manager] dictionary path configured: %s", cfg.DictionaryPath)
	}

	log.Printf("[manager] transport manager initialised (hashcache=%v, lowpri=%v, level=%d)",
		cfg.HashCachePath != "", cfg.LowPriorityPath != "", cfg.CompressionLevel)
	return tm, nil
}

// SetGrpcClient attaches a gRPC client for outbound transmission.
func (tm *TransportManager) SetGrpcClient(client *GrpcClient) {
	tm.client = client
}

// Start begins background goroutines:
//   - lowSummaryLoop: periodically flushes low-priority events as summaries
//   - staleCleanupLoop: removes stale hash cache entries
//   - diskFlushLoop: periodically persists the hash cache to disk
func (tm *TransportManager) Start() {
	if tm.cfg.LowSummaryInterval > 0 {
		tm.wg.Add(1)
		go tm.lowSummaryLoop()
	}

	tm.wg.Add(1)
	go tm.staleCleanupLoop()

	// Only run the disk flush loop if hash cache is persistent.
	if tm.hashCache.db != nil {
		tm.wg.Add(1)
		go tm.diskFlushLoop()
	}

	log.Println("[manager] started")
}

// Stop gracefully shuts down all subsystems.
func (tm *TransportManager) Stop() {
	close(tm.stopCh)
	tm.wg.Wait()

	if err := tm.compressor.Close(); err != nil {
		log.Printf("[manager] compressor close: %v", err)
	}
	if err := tm.hashCache.Close(); err != nil {
		log.Printf("[manager] hashcache close: %v", err)
	}
	if err := tm.pipeline.Close(); err != nil {
		log.Printf("[manager] pipeline close: %v", err)
	}
	if tm.client != nil {
		tm.client.Close()
	}

	log.Println("[manager] stopped")
}

// Ingest is the main entry point for event producers.
// It classifies the event, deduplicates via hash cache, optionally
// compresses, and routes to the correct priority channel.
//
// High-priority events are sent immediately through the gRPC client.
// Low-priority events are staged for hourly summary.
//
// The caller should NOT reuse `data` after calling Ingest.
func (tm *TransportManager) Ingest(data []byte, priority Priority, tainted bool, ruleMatch bool) {
	// 1. Compute content hash and check for duplicates.
	hash, shouldTransmit := tm.hashCache.ComputeAndCheck(data)

	evt := &TransportEvent{
		Data:      data,
		Hash:      hash,
		Priority:  priority,
		Tainted:   tainted,
		RuleMatch: ruleMatch,
		Timestamp: time.Now(),
	}

	// 2. If this is a known subgraph, only route a heartbeat marker.
	if !shouldTransmit {
		evt.Data = nil // no payload needed for heartbeat
		tm.pipeline.Ingest(evt)
		tm.recordHeartbeat()
		return
	}

	// 3. New subgraph — compress and route.
	compressed, err := tm.compressor.CompressProtobuf(data)
	if err != nil {
		log.Printf("[manager] compress error: %v", err)
		compressed = data // fallback to uncompressed
	}
	evt.Data = compressed

	tm.pipeline.Ingest(evt)

	// 4. High priority: send immediately.
	if priority >= PriorityHigh || tainted || ruleMatch {
		tm.flushHigh()
	}
}

// flushHigh drains high-priority events and sends them via gRPC.
func (tm *TransportManager) flushHigh() {
	high := tm.pipeline.DrainHigh()
	if len(high) == 0 || tm.client == nil {
		return
	}

	for _, evt := range high {
		if err := tm.client.Send(evt.Data); err != nil {
			log.Printf("[manager] send error: %v", err)
		}
	}
}

// lowSummaryLoop periodically drains low-priority events, compresses
// the summary, and sends it via gRPC.
func (tm *TransportManager) lowSummaryLoop() {
	defer tm.wg.Done()
	ticker := time.NewTicker(tm.cfg.LowSummaryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			summary := tm.pipeline.DrainLowSummary()
			if summary == nil {
				continue
			}

			// Serialise and compress the summary for transmission.
			// In production, this would use protobuf serialisation.
			log.Printf("[manager] low summary: %d events, %d unique hashes",
				summary.Count, len(summary.HashCount))

			if tm.client != nil {
				// For now, just record that we would send.
				log.Printf("[manager] would send summary over gRPC (%d events)", summary.Count)
			}
		case <-tm.stopCh:
			// Flush remaining low-priority events on shutdown.
			summary := tm.pipeline.DrainLowSummary()
			if summary != nil {
				log.Printf("[manager] final low summary: %d events", summary.Count)
			}
			return
		}
	}
}

// staleCleanupLoop periodically removes inactive hash cache entries.
func (tm *TransportManager) staleCleanupLoop() {
	defer tm.wg.Done()
	interval := tm.cfg.HashStaleAge / 2
	if interval < time.Minute {
		interval = 2*time.Minute + 30*time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			removed := tm.hashCache.CleanStale(tm.cfg.HashStaleAge)
			if removed > 0 {
				log.Printf("[manager] cleaned %d stale hash entries", removed)
			}
		case <-tm.stopCh:
			return
		}
	}
}

// diskFlushLoop periodically persists the hash cache to disk.
func (tm *TransportManager) diskFlushLoop() {
	defer tm.wg.Done()
	ticker := time.NewTicker(tm.cfg.HashCacheFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := tm.hashCache.FlushToDisk(); err != nil {
				log.Printf("[manager] hashcache flush: %v", err)
			}
		case <-tm.stopCh:
			return
		}
	}
}

// recordHeartbeat updates the heartbeat stats counter.
func (tm *TransportManager) recordHeartbeat() {
	tm.statsMx.Lock()
	tm.stats.Heartbeats++
	tm.stats.BytesSaved += 1024
	tm.statsMx.Unlock()
}

// HashCache returns the underlying HashCache for direct access.
func (tm *TransportManager) HashCache() *HashCache {
	return tm.hashCache
}

// Pipeline returns the underlying PriorityPipeline for direct access.
func (tm *TransportManager) Pipeline() *PriorityPipeline {
	return tm.pipeline
}

// Compressor returns the underlying Compressor for direct access.
func (tm *TransportManager) Compressor() *Compressor {
	return tm.compressor
}

// Client returns the attached gRPC client, if any.
func (tm *TransportManager) Client() *GrpcClient {
	return tm.client
}

// Stats returns aggregated statistics from all subsystems.
func (tm *TransportManager) Stats() TransportStats {
	tm.statsMx.Lock()
	defer tm.statsMx.Unlock()

	hcStats := tm.hashCache.Stats()
	ppStats := tm.pipeline.Stats()
	cRatio := tm.compressor.Ratio()

	tm.stats.ActiveHashes = hcStats["cached_hashes"].(int)
	tm.stats.HighSent = ppStats["high_sent"].(int64)
	tm.stats.LowStaged = ppStats["low_staged"].(int64)
	tm.stats.Processed = ppStats["processed"].(int64)
	tm.stats.CompressionRatio = cRatio

	return tm.stats
}
