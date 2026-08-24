// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/cockroachdb/pebble"
)

// SubgraphHash uniquely identifies a subgraph structure.
type SubgraphHash struct {
	Hash     string    `json:"hash"`
	SentAt   time.Time `json:"sent_at"`
	Count    int       `json:"count"`
	IsActive bool      `json:"is_active"`
}

// HashCache tracks previously sent subgraphs to avoid re-transmission.
// When a subgraph content hash is already known, the agent sends only
// a heartbeat (hash + timestamp) instead of the full structure.
type HashCache struct {
	mu      sync.Mutex
	hashes  map[string]*SubgraphHash // content hash → metadata
	db      *pebble.DB               // optional persistent backend
	dbPath  string
	hits    int64 // heartbeat-only sends
	savings int64 // estimated bytes saved
	stopCh  chan struct{}
	flushWg sync.WaitGroup
}

// NewHashCache creates an in-memory-only subgraph hash cache.
func NewHashCache() *HashCache {
	return &HashCache{
		hashes: make(map[string]*SubgraphHash),
		stopCh: make(chan struct{}),
	}
}

// NewPersistentHashCache creates a hash cache backed by Pebble.
// The cache survives agent restarts: existing hashes are loaded from
// disk on creation, and new hashes are flushed to disk periodically.
func NewPersistentHashCache(path string) (*HashCache, error) {
	db, err := pebble.Open(path, &pebble.Options{})
	if err != nil {
		return nil, err
	}

	hc := &HashCache{
		hashes: make(map[string]*SubgraphHash),
		db:     db,
		dbPath: path,
		stopCh: make(chan struct{}),
	}

	// Load existing hashes from disk.
	if err := hc.loadFromDisk(); err != nil {
		log.Printf("[hashcache] load error: %v", err)
	}

	// Start background flush goroutine.
	hc.flushWg.Add(1)
	go hc.flushLoop()

	log.Printf("[hashcache] persistent cache opened: %s (%d entries loaded)",
		path, len(hc.hashes))
	return hc, nil
}

// ComputeHash computes a SHA256 hash of subgraph content.
func ComputeHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ShouldTransmit checks if a subgraph needs full transmission.
// Returns true if the subgraph is new or changed.
// Returns false if it's a repeat (send heartbeat only).
func (hc *HashCache) ShouldTransmit(contentHash string) bool {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	existing, ok := hc.hashes[contentHash]
	if !ok {
		entry := &SubgraphHash{
			Hash:     contentHash,
			SentAt:   time.Now(),
			Count:    1,
			IsActive: true,
		}
		hc.hashes[contentHash] = entry
		hc.persistEntryLocked(entry)
		return true
	}

	existing.Count++
	existing.SentAt = time.Now()
	existing.IsActive = true
	hc.persistEntryLocked(existing)
	hc.hits++
	hc.savings += 1024
	return false
}

// ComputeAndCheck is a convenience method that computes the hash
// and checks the cache in one call.
func (hc *HashCache) ComputeAndCheck(data []byte) (string, bool) {
	hash := ComputeHash(data)
	return hash, hc.ShouldTransmit(hash)
}

// HeartbeatMessage is a minimal update for a known subgraph.
type HeartbeatMessage struct {
	Hash      string    `json:"hash"`
	Count     int       `json:"count"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"` // "heartbeat"
}

// NewHeartbeat creates a heartbeat for a known subgraph.
func (hc *HashCache) NewHeartbeat(contentHash string) *HeartbeatMessage {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if entry, ok := hc.hashes[contentHash]; ok {
		return &HeartbeatMessage{
			Hash:      contentHash,
			Count:     entry.Count,
			Timestamp: time.Now(),
			Type:      "heartbeat",
		}
	}
	return nil
}

// CleanStale removes entries inactive for more than maxAge.
func (hc *HashCache) CleanStale(maxAge time.Duration) int {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for hash, entry := range hc.hashes {
		if entry.SentAt.Before(cutoff) {
			delete(hc.hashes, hash)
			removed++
			if hc.db != nil {
				key := []byte("hc:" + hash)
				if err := hc.db.Delete(key, pebble.Sync); err != nil {
					log.Printf("[hashcache] delete error: %v", err)
				}
			}
		}
	}
	return removed
}

// FlushToDisk writes the in-memory hash map to Pebble.
func (hc *HashCache) FlushToDisk() error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if hc.db == nil || len(hc.hashes) == 0 {
		return nil
	}

	batch := hc.db.NewBatch()
	defer func() { _ = batch.Close() }()

	for hash, entry := range hc.hashes {
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		if err := batch.Set([]byte("hc:"+hash), data, nil); err != nil {
			return err
		}
	}

	return batch.Commit(pebble.Sync)
}

// loadFromDisk loads all entries from Pebble into the in-memory map.
func (hc *HashCache) loadFromDisk() error {
	if hc.db == nil {
		return nil
	}

	iter, err := hc.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte("hc:"),
		UpperBound: []byte("hd:"), // "hc:" + max byte
	})
	if err != nil {
		return err
	}
	defer func() { _ = iter.Close() }()

	for iter.First(); iter.Valid(); iter.Next() {
		var entry SubgraphHash
		if err := json.Unmarshal(iter.Value(), &entry); err != nil {
			log.Printf("[hashcache] corrupt entry: %v", err)
			continue
		}
		hc.hashes[entry.Hash] = &entry
	}
	return iter.Error()
}

// flushLoop periodically flushes the hash cache to disk.
func (hc *HashCache) flushLoop() {
	defer hc.flushWg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := hc.FlushToDisk(); err != nil {
				log.Printf("[hashcache] flush error: %v", err)
			}
		case <-hc.stopCh:
			if err := hc.FlushToDisk(); err != nil {
				log.Printf("[hashcache] stop flush error: %v", err)
			}
			return
		}
	}
}

// Stats returns cache statistics.
func (hc *HashCache) Stats() map[string]interface{} {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	return map[string]interface{}{
		"cached_hashes": len(hc.hashes),
		"heartbeats":    hc.hits,
		"bytes_saved":   hc.savings,
		"persistent":    hc.db != nil,
	}
}

// Close flushes pending writes and closes the Pebble database.
func (hc *HashCache) Close() error {
	close(hc.stopCh)
	hc.flushWg.Wait()

	if hc.db != nil {
		if err := hc.FlushToDisk(); err != nil {
			return err
		}
		return hc.db.Close()
	}
	return nil
}

func (hc *HashCache) persistEntryLocked(entry *SubgraphHash) {
	if hc.db == nil || entry == nil {
		return
	}
	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("[hashcache] marshal error: %v", err)
		return
	}
	if err := hc.db.Set([]byte("hc:"+entry.Hash), data, pebble.Sync); err != nil {
		log.Printf("[hashcache] persist error: %v", err)
	}
}
