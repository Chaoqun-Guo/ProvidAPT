// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package store implements an asynchronous RocksDB (Pebble) writer
// for ProvidAPT v2.  It reads events from the BPF ring buffer,
// converts them to protobuf-encoded Node/Edge records, and writes
// them to RocksDB in batches for optimal throughput.
package pebblestore

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/pebble"
	"google.golang.org/protobuf/proto"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/storage/schema"
	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
)

// ─── Store ──────────────────────────────────────────────────

// Store wraps a Pebble database and provides provenance-specific
// operations with asynchronous batch writes.
type Store struct {
	db       *pebble.DB
	wb       *pebble.Batch
	wbMu     sync.Mutex
	wbSize   int // batch size threshold
	flushInt time.Duration
	stopCh   chan struct{}
	wg       sync.WaitGroup
	cache    *pebble.Cache // shared LRU block cache

	// Statistics
	stats StoreStats
}

// StoreStats tracks write performance.
type StoreStats struct {
	NodesWritten    int64
	EdgesWritten    int64
	BatchesCommited int64
	BytesWritten    int64
	mu              sync.Mutex
}

// Open opens or creates a Pebble-backed store with performance
// optimisations: Bloom filters, LRU block cache, leveled compaction.
func Open(path string) (*Store, error) {
	opts, cache := HighThroughputConfig(path)
	db, err := pebble.Open(path, opts)
	if err != nil {
		return nil, fmt.Errorf("pebble open: %w", err)
	}

	s := &Store{
		db:       db,
		wb:       db.NewBatch(),
		wbSize:   500, // larger batch for throughput
		flushInt: 2 * time.Second,
		stopCh:   make(chan struct{}),
		cache:    cache,
	}

	// Start background flush goroutine
	s.wg.Add(1)
	go s.flushLoop()

	log.Printf("[store] opened: %s (batch=%d, flush=%v)", path, s.wbSize, s.flushInt)
	return s, nil
}

// ─── Node operations ───────────────────────────────────────

// PutNode writes a node to the store (queued in batch).
// All data (node + secondary indexes) is written within a single lock
// scope to prevent Flush() from replacing the batch mid-write.
func (s *Store) PutNode(node *pb.Node) error {
	if node.Type == "process" && node.Comm == "" && node.Label != "" {
		node.Comm = node.Label
	}

	data, err := proto.Marshal(node)
	if err != nil {
		return fmt.Errorf("marshal node: %w", err)
	}

	key := schema.NodeKey(node.Type, node.Id)

	s.wbMu.Lock()
	s.wb.Set([]byte(key), data, pebble.Sync)

	// Write secondary indexes within the same lock scope for atomicity
	// — Flush() cannot replace s.wb while we hold the lock.
	if node.Pid > 0 {
		pidKey := schema.PIDIndexKey(node.Pid, node.Id)
		idx := &pb.PIDIndex{Pid: node.Pid, NodeId: node.Id, FirstSeenNs: node.FirstSeenNs}
		idxData, _ := proto.Marshal(idx)
		s.wb.Set([]byte(pidKey), idxData, pebble.Sync)
	}
	if node.Inode > 0 {
		inodeKey := schema.InodeIndexKey(node.Inode, node.DevMajor, node.DevMinor, node.Id)
		idx := &pb.InodeIndex{Inode: node.Inode, DevMajor: node.DevMajor, DevMinor: node.DevMinor, NodeId: node.Id}
		idxData, _ := proto.Marshal(idx)
		s.wb.Set([]byte(inodeKey), idxData, pebble.Sync)
	}

	batchSize := s.wb.Count()
	s.wbMu.Unlock()

	s.stats.mu.Lock()
	s.stats.NodesWritten++
	s.stats.BytesWritten += int64(len(data))
	s.stats.mu.Unlock()

	if batchSize >= uint32(s.wbSize) {
		return s.Flush()
	}
	return nil
}

// ─── Edge operations ───────────────────────────────────────

// PutEdge writes an edge to the store with both primary and reverse indexes.
func (s *Store) PutEdge(edge *pb.Edge) error {
	data, err := proto.Marshal(edge)
	if err != nil {
		return fmt.Errorf("marshal edge: %w", err)
	}

	// Primary index: time-range ordered
	key := schema.EdgeKey(edge.TimestampNs, edge.Source, edge.Target)

	// Reverse index: target-prefixed for backward traversal
	revKey := schema.ReverseEdgeKey(edge.TimestampNs, edge.Target, edge.Source)

	s.wbMu.Lock()
	s.wb.Set([]byte(key), data, pebble.Sync)
	s.wb.Set([]byte(revKey), data, pebble.Sync)
	batchSize := s.wb.Count()
	s.wbMu.Unlock()

	s.stats.mu.Lock()
	s.stats.EdgesWritten++
	s.stats.BytesWritten += int64(len(data)) * 2
	s.stats.mu.Unlock()

	if batchSize >= uint32(s.wbSize) {
		return s.Flush()
	}
	return nil
}

// ─── Batch control ─────────────────────────────────────────

// Flush commits the current write batch to RocksDB.
func (s *Store) Flush() error {
	s.wbMu.Lock()
	defer s.wbMu.Unlock()

	if s.wb.Count() == 0 {
		return nil
	}

	if err := s.wb.Commit(&pebble.WriteOptions{Sync: false}); err != nil {
		return fmt.Errorf("batch commit: %w", err)
	}

	s.stats.mu.Lock()
	s.stats.BatchesCommited++
	s.stats.mu.Unlock()

	s.wb = s.db.NewBatch()
	return nil
}

// flushLoop periodically flushes the write batch.
func (s *Store) flushLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.flushInt)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.Flush(); err != nil {
				log.Printf("[store] flush error: %v", err)
			}
		case <-s.stopCh:
			s.Flush()
			return
		}
	}
}

// ─── Reader operations ─────────────────────────────────────

// GetNode retrieves a node by type and ID.
func (s *Store) GetNode(nodeType, nodeID string) (*pb.Node, error) {
	key := schema.NodeKey(nodeType, nodeID)
	data, closer, err := s.db.Get([]byte(key))
	if err == pebble.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer closer.Close()

	var node pb.Node
	if err := proto.Unmarshal(data, &node); err != nil {
		return nil, err
	}
	return &node, nil
}

// GetNodeByPID retrieves a process node by PID.
func (s *Store) GetNodeByPID(pid uint32) (*pb.Node, error) {
	prefix := schema.PIDIndexPrefix(pid)
	iter, err := s.db.NewIter(&pebble.IterOptions{LowerBound: []byte(prefix), UpperBound: []byte(prefix + "\xff")})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	if !iter.First() {
		return nil, nil // not found
	}

	// Parse the node ID from the index key
	var idx pb.PIDIndex
	if err := proto.Unmarshal(iter.Value(), &idx); err == nil && idx.NodeId != "" {
		return s.GetNode("process", idx.NodeId)
	}

	key := string(iter.Key())
	nodeID := trimPrefix(prefix, key)
	if nodeID == "" {
		return nil, nil
	}
	return s.GetNode("process", nodeID)
}

// GetNodeByInode retrieves a file node by inode.
func (s *Store) GetNodeByInode(inode uint64) (*pb.Node, error) {
	prefix := schema.InodeIndexPrefix(inode)
	iter, err := s.db.NewIter(&pebble.IterOptions{LowerBound: []byte(prefix), UpperBound: []byte(prefix + "\xff")})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	if !iter.First() {
		return nil, nil
	}

	var idx pb.InodeIndex
	if err := proto.Unmarshal(iter.Value(), &idx); err == nil && idx.NodeId != "" {
		return s.GetNode("file", idx.NodeId)
	}

	key := string(iter.Key())
	nodeID := trimPrefix(prefix, key)
	if nodeID == "" {
		return nil, nil
	}
	return s.GetNode("file", nodeID)
}

// GetEdgesBySource returns all outgoing edges from a node.
func (s *Store) GetEdgesBySource(source string) ([]*pb.Edge, error) {
	prefix := schema.EdgePrefix()
	iter, err := s.db.NewIter(&pebble.IterOptions{LowerBound: []byte(prefix), UpperBound: []byte(prefix + "\xff")})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var edges []*pb.Edge
	for iter.First(); iter.Valid(); iter.Next() {
		src, _, _, ok := schema.ParseEdgeKey(string(iter.Key()))
		if !ok || src != source {
			continue
		}
		var edge pb.Edge
		if err := proto.Unmarshal(iter.Value(), &edge); err != nil {
			return nil, err
		}
		edges = append(edges, &edge)
	}
	return edges, iter.Error()
}

// GetEdgesByTarget returns all incoming edges to a node.
func (s *Store) GetEdgesByTarget(target string) ([]*pb.Edge, error) {
	// Use reverse index: r:<target>|<ts>|<source>
	prefix := fmt.Sprintf("r:%s|", target)
	iter, err := s.db.NewIter(&pebble.IterOptions{LowerBound: []byte(prefix), UpperBound: []byte(prefix + "\xff")})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var edges []*pb.Edge
	for iter.First(); iter.Valid(); iter.Next() {
		var edge pb.Edge
		if err := proto.Unmarshal(iter.Value(), &edge); err != nil {
			return nil, err
		}
		edges = append(edges, &edge)
	}
	return edges, iter.Error()
}

// GetEdgesByTimeRange returns edges within [start, end) nanosecond window.
func (s *Store) GetEdgesByTimeRange(startNs, endNs uint64) ([]*pb.Edge, error) {
	startKey, endKey := schema.EdgeTimeRange(startNs, endNs)
	iter, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte(startKey),
		UpperBound: []byte(endKey),
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var edges []*pb.Edge
	for iter.First(); iter.Valid(); iter.Next() {
		var edge pb.Edge
		if err := proto.Unmarshal(iter.Value(), &edge); err != nil {
			return nil, err
		}
		edges = append(edges, &edge)
	}
	return edges, iter.Error()
}

// ─── Lifecycle ─────────────────────────────────────────────

// Close flushes pending data and closes the database.
// GetDB exposes the underlying Pebble database for direct operations.
func (s *Store) GetDB() *pebble.DB {
	return s.db
}

func (s *Store) Close() error {
	close(s.stopCh)
	s.wg.Wait()
	s.Flush()
	s.db.Close()
	if s.cache != nil {
		s.cache.Unref()
	}
	return nil
}

// Stats returns store statistics.
func (s *Store) Stats() map[string]interface{} {
	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()

	m := s.db.Metrics()
	return map[string]interface{}{
		"nodes_written":     s.stats.NodesWritten,
		"edges_written":     s.stats.EdgesWritten,
		"batches_committed": s.stats.BatchesCommited,
		"bytes_written":     s.stats.BytesWritten,
		"disk_usage_bytes":  m.DiskSpaceUsage(),
		"memtable_size":     m.MemTable.Size,
	}
}

// ─── Helpers ─────────────────────────────────────────────

// trimPrefix returns the remainder of key after prefix, or "" if it does not match.
func trimPrefix(prefix, key string) string {
	if !strings.HasPrefix(key, prefix) {
		return ""
	}
	return key[len(prefix):]
}
