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

	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/storage/schema"
)

// ─── Store ──────────────────────────────────────────────────

// Store wraps a Pebble database and provides provenance-specific
// operations with asynchronous batch writes.
type Store struct {
	db        *pebble.DB
	wb        *pebble.Batch
	wbMu      sync.Mutex
	wbSize    int       // batch size threshold
	flushInt  time.Duration
	stopCh    chan struct{}
	wg        sync.WaitGroup
	cache     *pebble.Cache // shared LRU block cache

	// Statistics
	stats     StoreStats
}

// StoreStats tracks write performance.
type StoreStats struct {
	NodesWritten   int64
	EdgesWritten   int64
	BatchesCommited int64
	BytesWritten   int64
	mu             sync.Mutex
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
		wbSize:   500,                 // larger batch for throughput
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
func (s *Store) PutNode(node *pb.Node) error {
	data, err := proto.Marshal(node)
	if err != nil {
		return fmt.Errorf("marshal node: %w", err)
	}

	key := schema.NodeKey(node.Type, node.Id)

	s.wbMu.Lock()
	s.wb.Set([]byte(key), data, pebble.Sync)
	batchSize := s.wb.Count()
	s.wbMu.Unlock()

	s.stats.mu.Lock()
	s.stats.NodesWritten++
	s.stats.BytesWritten += int64(len(data))
	s.stats.mu.Unlock()

	// Write secondary indexes in a separate goroutine to avoid blocking
	if node.Pid > 0 {
		go s.writePIDIndex(node.Pid, node.Id, node.FirstSeenNs)
	}
	if node.Inode > 0 {
		go s.writeInodeIndex(node.Inode, node.DevMajor, node.DevMinor, node.Id)
	}

	if batchSize >= uint32(s.wbSize) {
		return s.Flush()
	}
	return nil
}

// writePIDIndex creates a PID→Node index entry.
func (s *Store) writePIDIndex(pid uint32, nodeID string, ts uint64) {
	key := schema.PIDIndexKey(pid, nodeID)
	idx := &pb.PIDIndex{Pid: pid, NodeId: nodeID, FirstSeenNs: ts}
	data, _ := proto.Marshal(idx)

	s.wbMu.Lock()
	s.wb.Set([]byte(key), data, pebble.Sync)
	s.wbMu.Unlock()
}

// writeInodeIndex creates an Inode→Node index entry.
func (s *Store) writeInodeIndex(inode uint64, devMajor, devMinor uint32, nodeID string) {
	key := schema.InodeIndexKey(inode, devMajor, devMinor, nodeID)
	idx := &pb.InodeIndex{Inode: inode, DevMajor: devMajor, DevMinor: devMinor, NodeId: nodeID}
	data, _ := proto.Marshal(idx)

	s.wbMu.Lock()
	s.wb.Set([]byte(key), data, pebble.Sync)
	s.wbMu.Unlock()
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
	key := string(iter.Key())
	parts := splitAfter(prefix, key)
	if len(parts) < 2 {
		return nil, nil
	}
	nodeID := parts[1]

	// Determine node type from ID prefix
	nodeType := nodeTypeFromID(nodeID)
	return s.GetNode(nodeType, nodeID)
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

	key := string(iter.Key())
	parts := splitAfter(prefix, key)
	if len(parts) < 2 {
		return nil, nil
	}
	nodeID := parts[len(parts)-1]

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
	// Use reverse index: r:<target>:...
	prefix := fmt.Sprintf("r:%s:", target)
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
		"nodes_written":    s.stats.NodesWritten,
		"edges_written":    s.stats.EdgesWritten,
		"batches_committed": s.stats.BatchesCommited,
		"bytes_written":    s.stats.BytesWritten,
		"disk_usage_bytes": m.DiskSpaceUsage(),
		"memtable_size":    m.MemTable.Size,
	}
}

// ─── Helpers ─────────────────────────────────────────────

// splitAfter splits the remaining part of a key after a prefix.
func splitAfter(prefix, key string) []string {
	rest := key[len(prefix):]
	return strings.SplitN(rest, ":", 2)
}

func nodeTypeFromID(id string) string {
	if len(id) > 0 && id[0] == 'p' {
		return "process"
	}
	return "file"
}
