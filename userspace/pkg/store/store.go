// Package store provides a RocksDB-compatible persistent storage layer
// for provenance graph data.  It uses CockroachDB Pebble as the engine.
//
// Key schema (all keys are lexicographically sortable strings):
//
//   n:<node_id>               → Node JSON     (cold nodes)
//   e:<ts_hex>:<src>:<tgt>    → Edge JSON     (time-range ordered)
//
// All writes go through an internal WriteBatch for atomicity, and are
// flushed automatically when the batch reaches the configured size.
package store

import (
	"encoding/json"
	"fmt"

	"github.com/cockroachdb/pebble"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/provenance"
)

const (
	nodePrefix     = "n:"
	edgePrefix     = "e:"
	reverseEdgePrefix = "r:"
)

// nodeKey returns the store key for a node.
func nodeKey(id string) string { return nodePrefix + id }

// edgeKey returns a lexicographically time-ordered store key for an edge.
func edgeKey(ts uint64, source, target string) string {
	return fmt.Sprintf("e:%020d:%s:%s", ts, source, target)
}

// reverseEdgeKey returns a reverse-index key for backward traversal.
// Prefix scan "r:<target>" finds all edges pointing TO target.
func reverseEdgeKey(ts uint64, target, source string) string {
	return fmt.Sprintf("r:%s:%020d:%s", target, ts, source)
}

// ─── Store ──────────────────────────────────────────────────

type Store struct {
	db     *pebble.DB
	wb     *pebble.Batch
	wbCap  int // auto-flush when count >= cap
	closed bool
}

func Open(path string) (*Store, error) {
	db, err := pebble.Open(path, &pebble.Options{})
	if err != nil {
		return nil, fmt.Errorf("pebble open %s: %w", path, err)
	}
	return &Store{
		db:    db,
		wb:    db.NewBatch(),
		wbCap: 200,
	}, nil
}

// ── Node persistence ───────────────────────────────────────

func (s *Store) PutNode(n *provenance.Node) error {
	if s.closed {
		return errClosed
	}
	data, err := json.Marshal(n)
	if err != nil {
		return fmt.Errorf("marshal node: %w", err)
	}
	s.wb.Set([]byte(nodeKey(n.ID)), data, pebble.Sync)
	return s.autoFlush()
}

func (s *Store) GetNode(id string) (*provenance.Node, error) {
	v, closer, err := s.db.Get([]byte(nodeKey(id)))
	if err == pebble.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	var n provenance.Node
	if err := json.Unmarshal(v, &n); err != nil {
		return nil, err
	}
	return &n, nil
}

func (s *Store) DeleteNode(id string) error {
	s.wb.Delete([]byte(nodeKey(id)), pebble.NoSync)
	return s.autoFlush()
}

// ── Edge persistence ───────────────────────────────────────

func (s *Store) PutEdge(e *provenance.Edge) error {
	if s.closed {
		return errClosed
	}
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal edge: %w", err)
	}
	ts := uint64(e.Timestamp.UnixNano())
	// Primary index: time-range ordered
	s.wb.Set([]byte(edgeKey(ts, e.Source, e.Target)), data, pebble.Sync)
	// Reverse index: target-prefixed for backward traversal
	s.wb.Set([]byte(reverseEdgeKey(ts, e.Target, e.Source)), data, pebble.Sync)
	return s.autoFlush()
}

// GetEdgesByTimeRange returns edges with timestamps in [start, end).
func (s *Store) GetEdgesByTimeRange(start, end uint64) ([]*provenance.Edge, error) {
	lo := []byte(edgeKey(start, "", ""))
	hi := []byte(edgeKey(end, "", ""))

	iter, err := s.db.NewIter(&pebble.IterOptions{LowerBound: lo, UpperBound: hi})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var out []*provenance.Edge
	for iter.First(); iter.Valid(); iter.Next() {
		var e provenance.Edge
		if err := json.Unmarshal(iter.Value(), &e); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, iter.Error()
}

// GetEdgesByTarget returns all edges whose Target field matches the given
// node ID.  Uses the reverse index ("r:") for efficient lookup.
func (s *Store) GetEdgesByTarget(targetID string) ([]*provenance.Edge, error) {
	lo := []byte(fmt.Sprintf("r:%s:", targetID))
	hi := []byte(fmt.Sprintf("r:%s\xff", targetID))

	iter, err := s.db.NewIter(&pebble.IterOptions{LowerBound: lo, UpperBound: hi})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var out []*provenance.Edge
	for iter.First(); iter.Valid(); iter.Next() {
		var e provenance.Edge
		if err := json.Unmarshal(iter.Value(), &e); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, iter.Error()
}

// EdgeCount returns the total number of persisted edges.
func (s *Store) EdgeCount() (int, error) {
	lo, hi := []byte(edgePrefix), []byte("e\xff")
	iter, err := s.db.NewIter(&pebble.IterOptions{LowerBound: lo, UpperBound: hi})
	if err != nil {
		return 0, err
	}
	defer iter.Close()
	count := 0
	for iter.First(); iter.Valid(); iter.Next() {
		count++
	}
	return count, iter.Error()
}

// ── Batch lifecycle ────────────────────────────────────────

func (s *Store) autoFlush() error {
	if s.wb.Count() >= s.wbCap {
		return s.Flush()
	}
	return nil
}

func (s *Store) Flush() error {
	if s.wb.Count() == 0 {
		return nil
	}
	if err := s.wb.Commit(&pebble.WriteOptions{Sync: true}); err != nil {
		return fmt.Errorf("batch commit: %w", err)
	}
	s.wb = s.db.NewBatch()
	return nil
}

func (s *Store) Close() error {
	s.closed = true
	s.Flush()
	return s.db.Close()
}

// ── Statistics ─────────────────────────────────────────────

func (s *Store) Stats() map[string]interface{} {
	m := s.db.Metrics()
	return map[string]interface{}{
		"disk_bytes":    m.DiskSpaceUsage(),
		"batch_pending": s.wb.Count(),
		"memtable":      m.MemTable.Size,
	}
}

var errClosed = fmt.Errorf("store: closed")
