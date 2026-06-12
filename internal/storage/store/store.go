// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/cockroachdb/pebble"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/secure"
)

const (
	nodePrefix        = "n:"
	edgePrefix        = "e:"
	reverseEdgePrefix = "r:"
)

func nodeKey(id string) string        { return nodePrefix + id }
func edgeKey(ts uint64, source, target string) string {
	return fmt.Sprintf("e:%020d:%s:%s", ts, source, target)
}
func reverseEdgeKey(ts uint64, target, source string) string {
	return fmt.Sprintf("r:%s:%020d:%s", target, ts, source)
}

type Store struct {
	mu        sync.Mutex
	db        *pebble.DB
	wb        *pebble.Batch
	wbCap     int
	closed    bool
	encKey    []byte // nil = no encryption
}

func Open(path string, encryptKey []byte) (*Store, error) {
	db, err := pebble.Open(path, &pebble.Options{})
	if err != nil {
		return nil, fmt.Errorf("pebble open %s: %w", path, err)
	}
	return &Store{
		db:    db,
		wb:    db.NewIndexedBatch(),
		wbCap: 200,
		encKey: encryptKey,
	}, nil
}

// encrypt encrypts data if encryption is enabled.
func (s *Store) encrypt(data []byte) ([]byte, error) {
	if s.encKey == nil {
		return data, nil
	}
	return secure.Encrypt(s.encKey, data)
}

// decrypt decrypts data if encryption is enabled.
func (s *Store) decrypt(data []byte) ([]byte, error) {
	if s.encKey == nil {
		return data, nil
	}
	return secure.Decrypt(s.encKey, data)
}

// ── Node persistence ───────────────────────────────────────

func (s *Store) PutNode(n *provenance.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}
	data, err := json.Marshal(n)
	if err != nil {
		return fmt.Errorf("marshal node: %w", err)
	}
	enc, err := s.encrypt(data)
	if err != nil {
		return err
	}
	s.wb.Set([]byte(nodeKey(n.ID)), enc, pebble.Sync)
	return s.autoFlush()
}

func (s *Store) GetNode(id string) (*provenance.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, closer, err := s.wb.Get([]byte(nodeKey(id)))
	if err == pebble.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	dec, err := s.decrypt(v)
	if err != nil {
		return nil, err
	}
	var n provenance.Node
	if err := json.Unmarshal(dec, &n); err != nil {
		return nil, err
	}
	return &n, nil
}

func (s *Store) DeleteNode(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wb.Delete([]byte(nodeKey(id)), pebble.NoSync)
	return s.autoFlush()
}

// ── Edge persistence ───────────────────────────────────────

func (s *Store) PutEdge(e *provenance.Edge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal edge: %w", err)
	}
	enc, err := s.encrypt(data)
	if err != nil {
		return err
	}
	ts := uint64(e.Timestamp.UnixNano())
	s.wb.Set([]byte(edgeKey(ts, e.Source, e.Target)), enc, pebble.Sync)
	s.wb.Set([]byte(reverseEdgeKey(ts, e.Target, e.Source)), enc, pebble.Sync)
	return s.autoFlush()
}

func (s *Store) GetEdgesByTimeRange(start, end uint64) ([]*provenance.Edge, error) {
	// Flush pending writes so reads see the latest data.
	s.mu.Lock()
	s.flushLocked()
	s.mu.Unlock()

	lo := []byte(edgeKey(start, "", ""))
	hi := []byte(edgeKey(end, "", ""))

	iter, err := s.db.NewIter(&pebble.IterOptions{LowerBound: lo, UpperBound: hi})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var out []*provenance.Edge
	for iter.First(); iter.Valid(); iter.Next() {
		dec, err := s.decrypt(iter.Value())
		if err != nil {
			return nil, err
		}
		var e provenance.Edge
		if err := json.Unmarshal(dec, &e); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, iter.Error()
}

func (s *Store) GetEdgesByTarget(targetID string) ([]*provenance.Edge, error) {
	// Flush pending writes so reads see the latest data.
	s.mu.Lock()
	s.flushLocked()
	s.mu.Unlock()

	lo := []byte(fmt.Sprintf("r:%s:", targetID))
	hi := []byte(fmt.Sprintf("r:%s\xff", targetID))

	iter, err := s.db.NewIter(&pebble.IterOptions{LowerBound: lo, UpperBound: hi})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var out []*provenance.Edge
	for iter.First(); iter.Valid(); iter.Next() {
		dec, err := s.decrypt(iter.Value())
		if err != nil {
			return nil, err
		}
		var e provenance.Edge
		if err := json.Unmarshal(dec, &e); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, iter.Error()
}

// EdgeCount returns the total number of persisted edges.
func (s *Store) EdgeCount() (int, error) {
	// Flush pending writes so reads see the latest data.
	s.mu.Lock()
	s.flushLocked()
	s.mu.Unlock()

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
	// Must be called with s.mu held.
	if int(s.wb.Count()) >= s.wbCap {
		return s.flushLocked()
	}
	return nil
}

func (s *Store) flushLocked() error {
	if s.wb.Count() == 0 {
		return nil
	}
	if err := s.wb.Commit(&pebble.WriteOptions{Sync: true}); err != nil {
		return fmt.Errorf("batch commit: %w", err)
	}
	s.wb = s.db.NewIndexedBatch()
	return nil
}

// Flush commits any pending writes to the underlying database.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushLocked()
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.flushLocked()
	return s.db.Close()
}

// UnderlyingDB returns the raw pebble.DB for direct operations.
func (s *Store) UnderlyingDB() *pebble.DB {
	return s.db
}

// DiskUsage returns the approximate disk space used by the store.
func (s *Store) DiskUsage() int64 {
	return int64(s.db.Metrics().DiskSpaceUsage())
}

func (s *Store) Stats() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.db.Metrics()
	return map[string]interface{}{
		"disk_bytes":    m.DiskSpaceUsage(),
		"batch_pending": s.wb.Count(),
		"memtable":      m.MemTable.Size,
	}
}

var errClosed = fmt.Errorf("store: closed")
