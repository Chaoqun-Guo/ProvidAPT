// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package store — asynchronous dual-trigger batch writer.
//
// Two commit triggers:
//  1. Time-based:  every 100ms
//  2. Count-based:  every 1000 records
//
// Whichever fires first triggers a WriteBatch commit.
// On SIGINT/SIGTERM, the final flush drains all pending writes.
package pebblestore

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
	"github.com/cockroachdb/pebble"
	"google.golang.org/protobuf/proto"
)

const (
	defaultBatchSize     = 1000
	defaultFlushInterval = 100 * time.Millisecond
)

// ─── BatchWriter ────────────────────────────────────────────

// BatchWriter commits writes to RocksDB using dual-trigger batching
// (time or count) and ensures final flush on process exit.
type BatchWriter struct {
	db            *pebble.DB
	wb            *pebble.Batch
	wbMu          sync.Mutex
	pending       int
	batchSize     int
	flushInterval time.Duration

	stats    BatchStats
	stopCh   chan struct{}
	wg       sync.WaitGroup
	signalCh chan os.Signal
}

// BatchStats tracks write performance.
type BatchStats struct {
	NodesWritten     int64
	EdgesWritten     int64
	BatchesCommitted int64
	BytesWritten     int64
	FlushByCount     int64
	FlushByTime      int64
	FlushBySignal    int64
}

// NewBatchWriter creates a dual-trigger batch writer.
func NewBatchWriter(db *pebble.DB) *BatchWriter {
	bw := &BatchWriter{
		db:            db,
		wb:            db.NewBatch(),
		batchSize:     defaultBatchSize,
		flushInterval: defaultFlushInterval,
		stopCh:        make(chan struct{}),
		signalCh:      make(chan os.Signal, 1),
	}
	signal.Notify(bw.signalCh, syscall.SIGINT, syscall.SIGTERM)
	return bw
}

// Start begins the background flush goroutine.
func (bw *BatchWriter) Start() {
	bw.wg.Add(1)
	go bw.flushLoop()
	log.Printf("[batch] started: flush=%v batch=%d", bw.flushInterval, bw.batchSize)
}

func (bw *BatchWriter) flushLoop() {
	defer bw.wg.Done()
	ticker := time.NewTicker(bw.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Time-based trigger: try flush if we have pending data
			bw.wbMu.Lock()
			needsFlush := bw.pending > 0
			bw.wbMu.Unlock()
			if needsFlush {
				bw.commit("time")
			}

		case <-bw.signalCh:
			// Signal-based trigger: final flush on SIGINT/SIGTERM
			log.Printf("[batch] signal received — final flush")
			bw.Flush()
			bw.stats.FlushBySignal++
			// Don't stop; let main handle shutdown

		case <-bw.stopCh:
			return
		}
	}
}

// ─── Write operations ───────────────────────────────────────

// WriteNode queues a node write.  Returns immediately; actual
// write happens on next batch commit.
func (bw *BatchWriter) WriteNode(n *pb.Node) error {
	data, err := proto.Marshal(n)
	if err != nil {
		return err
	}
	key := "n:" + n.Type + ":" + n.Id

	bw.wbMu.Lock()
	bw.wb.Set([]byte(key), data, pebble.NoSync)
	bw.pending++
	reached := bw.pending >= bw.batchSize
	bw.wbMu.Unlock()

	atomic.AddInt64(&bw.stats.NodesWritten, 1)
	atomic.AddInt64(&bw.stats.BytesWritten, int64(len(data)))

	if reached {
		return bw.commit("count")
	}
	return nil
}

// WriteEdge queues an edge write with both primary and reverse indexes.
func (bw *BatchWriter) WriteEdge(e *pb.Edge) error {
	data, err := proto.Marshal(e)
	if err != nil {
		return err
	}

	// Primary index: e:<ts>:<src>:<tgt>
	key := fmt.Sprintf("e:%016x:%s:%s", e.TimestampNs, e.Source, e.Target)
	// Reverse index: r:<tgt>:<ts>:<src>
	revKey := fmt.Sprintf("r:%s:%016x:%s", e.Target, e.TimestampNs, e.Source)

	bw.wbMu.Lock()
	bw.wb.Set([]byte(key), data, pebble.NoSync)
	bw.wb.Set([]byte(revKey), data, pebble.NoSync)
	bw.pending += 2
	reached := bw.pending >= bw.batchSize
	bw.wbMu.Unlock()

	atomic.AddInt64(&bw.stats.EdgesWritten, 1)
	atomic.AddInt64(&bw.stats.BytesWritten, int64(len(data))*2)

	if reached {
		return bw.commit("count")
	}
	return nil
}

// ─── Commit ─────────────────────────────────────────────────

// commit flushes the current batch to RocksDB.
func (bw *BatchWriter) commit(trigger string) error {
	bw.wbMu.Lock()
	defer bw.wbMu.Unlock()

	if bw.pending == 0 {
		return nil
	}

	if err := bw.wb.Commit(&pebble.WriteOptions{Sync: false}); err != nil {
		return err
	}

	switch trigger {
	case "count":
		atomic.AddInt64(&bw.stats.FlushByCount, 1)
	case "time":
		atomic.AddInt64(&bw.stats.FlushByTime, 1)
	}

	atomic.AddInt64(&bw.stats.BatchesCommitted, 1)
	bw.wb = bw.db.NewBatch()
	bw.pending = 0
	return nil
}

// Flush forces an immediate commit of all pending writes.
func (bw *BatchWriter) Flush() error {
	return bw.commit("flush")
}

// ─── Signal-safe shutdown ──────────────────────────────────

// Stop performs final flush and stops the background goroutine.
func (bw *BatchWriter) Stop() {
	bw.Flush()
	close(bw.stopCh)
	bw.wg.Wait()
	log.Printf("[batch] stopped: %s", bw.Summary())
}

// Summary returns a one-line performance summary.
func (bw *BatchWriter) Summary() string {
	s := bw.stats
	return fmt.Sprintf("%d batches (%d count, %d time, %d signal), %d nodes, %d edges, %.1f KB",
		s.BatchesCommitted, s.FlushByCount, s.FlushByTime, s.FlushBySignal,
		s.NodesWritten, s.EdgesWritten, float64(s.BytesWritten)/1024)
}
