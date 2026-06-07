// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"log"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
)

// ═══════════════════════════════════════════════════════════════
// Multi-core parallel event parser
//
// Architecture:
//
//   RingBuf → Dispatcher (goroutine 1)
//               │
//               ├── LockFreeQueue 1 → Worker 1 (goroutine)
//               ├── LockFreeQueue 2 → Worker 2 (goroutine)
//               ├── LockFreeQueue 3 → Worker 3 (goroutine)
//               └── LockFreeQueue N → Worker N (goroutine)
//                                        │
//                                        ├── ParseRawEvent()
//                                        └── emit to EventCh
// ═══════════════════════════════════════════════════════════════

// WorkerPoolConfig for the parallel parser.
type WorkerPoolConfig struct {
	NumWorkers   int  // number of parser goroutines (0 = GOMAXPROCS)
	QueueSize    int  // per-worker queue size
}

// DefaultWorkerPoolConfig returns a configuration with one worker
// per CPU core.
func DefaultWorkerPoolConfig() *WorkerPoolConfig {
	return &WorkerPoolConfig{
		NumWorkers: runtime.GOMAXPROCS(0),
		QueueSize:  4096,
	}
}

// WorkerPool manages parallel event parsers.
type WorkerPool struct {
	cfg        *WorkerPoolConfig
	dispatcher *Dispatcher
	workers    []*Worker
	eventCh    chan *collector.Event
	errCh      chan error
	started    atomic.Bool
	stopCh     chan struct{}
	wg         sync.WaitGroup
	eventsParsed atomic.Int64
}

// Dispatcher reads from the zero-copy reader and distributes raw
// samples across workers using round-robin.
type Dispatcher struct {
	reader  *ZeroCopyReader
	queues  []*LockFreeQueue
	next    atomic.Uint64
	dropped atomic.Int64
}

// Worker parses raw event bytes from its queue.
type Worker struct {
	id    int
	queue *LockFreeQueue
	pool  *WorkerPool
	seq   uint64
}

// NewWorkerPool creates a pool of parallel event parsers.
func NewWorkerPool(cfg *WorkerPoolConfig, reader *ZeroCopyReader) *WorkerPool {
	if cfg == nil {
		cfg = DefaultWorkerPoolConfig()
	}
	if cfg.NumWorkers <= 0 {
		cfg.NumWorkers = runtime.GOMAXPROCS(0)
	}

	pool := &WorkerPool{
		cfg:     cfg,
		eventCh: make(chan *collector.Event, cfg.NumWorkers*cfg.QueueSize),
		errCh:   make(chan error, 16),
		stopCh:  make(chan struct{}),
	}

	// Create queues and workers
	queues := make([]*LockFreeQueue, cfg.NumWorkers)
	workers := make([]*Worker, cfg.NumWorkers)
	for i := 0; i < cfg.NumWorkers; i++ {
		queues[i] = NewLockFreeQueue(cfg.QueueSize)
		workers[i] = &Worker{
			id:    i,
			queue: queues[i],
			pool:  pool,
		}
	}

	pool.dispatcher = &Dispatcher{
		reader: reader,
		queues: queues,
	}
	pool.workers = workers

	return pool
}

// Start begins the dispatcher and all workers.
func (wp *WorkerPool) Start() {
	if wp.started.Load() {
		return
	}
	wp.started.Store(true)

	// Start workers
	for _, w := range wp.workers {
		wp.wg.Add(1)
		go w.run()
	}

	// Start dispatcher
	wp.wg.Add(1)
	go wp.dispatcher.run(wp)

	log.Printf("[pipeline] worker pool: %d workers, queue=%d",
		len(wp.workers), wp.cfg.QueueSize)
}

// EventCh returns the channel that receives parsed events.
func (wp *WorkerPool) EventCh() <-chan *collector.Event {
	return wp.eventCh
}

// ErrCh returns the error channel.
func (wp *WorkerPool) ErrCh() <-chan error {
	return wp.errCh
}

// Stop gracefully shuts down all workers and the dispatcher.
func (wp *WorkerPool) Stop() {
	close(wp.stopCh)
	wp.wg.Wait()
	close(wp.eventCh)
	close(wp.errCh)
}

// Stats returns performance counters.
func (wp *WorkerPool) Stats() map[string]interface{} {
	return map[string]interface{}{
		"workers":          len(wp.workers),
		"events_parsed":   wp.eventsParsed.Load(),
		"dispatcher_drops": wp.dispatcher.dropped.Load(),
	}
}

// ── Dispatcher ──────────────────────────────────────────────

func (d *Dispatcher) run(wp *WorkerPool) {
	defer wp.wg.Done()
	iter := 0

	for {
		select {
		case <-wp.stopCh:
			return
		default:
		}

		data, err := d.reader.ReadRaw()
		if err != nil {
			select {
			case wp.errCh <- err:
			default:
			}
			continue
		}

		// Round-robin dispatch
		n := d.next.Add(1) % uint64(len(d.queues))
		queue := d.queues[n]

		ev := &rawEvent{data: data, seq: d.next.Load()}
		if !queue.TryPush(ev.ptr()) {
			d.dropped.Add(1)
			SpinWait(iter)
			iter++
			continue
		}
		iter = 0
	}
}

// ── Worker ──────────────────────────────────────────────────

func (w *Worker) run() {
	defer w.pool.wg.Done()

	for {
		select {
		case <-w.pool.stopCh:
			return
		default:
		}

		item, ok := w.queue.TryPop()
		if !ok {
			runtime.Gosched()
			continue
		}

		ev := (*rawEvent)(item)
		parsed, err := collector.ParseRawEvent(ev.data)
		if err != nil {
			select {
			case w.pool.errCh <- err:
			default:
			}
			continue
		}

		w.pool.eventsParsed.Add(1)
		w.pool.eventCh <- parsed
	}
}
