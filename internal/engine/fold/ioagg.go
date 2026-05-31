// Package fold implements kernel-side event folding for ProvidAPT v2.1.
//
// Reduces ring buffer pressure by aggregating high-frequency I/O events
// in kernel BPF maps and only emitting summary events at close() or
// on a periodic timer.
package fold

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// IO aggregation
// ═══════════════════════════════════════════════════════════════

// AggKey is the composite key for the IO aggregation map.
// Matches the kernel-side BPF map key: (pid, fd, op_type).
type AggKey struct {
	PID    uint32 `json:"pid"`
	FD     int32  `json:"fd"`
	OpType uint32 `json:"op_type"` // 0=read, 1=write
}

func (k AggKey) String() string {
	op := "R"
	if k.OpType == 1 {
		op = "W"
	}
	return fmt.Sprintf("%s:%d:%d", op, k.PID, k.FD)
}

// AggValue holds the accumulated counters for an IO aggregation entry.
type AggValue struct {
	Count      uint64    `json:"count"`       // number of IO operations
	TotalBytes uint64    `json:"total_bytes"` // total bytes transferred
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// AggregateEvent is emitted when a folded IO summary is flushed.
type AggregateEvent struct {
	PID        uint32    `json:"pid"`
	Comm       string    `json:"comm"`
	FD         int32     `json:"fd"`
	OpType     uint32    `json:"op_type"`
	Count      uint64    `json:"count"`
	TotalBytes uint64    `json:"total_bytes"`
	Duration   string    `json:"duration"` // aggregation window
}

// IOAggregator folds small IO events into aggregated summaries.
// In production, the counters live in a BPF_MAP_TYPE_HASH on the
// kernel side.  This userspace component manages the flush lifecycle.
type IOAggregator struct {
	mu         sync.Mutex
	agg        map[AggKey]*AggValue
	flushInt   time.Duration   // default 1 second
	batchSize  int             // flush if count exceeds this
	lastFlush  time.Time
	flushed    []*AggregateEvent
	totalFolded int64
	totalEvents int64 // would have been without folding
}

// NewIOAggregator creates an IO aggregator.
func NewIOAggregator() *IOAggregator {
	return &IOAggregator{
		agg:       make(map[AggKey]*AggValue),
		flushInt:  time.Second,
		batchSize: 100,
		lastFlush: time.Now(),
	}
}

// RecordIO records a read or write operation.
// In production, this is the userspace consumer of the BPF agg map.
func (ia *IOAggregator) RecordIO(pid uint32, comm string, fd int32, opType uint32, bytes uint64) {
	key := AggKey{PID: pid, FD: fd, OpType: opType}
	now := time.Now()

	ia.mu.Lock()
	val, ok := ia.agg[key]
	if ok {
		val.Count++
		val.TotalBytes += bytes
		val.LastSeen = now
	} else {
		ia.agg[key] = &AggValue{
			Count:      1,
			TotalBytes: bytes,
			FirstSeen:  now,
			LastSeen:   now,
		}
	}
	ia.totalEvents++
	ia.mu.Unlock()
}

// OnClose is called when a file descriptor is closed.
// Forces an immediate flush of the aggregated data for that FD.
func (ia *IOAggregator) OnClose(pid uint32, fd int32) {
	ia.mu.Lock()
	keysToFlush := []AggKey{}
	for key := range ia.agg {
		if key.PID == pid && key.FD == fd {
			keysToFlush = append(keysToFlush, key)
		}
	}
	ia.mu.Unlock()

	for _, key := range keysToFlush {
		ia.flushKey(key, "close")
	}
}

// Tick flushes all entries that have accumulated enough data.
// Called periodically (every second in production via eBPF timer).
func (ia *IOAggregator) Tick(commMap map[uint32]string) int {
	ia.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(ia.lastFlush)
	flushCount := 0

	for key, val := range ia.agg {
		shouldFlush := false

		// Flush if count exceeds batch size
		if val.Count >= uint64(ia.batchSize) {
			shouldFlush = true
		}

		// Flush if time exceeds flush interval
		if elapsed >= ia.flushInt && val.Count > 0 {
			shouldFlush = true
		}

		if shouldFlush {
			comm := commMap[key.PID]
			ia.flushed = append(ia.flushed, &AggregateEvent{
				PID:        key.PID,
				Comm:       comm,
				FD:         key.FD,
				OpType:     key.OpType,
				Count:      val.Count,
				TotalBytes: val.TotalBytes,
				Duration:   val.LastSeen.Sub(val.FirstSeen).String(),
			})
			ia.totalFolded += int64(val.Count)
			delete(ia.agg, key)
			flushCount++
		}
	}

	ia.lastFlush = now
	ia.mu.Unlock()

	return flushCount
}

// flushKey flushes a single aggregation key.
func (ia *IOAggregator) flushKey(key AggKey, reason string) {
	ia.mu.Lock()
	val, ok := ia.agg[key]
	if !ok {
		ia.mu.Unlock()
		return
	}
	ia.flushed = append(ia.flushed, &AggregateEvent{
		PID:        key.PID,
		FD:         key.FD,
		OpType:     key.OpType,
		Count:      val.Count,
		TotalBytes: val.TotalBytes,
		Duration:   val.LastSeen.Sub(val.FirstSeen).String(),
	})
	ia.totalFolded += int64(val.Count)
	delete(ia.agg, key)
	ia.mu.Unlock()

	log.Printf("[fold] flush %s reason=%s count=%d bytes=%d",
		key, reason, val.Count, val.TotalBytes)
}

// SetFlushInterval adjusts the aggregation window dynamically.
// Called by the throttle module based on CPU load.
func (ia *IOAggregator) SetFlushInterval(d time.Duration) {
	ia.mu.Lock()
	defer ia.mu.Unlock()
	ia.flushInt = d
	log.Printf("[fold] flush interval updated to %v", d)
}

// Stats returns aggregator statistics.
func (ia *IOAggregator) Stats() map[string]interface{} {
	ia.mu.Lock()
	defer ia.mu.Unlock()

	foldRatio := 0.0
	if ia.totalEvents > 0 {
		foldRatio = float64(ia.totalFolded) / float64(ia.totalEvents) * 100.0
	}
	return map[string]interface{}{
		"active_entries":  len(ia.agg),
		"total_events":    ia.totalEvents,
		"total_folded":    ia.totalFolded,
		"fold_ratio":      fmt.Sprintf("%.1f%%", foldRatio),
		"flush_interval":  ia.flushInt.String(),
		"batch_size":      ia.batchSize,
	}
}
