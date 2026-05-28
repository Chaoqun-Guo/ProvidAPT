package pipeline

import (
	"runtime"
	"sync/atomic"
	"unsafe"
)

// ═══════════════════════════════════════════════════════════════
// Lock-free SPSC (Single Producer, Single Consumer) ring buffer
//
// This is a wait-free bounded queue designed for the event dispatch
// path: one dispatcher goroutine writes, one worker goroutine reads.
//
// Memory ordering is managed via atomic load/store with
// memory barriers on x86_64 (sequential consistency is sufficient).
//
// The queue uses a power-of-two sized buffer with bit-mask wrapping,
// avoiding expensive modulo operations.
// ═══════════════════════════════════════════════════════════════

// maxQueueSize is the maximum number of items in the lock-free queue.
const maxQueueSize = 65536

// LockFreeQueue is an SPSC lock-free ring buffer.
type LockFreeQueue struct {
	buffer []unsafe.Pointer // item slots
	mask   uint64           // size - 1 (for bit-mask wrapping)
	head   atomic.Uint64    // consumer read index
	tail   atomic.Uint64    // producer write index
}

// NewLockFreeQueue creates an SPSC queue with the given size (rounded up to power of 2).
func NewLockFreeQueue(size int) *LockFreeQueue {
	if size <= 0 {
		size = 4096
	}
	if size > maxQueueSize {
		size = maxQueueSize
	}
	// Round to power of 2
	pow2 := uint64(1)
	for pow2 < uint64(size) {
		pow2 <<= 1
	}
	return &LockFreeQueue{
		buffer: make([]unsafe.Pointer, pow2),
		mask:   pow2 - 1,
	}
}

// TryPush attempts to add an item.  Returns false if the queue is full.
func (q *LockFreeQueue) TryPush(item unsafe.Pointer) bool {
	tail := q.tail.Load()
	head := q.head.Load()

	if tail-head >= uint64(len(q.buffer)) {
		return false // full
	}

	// Write item, then advance tail (release semantics)
	slot := tail & q.mask
	q.buffer[slot] = item
	q.tail.Store(tail + 1)
	return true
}

// TryPop attempts to remove an item.  Returns item and true, or nil and false if empty.
func (q *LockFreeQueue) TryPop() (unsafe.Pointer, bool) {
	head := q.head.Load()
	tail := q.tail.Load()

	if head >= tail {
		return nil, false // empty
	}

	slot := head & q.mask
	item := q.buffer[slot]
	if item == nil {
		return nil, false
	}

	// Clear slot and advance head (release semantics)
	q.buffer[slot] = nil
	q.head.Store(head + 1)
	return item, true
}

// Len returns the approximate number of items in the queue.
func (q *LockFreeQueue) Len() int {
	return int(q.tail.Load() - q.head.Load())
}

// Cap returns the maximum capacity.
func (q *LockFreeQueue) Cap() int {
	return len(q.buffer)
}

// ═══════════════════════════════════════════════════════════════
// Raw event wrapper for passing across the queue
// ═══════════════════════════════════════════════════════════════

// rawEvent is a pointer-wrapped byte slice for lock-free transfer.
type rawEvent struct {
	data []byte
	seq  uint64
}

// pointerConvert converts between *rawEvent and unsafe.Pointer.
func (e *rawEvent) ptr() unsafe.Pointer {
	return unsafe.Pointer(e)
}

// ═══════════════════════════════════════════════════════════════
// Wait-free helpers
// ═══════════════════════════════════════════════════════════════

// SpinWait yields the CPU briefly to allow other goroutines to
// make progress.  This is used in the dispatcher when the queue
// is full.
func SpinWait(iter int) {
	if iter < 10 {
		// Light pause — just loop
	} else if iter < 30 {
		runtime.Gosched()
	} else {
		runtime.Gosched()
	}
}
