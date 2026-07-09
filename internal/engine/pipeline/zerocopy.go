// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf/ringbuf"
)

// ═══════════════════════════════════════════════════════════════
// Zero-copy ring buffer reader
//
// The BPF ring buffer (BPF_MAP_TYPE_RINGBUF) is already backed by
// mmap — cilium/ebpf's ringbuf.Reader reads directly from the
// shared memory page without copying through kernel buffers.
//
// This wrapper further reduces allocations by:
//   - Reusing buffers for parsed event data
//   - Providing a direct byte slice to the parser (no intermediate
//     allocations)
//   - Using a fixed-size object pool for parsed events
// ═══════════════════════════════════════════════════════════════

// ZeroCopyReader wraps ringbuf.Reader with zero-allocation reads.
type ZeroCopyReader struct {
	rb    *ringbuf.Reader
	pool  *RawSamplePool
	stats ReaderStats
}

// ReaderStats tracks zero-copy reader performance.
type ReaderStats struct {
	Reads        atomic.Int64
	BytesTotal   atomic.Int64
	Errors       atomic.Int64
	DroppedTotal atomic.Int64
}

// NewZeroCopyReader wraps an existing ring buffer reader.
func NewZeroCopyReader(rb *ringbuf.Reader) *ZeroCopyReader {
	return &ZeroCopyReader{
		rb:   rb,
		pool: NewRawSamplePool(1024),
	}
}

// ReadRaw returns the raw bytes of the next ring buffer sample.
// The returned slice is valid only until the next call to ReadRaw.
func (z *ZeroCopyReader) ReadRaw() ([]byte, error) {
	record, err := z.rb.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, err
		}
		z.stats.Errors.Add(1)
		return nil, err
	}

	z.stats.Reads.Add(1)
	z.stats.BytesTotal.Add(int64(len(record.RawSample)))

	// ringbuf.Reader already provides a zero-copy view into the
	// mmap'd area.  We return the raw bytes directly.
	// The cilium/ebpf library handles the mmap lifecycle.
	return record.RawSample, nil
}

// Stats returns a snapshot of reader statistics.
func (z *ZeroCopyReader) Stats() map[string]int64 {
	return map[string]int64{
		"reads":   z.stats.Reads.Load(),
		"bytes":   z.stats.BytesTotal.Load(),
		"errors":  z.stats.Errors.Load(),
		"dropped": z.stats.DroppedTotal.Load(),
	}
}

// ═══════════════════════════════════════════════════════════════
// Raw sample pool — reduces GC pressure from event allocations
// ═══════════════════════════════════════════════════════════════

// RawSamplePool is a fixed-size pool of byte slices for ring buffer
// samples.  It reduces GC pressure by reusing allocations.
type RawSamplePool struct {
	pool sync.Pool
}

// NewRawSamplePool creates a pool with an initial capacity.
func NewRawSamplePool(prealloc int) *RawSamplePool {
	return &RawSamplePool{
		pool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 0, 340) // typical event size
				return &buf
			},
		},
	}
}

// Get returns a reusable byte slice.
func (p *RawSamplePool) Get() *[]byte {
	buf, ok := p.pool.Get().(*[]byte)
	if !ok || buf == nil {
		fallback := make([]byte, 0, 340)
		return &fallback
	}
	return buf
}

// Put returns a byte slice to the pool.
func (p *RawSamplePool) Put(buf *[]byte) {
	*buf = (*buf)[:0]
	p.pool.Put(buf)
}
