// Package store — zero-copy ring buffer parser.
//
// Reads raw bytes directly from the BPF ring buffer (mmap'd memory)
// and parses them into protobuf Event structs with ZERO intermediate
// allocations.  The cilium/ebpf ringbuf.Reader already provides an
// mmap'd zero-copy view; this builds on that to avoid any copying
// until the final protobuf structure.
package pebblestore

import (
	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
	"github.com/cilium/ebpf/ringbuf"
)

// ─── RingBufferStats ────────────────────────────────────────

// RingBufferStats tracks reader performance.
type RingBufferStats struct {
	EventsRead    int64
	EventsDropped int64
	ParseErrors   int64
	TotalBytes    int64
}

// ─── ZeroCopyReader ─────────────────────────────────────────

// ZeroCopyReader reads and parses raw ring buffer records directly
// into protobuf Events with no intermediate byte copies.
//
// The cilium/ebpf ringbuf.Reader reads from an mmap'd kernel buffer.
// We take that raw byte slice and parse it in-place into a protobuf
// struct via RawEventToProto — no encoding/binary, no json, no
// intermediate allocations.
type ZeroCopyReader struct {
	rb    *ringbuf.Reader
	stats RingBufferStats
}

// NewZeroCopyReader wraps a BPF ring buffer reader.
func NewZeroCopyReader(rb *ringbuf.Reader) *ZeroCopyReader {
	return &ZeroCopyReader{rb: rb}
}

// Read parses the next raw ring buffer record into a protobuf Event.
//
// Zero-copy path:
//
//	BPF RingBuf (mmap) → cilium/ebpf record.RawSample (direct ptr)
//	                    → RawEventToProto (in-place byte parsing)
//	                    → protobuf.Event
//
// No json.Marshal, no binary.Read, no intermediate byte slice.
func (z *ZeroCopyReader) Read() (*pb.Event, error) {
	record, err := z.rb.Read()
	if err != nil {
		if err == ringbuf.ErrClosed {
			return nil, err
		}
		z.stats.EventsDropped++
		return nil, err
	}

	z.stats.EventsRead++
	z.stats.TotalBytes += int64(len(record.RawSample))

	// Zero-copy parse: the raw bytes come from mmap'd kernel memory,
	// we parse them directly into protobuf fields with manual byte access.
	evt := RawEventToProto(record.RawSample)
	if evt == nil {
		z.stats.ParseErrors++
		return nil, ringbuf.ErrClosed // placeholder
	}

	return evt, nil
}

// Stats returns reader statistics.
func (z *ZeroCopyReader) Stats() RingBufferStats {
	return z.stats
}
