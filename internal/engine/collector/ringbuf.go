// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/metrics"
)

// ─── Wire format (must match struct event in kernel/include/providapt.h) ───
//
//	Offset  Field          Type       Bytes
//	────────────────────────────────────────
//	     0  type           u32             4
//	     4  flags          u32             4
//	     8  timestamp_ns   u64             8
//	    16  pid            u32             4
//	    20  tid            u32             4
//	    24  ppid           u32             4
//	    28  uid            u32             4
//	    32  gid            u32             4
//	    36  payload        union [24]byte  24
//	    60  comm           char[16]       16
//	    76  pathname       char[256]     256
//	──────────────────────────────────────── 332 total
//
// union payload layout (file oriented):
//	   36  inode          u64             8
//	   44  dev_major      u32             4
//	   48  dev_minor      u32             4
//	   52  mode           u32             4
//	   56  f_flags        u32             4
//	                       union total:   24
//
// union payload layout (fork oriented):
//	   36  child_pid      u32             4
//	   40  reserved       [20]byte       20
//	                       union total:   24

const (
	eventHeaderSize = 36
	eventTotalSize  = 332
	unionSize       = 24
	commOffset      = 60
	commSize        = 16
	pathnameOffset  = 76
	pathnameSize    = 256
	childPidOffset  = 36
	inodeOffset     = 36
	devMajorOffset  = 44
	devMinorOffset  = 48
	modeOffset      = 52
	fFlagsOffset    = 56
)

// Event represents a single provenance event decoded from the eBPF ring buffer.
type Event struct {
	Type        syscall.EventType
	Flags       uint32
	TimestampNS uint64
	PID         uint32
	TID         uint32
	PPID        uint32
	UID         uint32
	GID         uint32

	// File payload (valid for file_* events)
	Inode    uint64
	DevMajor uint32
	DevMinor uint32
	Mode     uint32
	FFlags   uint32

	// Fork payload (valid for proc_fork)
	ChildPID uint32

	Comm     string
	Pathname string
}

// Start begins reading events from the BPF ring buffer.
// Returns channels for parsed events and errors.
func Start(rb *ringbuf.Reader) (<-chan *Event, <-chan error) {
	eventCh := make(chan *Event, 1024)
	errCh := make(chan error, 1)

	go func() {
		defer close(eventCh)
		defer close(errCh)

		for {
			record, err := rb.Read()
			if err != nil {
				errCh <- fmt.Errorf("ringbuf read: %w", err)
				return
			}

			metrics.EventsIngested.Inc()

			evt, err := ParseRawEvent(record.RawSample)
			if err != nil {
				metrics.EventsParseErrors.Inc()
				errCh <- fmt.Errorf("parse event: %w", err)
				continue
			}
			eventCh <- evt
		}
	}()

	return eventCh, errCh
}

// ParseRawEvent decodes a binary ring buffer record into an Event.
// The input must be exactly struct event (332 bytes) from the kernel side.
func ParseRawEvent(data []byte) (*Event, error) {
	if len(data) < eventTotalSize {
		return nil, fmt.Errorf("event too short: %d bytes, need %d",
			len(data), eventTotalSize)
	}

	rd := binary.LittleEndian

	evt := &Event{
		Type:        syscall.EventType(rd.Uint32(data[0:4])),
		Flags:       rd.Uint32(data[4:8]),
		TimestampNS: rd.Uint64(data[8:16]),
		PID:         rd.Uint32(data[16:20]),
		TID:         rd.Uint32(data[20:24]),
		PPID:        rd.Uint32(data[24:28]),
		UID:         rd.Uint32(data[28:32]),
		GID:         rd.Uint32(data[32:36]),
	}

	// Parse union payload
	evt.Inode = rd.Uint64(data[inodeOffset : inodeOffset+8])
	evt.DevMajor = rd.Uint32(data[devMajorOffset : devMajorOffset+4])
	evt.DevMinor = rd.Uint32(data[devMinorOffset : devMinorOffset+4])
	evt.Mode = rd.Uint32(data[modeOffset : modeOffset+4])
	evt.FFlags = rd.Uint32(data[fFlagsOffset : fFlagsOffset+4])
	evt.ChildPID = rd.Uint32(data[childPidOffset : childPidOffset+4])

	// Fixed-length strings
	evt.Comm = cString(data[commOffset : commOffset+commSize])
	evt.Pathname = cString(data[pathnameOffset : pathnameOffset+pathnameSize])

	return evt, nil
}

// cString extracts a null-terminated string from a byte slice.
func cString(buf []byte) string {
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}
