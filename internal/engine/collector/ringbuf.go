// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/metrics"
	"github.com/cilium/ebpf/ringbuf"
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
//	    60  sample_hook_id u32             4
//	    64  sample_count   u32             4
//	    68  comm           char[16]       16
//	    84  pathname       char[256]     256
//	──────────────────────────────────────── 340 total
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
	eventHeaderSize    = 36
	eventTotalSize     = 340
	unionSize          = 24
	sampleHookIDOffset = 60
	sampleCountOffset  = 64
	commOffset         = 68
	commSize           = 16
	pathnameOffset     = 84
	pathnameSize       = 256
	childPidOffset     = 36
	inodeOffset        = 36
	saddrOffset        = 36
	daddrOffset        = 40
	sportOffset        = 44
	dportOffset        = 46
	protocolOffset     = 48
	devMajorOffset     = 44
	devMinorOffset     = 48
	modeOffset         = 52
	fFlagsOffset       = 56
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

	// Sample payload metadata
	SampleHookID uint32
	SampleCount  uint32

	// Network payload (valid for net_* events)
	Saddr    uint32
	Daddr    uint32
	Sport    uint16
	Dport    uint16
	Protocol uint8

	Comm     string
	Pathname string
	ExePath  string
	Cmdline  string
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
// The input must be at least struct event (340 bytes) from the kernel side.
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
	evt.SampleHookID = rd.Uint32(data[sampleHookIDOffset : sampleHookIDOffset+4])
	evt.SampleCount = rd.Uint32(data[sampleCountOffset : sampleCountOffset+4])
	evt.Saddr = rd.Uint32(data[saddrOffset : saddrOffset+4])
	evt.Daddr = rd.Uint32(data[daddrOffset : daddrOffset+4])
	evt.Sport = rd.Uint16(data[sportOffset : sportOffset+2])
	evt.Dport = rd.Uint16(data[dportOffset : dportOffset+2])
	evt.Protocol = data[protocolOffset]

	// Fixed-length strings
	evt.Comm = cString(data[commOffset : commOffset+commSize])
	evt.Pathname = cString(data[pathnameOffset : pathnameOffset+pathnameSize])
	evt.normalizePathname()

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

func (e *Event) normalizePathname() {
	if !isPathBackedEvent(e.Type) || !pathUnavailable(e.Pathname) {
		return
	}
	if e.Inode == 0 {
		return
	}
	e.Pathname = fmt.Sprintf("inode://%d:%d/%d", e.DevMajor, e.DevMinor, e.Inode)
}

func isPathBackedEvent(typ syscall.EventType) bool {
	switch typ {
	case syscall.EventProcessExec,
		syscall.EventFileOpen,
		syscall.EventFileCreate,
		syscall.EventFileModify,
		syscall.EventFileDelete,
		syscall.EventFileRename:
		return true
	default:
		return false
	}
}

func pathUnavailable(pathname string) bool {
	pathname = strings.TrimSpace(pathname)
	return pathname == "" ||
		pathname == "?" ||
		pathname == "\u2026" ||
		strings.ContainsRune(pathname, '\uFFFD')
}
