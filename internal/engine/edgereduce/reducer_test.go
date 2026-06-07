// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package edgereduce

import (
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
)

// ─── Tests ──────────────────────────────────────────────────

func TestNewEdgeReducer(t *testing.T) {
	r := NewEdgeReducer(100, time.Second, nil)
	if r == nil {
		t.Fatal("NewEdgeReducer returned nil")
	}
	stats := r.Stats()
	if stats["max_size"] != 100 {
		t.Errorf("max_size = %d", stats["max_size"])
	}
	if stats["merge_window"] != "1s" {
		t.Errorf("window = %s", stats["merge_window"])
	}
}

func TestDefaultWindow(t *testing.T) {
	r := NewEdgeReducer(0, 0, nil)
	s := r.Stats()
	if s["merge_window"] != "5s" {
		t.Errorf("window = %v", s["merge_window"])
	}
	if s["max_size"] != 10000 {
		t.Errorf("max_size = %v", s["max_size"])
	}
}

func TestIngestNewEdge(t *testing.T) {
	r := NewEdgeReducer(100, time.Minute, nil)
	evt := &pb.Event{
		Type: 10, Pid: 100, Ppid: 1,
		Pathname: "/etc/shadow", Inode: 5000,
		DevMajor: 8, DevMinor: 3,
		TimestampNs: 1000,
	}

	ce, merged, err := r.Ingest(evt)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if merged {
		t.Error("new edge should not be merged")
	}
	if ce.Source != "p:100" {
		t.Errorf("source = %s", ce.Source)
	}
	if ce.Count != 1 {
		t.Errorf("count = %d", ce.Count)
	}
}

func TestIngestMergeDuplicate(t *testing.T) {
	r := NewEdgeReducer(100, time.Minute, nil)
	evt := &pb.Event{
		Type: 10, Pid: 100,
		Pathname: "/etc/shadow", Inode: 5000,
		DevMajor: 8, DevMinor: 3,
		TimestampNs: uint64(time.Now().UnixNano()),
	}

	// First — new
	_, merged1, _ := r.Ingest(evt)
	if merged1 {
		t.Error("first should not be merged")
	}

	// Second — within window, same source/target/type
	ce, merged2, _ := r.Ingest(evt)
	if !merged2 {
		t.Error("second should be merged")
	}
	if ce.Count != 2 {
		t.Errorf("count = %d, want 2", ce.Count)
	}
}

func TestIngestOutsideWindow(t *testing.T) {
	r := NewEdgeReducer(100, time.Millisecond, nil)
	evt := &pb.Event{
		Type: 10, Pid: 100,
		Pathname: "/etc/hosts", Inode: 1000,
		DevMajor: 8, DevMinor: 3,
		TimestampNs: uint64(time.Now().UnixNano()),
	}

	r.Ingest(evt)
	time.Sleep(2 * time.Millisecond)
	evt.TimestampNs = uint64(uint64(time.Now().UnixNano()))

	ce, merged, _ := r.Ingest(evt)
	if merged {
		t.Error("outside window should not be merged")
	}
	if ce.Count != 1 {
		t.Errorf("count = %d, want 1", ce.Count)
	}
}

func TestNeverMergeExecve(t *testing.T) {
	r := NewEdgeReducer(100, time.Minute, nil)
	evt := &pb.Event{
		Type: 2, Pid: 100, // EV_PROCESS_EXEC
		Pathname: "/bin/bash", Inode: 2000,
		DevMajor: 8, DevMinor: 3,
		TimestampNs: uint64(time.Now().UnixNano()),
	}

	ce, merged, err := r.Ingest(evt)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if merged {
		t.Error("exec events must never be merged")
	}
	_ = ce
}

func TestNeverMergeConnect(t *testing.T) {
	r := NewEdgeReducer(100, time.Minute, nil)
	evt := &pb.Event{
		Type: 20, Pid: 100, // EV_NET_CONNECT
		Daddr: 0x08080808, Dport: 443,
		TimestampNs: uint64(time.Now().UnixNano()),
	}

	ce, merged, _ := r.Ingest(evt)
	if merged {
		t.Error("connect events must never be merged")
	}
	_ = ce
}

func TestFlushAll(t *testing.T) {
	var flushed int64
	r := NewEdgeReducer(100, time.Minute, func(ce *CachedEdge) error {
		atomic.AddInt64(&flushed, 1)
		return nil
	})

	for i := 0; i < 5; i++ {
		r.Ingest(&pb.Event{
			Type: 10, Pid: uint32(100 + i),
			Pathname: "/tmp/test", Inode: uint64(i),
			DevMajor: 8, DevMinor: 3,
			TimestampNs: uint64(uint64(time.Now().UnixNano())),
		})
	}

	n := r.FlushAll()
	if n != 5 {
		t.Errorf("flushed = %d, want 5", n)
	}
}

func TestEviction(t *testing.T) {
	var flushed int64
	r := NewEdgeReducer(3, time.Minute, func(ce *CachedEdge) error {
		atomic.AddInt64(&flushed, 1)
		return nil
	})

	// Insert 5 different edges → 3 fit, 2 evicted
	for i := 0; i < 5; i++ {
		r.Ingest(&pb.Event{
			Type: 10, Pid: uint32(100 + i),
			Pathname: "/tmp/file", Inode: uint64(1000 + i),
			DevMajor: 8, DevMinor: 3,
			TimestampNs: uint64(uint64(time.Now().UnixNano())),
		})
	}

	if flushed < 2 {
		t.Errorf("expected ≥2 evictions, got %d", flushed)
	}

	stats := r.Stats()
	if stats["cache_size"].(int) > 3 {
		t.Errorf("cache size = %d, want ≤3", stats["cache_size"])
	}
}

func TestMultipleTargetTypes(t *testing.T) {
	r := NewEdgeReducer(100, time.Minute, nil)

	tests := []struct {
		name string
		evt  *pb.Event
	}{
		{"fork", &pb.Event{Type: 1, Pid: 100, ChildPid: 101, TimestampNs: 1}},
		{"file", &pb.Event{Type: 10, Pid: 100, Pathname: "/etc/hosts", Inode: 999, DevMajor: 8, DevMinor: 3, TimestampNs: 2}},
		{"network", &pb.Event{Type: 20, Pid: 100, Daddr: 0x08080808, Dport: 443, TimestampNs: 3}},
	}

	for _, tt := range tests {
		ce, _, err := r.Ingest(tt.evt)
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if ce.Source != "p:100" {
			t.Errorf("%s: source = %s", tt.name, ce.Source)
		}
		t.Logf("%s: source=%s target=%s rel=%s", tt.name, ce.Source, ce.Target, ce.Relation)
	}
}

func TestStats(t *testing.T) {
	r := NewEdgeReducer(100, time.Second, nil)

	r.Ingest(&pb.Event{Type: 10, Pid: 100, Pathname: "/a", Inode: 1, DevMajor: 8, DevMinor: 3, TimestampNs: 1})
	r.Ingest(&pb.Event{Type: 10, Pid: 100, Pathname: "/a", Inode: 1, DevMajor: 8, DevMinor: 3, TimestampNs: 2}) // merge

	stats := r.Stats()
	if stats["merged_edges"].(int64) != 1 {
		t.Errorf("merged = %d", stats["merged_edges"])
	}
	if stats["total_edges"].(int64) != 2 {
		t.Errorf("total = %d", stats["total_edges"])
	}
	if stats["cache_size"].(int) != 1 {
		t.Errorf("cache size = %d", stats["cache_size"])
	}
}

func TestToProtoEdge(t *testing.T) {
	now := time.Now()
	ce := &CachedEdge{
		Source: "p:100", Target: "f:500", Relation: "used",
		Count: 42, FirstSeen: now, LastSeen: now,
	}

	pe := ce.ToProtoEdge()
	if pe.Source != "p:100" {
		t.Errorf("Source = %s", pe.Source)
	}
	if pe.Count != 42 {
		t.Errorf("Count = %d", pe.Count)
	}
	if pe.Relation != "used" {
		t.Errorf("Relation = %s", pe.Relation)
	}
}

func TestFlushOld(t *testing.T) {
	var flushed int64
	r := NewEdgeReducer(100, 50*time.Millisecond, func(ce *CachedEdge) error {
		atomic.AddInt64(&flushed, 1)
		return nil
	})

	r.Ingest(&pb.Event{
		Type: 10, Pid: 100,
		Pathname: "/tmp/old", Inode: 1,
		DevMajor: 8, DevMinor: 3,
		TimestampNs: uint64(time.Now().Add(-time.Second).UnixNano()),
	})

	time.Sleep(100 * time.Millisecond)
	n := r.FlushOld()
	if n != 1 {
		t.Errorf("flushed old = %d, want 1", n)
	}
}
