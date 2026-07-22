// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
)

func testEvent() *collector.Event {
	return &collector.Event{
		PID:  100,
		PPID: 1,
		UID:  1000,
		Comm: "test-proc",
	}
}

func TestNewJSONWriter(t *testing.T) {
	dir := t.TempDir()
	w, err := NewJSONWriter(dir)
	if err != nil {
		t.Fatalf("NewJSONWriter failed: %v", err)
	}
	defer w.Close()

	if w.dir != dir {
		t.Errorf("dir = %q, want %q", w.dir, dir)
	}
	if w.f == nil {
		t.Error("file handle should not be nil")
	}
}

func TestJSONWriterWriteAndRead(t *testing.T) {
	dir := t.TempDir()
	w, err := NewJSONWriter(dir)
	if err != nil {
		t.Fatalf("NewJSONWriter failed: %v", err)
	}

	evt := testEvent()
	if err := w.Write(evt); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	w.Close()

	// Read back and verify
	data, err := os.ReadFile(w.filename)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	var decoded collector.NormalizedEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON unmarshal failed: %v (content: %s)", err, string(data))
	}
	if decoded.Process.PID != evt.PID {
		t.Errorf("PID = %d, want %d", decoded.Process.PID, evt.PID)
	}
}

func TestJSONWriterUsesTypedPayload(t *testing.T) {
	dir := t.TempDir()
	w, err := NewJSONWriter(dir)
	if err != nil {
		t.Fatalf("NewJSONWriter failed: %v", err)
	}

	evt := &collector.Event{
		Type:        syscall.EventProcessFork,
		TimestampNS: 42,
		PID:         100,
		TID:         100,
		PPID:        1,
		UID:         0,
		GID:         0,
		Comm:        "bash",
		ChildPID:    101,
		Inode:       101,
		Saddr:       101,
	}
	if err := w.Write(evt); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	w.Close()

	data, err := os.ReadFile(w.filename)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	payload := decoded["payload"].(map[string]interface{})
	if payload["child_pid"].(float64) != 101 {
		t.Fatalf("child_pid = %v, want 101", payload["child_pid"])
	}
	if _, ok := payload["inode"]; ok {
		t.Fatal("fork payload should not expose inode")
	}
	if _, ok := payload["saddr"]; ok {
		t.Fatal("fork payload should not expose saddr")
	}
}

func TestJSONWriterMultipleEvents(t *testing.T) {
	dir := t.TempDir()
	w, err := NewJSONWriter(dir)
	if err != nil {
		t.Fatalf("NewJSONWriter failed: %v", err)
	}

	for i := 0; i < 10; i++ {
		evt := testEvent()
		evt.PID = uint32(100 + i)
		if err := w.Write(evt); err != nil {
			t.Fatalf("Write %d failed: %v", i, err)
		}
	}
	w.Close()

	data, err := os.ReadFile(w.filename)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 10 {
		t.Fatalf("expected 10 JSON lines, got %d", len(lines))
	}
}

func TestJSONWriterRotatesAndPrunes(t *testing.T) {
	dir := t.TempDir()
	w, err := NewJSONWriter(dir)
	if err != nil {
		t.Fatalf("NewJSONWriter failed: %v", err)
	}
	w.maxFileBytes = 350
	w.retainFiles = 2

	for i := 0; i < 6; i++ {
		evt := testEvent()
		evt.PID = uint32(100 + i)
		evt.Pathname = strings.Repeat("x", 120)
		if err := w.Write(evt); err != nil {
			t.Fatalf("Write %d failed: %v", i, err)
		}
	}
	w.Close()

	matches, err := filepath.Glob(filepath.Join(dir, "providapt-*.ndjson"))
	if err != nil {
		t.Fatalf("Glob failed: %v", err)
	}
	if len(matches) > 2 {
		t.Fatalf("retained files = %d, want <= 2: %#v", len(matches), matches)
	}
	if len(matches) < 2 {
		t.Fatalf("expected rotation to create at least 2 files, got %d", len(matches))
	}
}

func TestJSONWriterOptionsDisableArchivedRetention(t *testing.T) {
	dir := t.TempDir()
	w, err := NewJSONWriterWithOptions(dir, JSONWriterOptions{
		MaxFileBytes: 300,
		RetainFiles:  0,
	})
	if err != nil {
		t.Fatalf("NewJSONWriterWithOptions failed: %v", err)
	}

	for i := 0; i < 5; i++ {
		evt := testEvent()
		evt.PID = uint32(200 + i)
		evt.Pathname = strings.Repeat("x", 120)
		if err := w.Write(evt); err != nil {
			t.Fatalf("Write %d failed: %v", i, err)
		}
	}
	w.Close()

	matches, err := filepath.Glob(filepath.Join(dir, "providapt-*.ndjson"))
	if err != nil {
		t.Fatalf("Glob failed: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("retained files = %d, want active file only: %#v", len(matches), matches)
	}
}

func TestJSONWriterRetainsByTotalBytes(t *testing.T) {
	dir := t.TempDir()
	w, err := NewJSONWriterWithOptions(dir, JSONWriterOptions{
		MaxFileBytes: 280,
		RetainFiles:  1,
		RetainBytes:  1200,
	})
	if err != nil {
		t.Fatalf("NewJSONWriterWithOptions failed: %v", err)
	}

	for i := 0; i < 8; i++ {
		evt := testEvent()
		evt.PID = uint32(300 + i)
		evt.Pathname = strings.Repeat("x", 120)
		if err := w.Write(evt); err != nil {
			t.Fatalf("Write %d failed: %v", i, err)
		}
	}
	w.Close()

	matches, err := filepath.Glob(filepath.Join(dir, "providapt-*.ndjson"))
	if err != nil {
		t.Fatalf("Glob failed: %v", err)
	}
	if len(matches) <= 1 {
		t.Fatalf("retained files = %d, want archives despite retain_files=1: %#v", len(matches), matches)
	}
	var total int64
	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		total += info.Size()
	}
	if total > 1200 {
		t.Fatalf("retained bytes = %d, want <= 1200", total)
	}
}

func TestJSONWriterCloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	w, err := NewJSONWriter(dir)
	if err != nil {
		t.Fatalf("NewJSONWriter failed: %v", err)
	}
	// Close twice should not panic
	w.Close()
	w.Close()
}

func TestNewWriterJSON(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir, "json")
	if err != nil {
		t.Fatalf("NewWriter(json) failed: %v", err)
	}
	defer w.Close()

	evt := testEvent()
	if err := w.Write(evt); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
}

func TestNewWriterUnknownFormat(t *testing.T) {
	_, err := NewWriter(t.TempDir(), "csv")
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewWriterParquet(t *testing.T) {
	w, err := NewWriter(t.TempDir(), "parquet")
	if err != nil {
		t.Fatalf("NewWriter(parquet) failed: %v", err)
	}
	defer w.Close()

	evt := testEvent()
	if err := w.Write(evt); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
}

func TestNewWriterCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dir", "structure")
	w, err := NewJSONWriter(dir)
	if err != nil {
		t.Fatalf("NewJSONWriter failed: %v", err)
	}
	w.Close()

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("directory was not created")
	}
}

func TestWriterCloseNilJSON(t *testing.T) {
	w := &Writer{format: "json"}
	// Close without a JSON writer — should not panic
	w.Close()
}

// Benchmark JSON serialization
func BenchmarkJSONWriterWrite(b *testing.B) {
	dir := b.TempDir()
	w, err := NewJSONWriter(dir)
	if err != nil {
		b.Fatalf("NewJSONWriter failed: %v", err)
	}
	defer w.Close()

	evt := testEvent()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Write(evt)
	}
}
