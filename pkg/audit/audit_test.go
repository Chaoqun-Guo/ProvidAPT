// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewStore(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	if s.path != filepath.Join(dir, "audit.ndjson") {
		t.Errorf("path = %q, want %q", s.path, filepath.Join(dir, "audit.ndjson"))
	}
}

func TestLogAndRecent(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	entries, err := s.Recent(10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}

	s.Log(Entry{
		Category: CatSystem,
		Severity: "INFO",
		Message:  "test entry",
		Source:   "test",
	})

	entries, err = s.Recent(10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Message != "test entry" {
		t.Errorf("message = %q, want %q", entries[0].Message, "test entry")
	}
	if entries[0].Source != "test" {
		t.Errorf("source = %q, want %q", entries[0].Source, "test")
	}
	if entries[0].ID == "" {
		t.Error("expected non-empty ID")
	}
	if entries[0].Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestLogMultipleCategories(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	s.Log(Entry{Category: CatSystem, Severity: "INFO", Message: "startup", Source: "test"})
	s.Log(Entry{Category: CatSecurity, Severity: "WARNING", Message: "anomaly", Source: "test"})
	s.Log(Entry{Category: CatAdmin, Severity: "INFO", Message: "purge", Source: "cli"})
	s.Log(Entry{Category: CatIntegrity, Severity: "CRITICAL", Message: "ebpf missing", Source: "test"})

	// Query by category
	security, err := s.Query(CatSecurity, time.Time{}, 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(security) != 1 || security[0].Message != "anomaly" {
		t.Errorf("expected 1 security entry, got %d: %v", len(security), security)
	}

	// Query with time filter
	future := time.Now().Add(1 * time.Hour)
	none, err := s.Query(CatAdmin, future, 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("expected 0 entries after future time, got %d", len(none))
	}
}

func TestLogWithDetails(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	s.Log(Entry{
		Category: CatSecurity,
		Severity: "CRITICAL",
		Message:  "honeypot triggered",
		Source:   "deception",
		Details: map[string]interface{}{
			"pid":   float64(1234),
			"comm":  "curl",
			"path":  "/tmp/backup_credentials.xml",
			"count": float64(1),
		},
	})

	entries, err := s.Recent(10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Details["comm"] != "curl" {
		t.Errorf("details['comm'] = %v, want 'curl'", entries[0].Details["comm"])
	}
}

func TestReplayOnOpen(t *testing.T) {
	dir := t.TempDir()

	// Create first store and add entries.
	s1, err := New(dir)
	if err != nil {
		t.Fatalf("New s1: %v", err)
	}
	s1.Log(Entry{Category: CatSystem, Severity: "INFO", Message: "boot", Source: "test"})
	s1.Log(Entry{Category: CatSecurity, Severity: "WARNING", Message: "alert", Source: "test"})
	s1.Close()

	// Re-open and verify entries are replayed.
	s2, err := New(dir)
	if err != nil {
		t.Fatalf("New s2: %v", err)
	}
	defer s2.Close()

	entries, err := s2.Recent(10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 replayed entries, got %d", len(entries))
	}
}

func TestReplaySkipsCorruptLines(t *testing.T) {
	dir := t.TempDir()

	// Write a valid entry followed by a corrupt line.
	valid := Entry{Category: CatSystem, Severity: "INFO", Message: "good", Source: "test"}
	data, _ := json.Marshal(valid)
	corrupt := []byte("{not-json}\n")

	path := filepath.Join(dir, "audit.ndjson")
	os.WriteFile(path, append(append(data, '\n'), corrupt...), 0644)

	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	entries, err := s.Recent(10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 valid entry (corrupt skipped), got %d", len(entries))
	}
}

func TestNDJSONFileFormat(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	s.Log(Entry{Category: CatSystem, Severity: "INFO", Message: "line1", Source: "test"})
	s.Log(Entry{Category: CatAdmin, Severity: "INFO", Message: "line2", Source: "test"})
	s.Close()

	data, err := os.ReadFile(filepath.Join(dir, "audit.ndjson"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSON lines, got %d", len(lines))
	}

	var e1 Entry
	if err := json.Unmarshal([]byte(lines[0]), &e1); err != nil {
		t.Fatalf("line 1 unmarshal: %v", err)
	}
	if e1.Message != "line1" {
		t.Errorf("line 1 message = %q", e1.Message)
	}
}

func TestCloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.Close()
	s.Close() // must not panic
}

func BenchmarkLog(b *testing.B) {
	dir := b.TempDir()
	s, err := New(dir)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	defer s.Close()

	e := Entry{
		Category: CatSystem,
		Severity: "INFO",
		Message:  "benchmark log entry with some extra text",
		Source:   "bench",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Log(e)
	}
}

func BenchmarkQuery(b *testing.B) {
	dir := b.TempDir()
	s, err := New(dir)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	defer s.Close()

	for i := 0; i < 5000; i++ {
		s.Log(Entry{
			Category: CatSystem,
			Severity: "INFO",
			Message:  "entry",
			Source:   "bench",
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Query(CatSystem, time.Time{}, 100)
	}
}
