// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package audit provides a persistent audit logging framework for
// security-relevant and administrative events. Entries are stored as
// newline-delimited JSON (NDJSON) for easy querying and forwarding.
package audit

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Category identifies the type of audit event.
type Category string

const (
	CatSecurity  Category = "security"  // Security events (honeypot trigger, tamper detection)
	CatAdmin     Category = "admin"     // Admin operations (purge, restart, config change)
	CatSystem    Category = "system"    // System events (startup, shutdown, self-check failures)
	CatIntegrity Category = "integrity" // Integrity events (eBPF missing, map inconsistency)
)

// Entry is a single audit log entry persisted as a JSON line.
type Entry struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Category  Category               `json:"category"`
	Severity  string                 `json:"severity"` // INFO, WARNING, CRITICAL
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Source    string                 `json:"source"` // module name ("selfheal", "armor", "cli")
}

// Store persists audit entries to an NDJSON file and maintains a
// bounded in-memory buffer for efficient recent-entry queries.
// The on-disk file is automatically rotated when it exceeds MaxFileSize.
type Store struct {
	mu          sync.Mutex
	f           *os.File
	path        string
	entries     []Entry
	maxSize     int
	maxFileSize int64  // bytes; 0 = no rotation
	maxBackups  int    // number of rotated files to retain
}

// New creates or opens an audit store at <dir>/audit.ndjson.
func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("audit mkdir: %w", err)
	}

	path := filepath.Join(dir, "audit.ndjson")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("audit open %s: %w", path, err)
	}

	s := &Store{
		f:           f,
		path:        path,
		entries:     make([]Entry, 0, 1024),
		maxSize:     10000,
		maxFileSize: 100 * 1024 * 1024, // 100 MB default
		maxBackups:  3,
	}

	// Replay existing entries into memory.
	if fi, _ := os.Stat(path); fi != nil && fi.Size() > 0 {
		if err := s.replay(); err != nil {
			// Non-fatal — entries remain on disk.
			fmt.Fprintf(os.Stderr, "audit replay warning: %v\n", err)
		}
	}

	return s, nil
}

// Log records a single audit entry. It is written to the NDJSON file
// immediately and retained in the in-memory buffer.
func (s *Store) Log(entry Entry) error {
	if entry.ID == "" {
		entry.ID = generateID()
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit marshal: %w", err)
	}
	data = append(data, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	// Rotate if current file exceeds maxFileSize.
	if s.maxFileSize > 0 {
		if fi, _ := s.f.Stat(); fi != nil && fi.Size() > s.maxFileSize {
			if err := s.rotate(); err != nil {
				fmt.Fprintf(os.Stderr, "audit rotate warning: %v\n", err)
			}
		}
	}

	if _, err := s.f.Write(data); err != nil {
		return fmt.Errorf("audit write: %w", err)
	}

	s.entries = append(s.entries, entry)
	if len(s.entries) > s.maxSize {
		s.entries = s.entries[len(s.entries)-s.maxSize:]
	}

	return nil
}

// Query returns entries matching the given category, from the given
// time onwards, up to the given limit.
func (s *Store) Query(cat Category, since time.Time, limit int) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []Entry
	for _, e := range s.entries {
		if cat != "" && e.Category != cat {
			continue
		}
		if !since.IsZero() && e.Timestamp.Before(since) {
			continue
		}
		out = append(out, e)
	}

	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}

	// Return a copy to avoid races.
	result := make([]Entry, len(out))
	copy(result, out)
	return result, nil
}

// Recent returns the most recent entries up to the given limit.
func (s *Store) Recent(limit int) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 || len(s.entries) == 0 {
		return nil, nil
	}

	start := 0
	if len(s.entries) > limit {
		start = len(s.entries) - limit
	}

	out := make([]Entry, len(s.entries[start:]))
	copy(out, s.entries[start:])
	return out, nil
}

// Close closes the underlying file.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f != nil {
		return s.f.Close()
	}
	return nil
}

// rotate closes the current file, renames it with a timestamp suffix,
// opens a new file, and cleans up old backups.
func (s *Store) rotate() error {
	// Close current file.
	if err := s.f.Close(); err != nil {
		return fmt.Errorf("close audit: %w", err)
	}

	// Rename with timestamp.
	timestamp := time.Now().UTC().Format("20060102T150405")
	rotatedPath := s.path + "." + timestamp
	if err := os.Rename(s.path, rotatedPath); err != nil {
		return fmt.Errorf("rename audit: %w", err)
	}

	// Open new file.
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// Try to restore the old file.
		os.Rename(rotatedPath, s.path)
		return fmt.Errorf("open new audit: %w", err)
	}
	s.f = f

	// Clean up old backups beyond maxBackups.
	if s.maxBackups > 0 {
		dir := filepath.Dir(s.path)
		base := filepath.Base(s.path)
		entries, _ := os.ReadDir(dir)
		var backups []string
		for _, e := range entries {
			if !e.IsDir() && len(e.Name()) > len(base) && e.Name()[:len(base)] == base && e.Name()[len(base)] == '.' {
				backups = append(backups, filepath.Join(dir, e.Name()))
			}
		}
		// Sort by name (which includes timestamp, making it chronological).
		// Remove oldest beyond maxBackups.
		for len(backups) > s.maxBackups {
			// Find the oldest (sorted by name = oldest timestamp)
			oldest := 0
			for i := 1; i < len(backups); i++ {
				if backups[i] < backups[oldest] {
					oldest = i
				}
			}
			os.Remove(backups[oldest])
			backups = append(backups[:oldest], backups[oldest+1:]...)
		}
	}

	return nil
}

// ── helpers ──────────────────────────────────────────────────────

// replay reads the NDJSON file and populates the in-memory buffer.
func (s *Store) replay() error {
	f, err := os.Open(s.path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Grow the buffer for potentially long lines.
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			continue // skip corrupt lines
		}
		s.entries = append(s.entries, e)
	}

	// Trim to max size.
	if len(s.entries) > s.maxSize {
		s.entries = s.entries[len(s.entries)-s.maxSize:]
	}

	return scanner.Err()
}

// generateID returns a hex-encoded random 16-byte identifier.
func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback: timestamp-based
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

// Ensure Store implements io.Closer.
var _ io.Closer = (*Store)(nil)
