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
type Store struct {
	mu       sync.Mutex
	f        *os.File
	path     string
	entries  []Entry
	maxSize  int
}

// New creates or opens an audit store at <dir>/audit.ndjson.
// The directory is created if it does not exist. Existing audit
// entries are replayed into the in-memory buffer on startup.
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
		f:       f,
		path:    path,
		entries: make([]Entry, 0, 1024),
		maxSize: 10000,
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
