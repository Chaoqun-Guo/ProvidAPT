package format

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
)

// JSONWriter writes provenance events as newline-delimited JSON.
type JSONWriter struct {
	mu       sync.Mutex
	f        *os.File
	dir      string
	filename string
}

// NewJSONWriter creates a JSON lines writer.
func NewJSONWriter(dir string) (*JSONWriter, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	filename := filepath.Join(dir, fmt.Sprintf("providapt-%s.ndjson",
		time.Now().UTC().Format("20060102T150405Z")))
	f, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("create output file: %w", err)
	}

	return &JSONWriter{f: f, dir: dir, filename: filename}, nil
}

// Write marshals an event to JSON and appends it.
func (w *JSONWriter) Write(evt *collector.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}
	_, err = w.f.Write(append(data, '\n'))
	return err
}

// Close closes the underlying file.
func (w *JSONWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f != nil {
		w.f.Close()
	}
}
