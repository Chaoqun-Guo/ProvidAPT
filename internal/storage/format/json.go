// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
)

const (
	defaultJSONMaxFileBytes = 64 * 1024 * 1024
	defaultJSONRetainFiles  = 2
)

// JSONWriter writes provenance events as newline-delimited JSON.
type JSONWriter struct {
	mu           sync.Mutex
	f            *os.File
	dir          string
	filename     string
	currentBytes int64
	maxFileBytes int64
	retainFiles  int
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

	return &JSONWriter{
		f:            f,
		dir:          dir,
		filename:     filename,
		maxFileBytes: defaultJSONMaxFileBytes,
		retainFiles:  defaultJSONRetainFiles,
	}, nil
}

// Write marshals an event to JSON and appends it.
func (w *JSONWriter) Write(evt *collector.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	normalized := collector.NormalizeEvent(evt)
	data, err := json.Marshal(normalized)
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}
	record := append(data, '\n')
	if err := w.rotateIfNeededLocked(int64(len(record))); err != nil {
		return err
	}
	n, err := w.f.Write(record)
	w.currentBytes += int64(n)
	return err
}

// Close closes the underlying file.
func (w *JSONWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f != nil {
		if err := w.f.Close(); err != nil {
			log.Printf("[format/json] close file: %v", err)
		}
	}
}

func (w *JSONWriter) rotateIfNeededLocked(nextBytes int64) error {
	if w.maxFileBytes <= 0 || w.currentBytes == 0 || w.currentBytes+nextBytes <= w.maxFileBytes {
		return nil
	}
	if w.f != nil {
		if err := w.f.Close(); err != nil {
			return fmt.Errorf("close rotated json file: %w", err)
		}
	}
	filename := filepath.Join(w.dir, fmt.Sprintf("providapt-%s.ndjson",
		time.Now().UTC().Format("20060102T150405.000000000Z")))
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("create rotated output file: %w", err)
	}
	w.f = f
	w.filename = filename
	w.currentBytes = 0
	w.pruneOldFilesLocked()
	return nil
}

func (w *JSONWriter) pruneOldFilesLocked() {
	if w.retainFiles <= 0 {
		return
	}
	matches, err := filepath.Glob(filepath.Join(w.dir, "providapt-*.ndjson"))
	if err != nil || len(matches) <= w.retainFiles {
		return
	}
	sort.Slice(matches, func(i, j int) bool {
		iInfo, iErr := os.Stat(matches[i])
		jInfo, jErr := os.Stat(matches[j])
		if iErr == nil && jErr == nil && !iInfo.ModTime().Equal(jInfo.ModTime()) {
			return iInfo.ModTime().Before(jInfo.ModTime())
		}
		return matches[i] < matches[j]
	})
	for _, path := range matches[:len(matches)-w.retainFiles] {
		if path == w.filename {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Printf("[format/json] prune %s: %v", path, err)
		}
	}
}
