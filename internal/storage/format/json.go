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
	defaultJSONMaxFileBytes = 16 * 1024 * 1024
	defaultJSONRetainFiles  = 1
)

// JSONWriterOptions controls NDJSON rotation and retention.
type JSONWriterOptions struct {
	MaxFileBytes int64
	RetainFiles  int
	RetainBytes  int64
}

// JSONWriter writes provenance events as newline-delimited JSON.
type JSONWriter struct {
	mu           sync.Mutex
	f            *os.File
	dir          string
	filename     string
	currentBytes int64
	maxFileBytes int64
	retainFiles  int
	retainBytes  int64
}

// NewJSONWriter creates a JSON lines writer.
func NewJSONWriter(dir string) (*JSONWriter, error) {
	return NewJSONWriterWithOptions(dir, JSONWriterOptions{})
}

// NewJSONWriterWithOptions creates a JSON lines writer with rotation options.
func NewJSONWriterWithOptions(dir string, opts JSONWriterOptions) (*JSONWriter, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	filename := filepath.Join(dir, fmt.Sprintf("providapt-%s.ndjson",
		time.Now().UTC().Format("20060102T150405Z")))
	f, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("create output file: %w", err)
	}
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = defaultJSONMaxFileBytes
	}
	if opts.RetainFiles < 0 {
		opts.RetainFiles = defaultJSONRetainFiles
	}

	return &JSONWriter{
		f:            f,
		dir:          dir,
		filename:     filename,
		maxFileBytes: opts.MaxFileBytes,
		retainFiles:  opts.RetainFiles,
		retainBytes:  opts.RetainBytes,
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
	if w.retainBytes > 0 {
		w.pruneOldFilesBySizeLocked()
	}
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
	if w.retainBytes > 0 {
		w.pruneOldFilesBySizeLocked()
		return
	}
	if w.retainFiles <= 0 {
		matches, _ := filepath.Glob(filepath.Join(w.dir, "providapt-*.ndjson"))
		for _, path := range matches {
			if path == w.filename {
				continue
			}
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				log.Printf("[format/json] prune %s by file-count retention failed: %v", path, err)
			}
		}
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
			log.Printf("[format/json] prune %s by file-count retention failed: %v", path, err)
		} else {
			log.Printf("[format/json] pruned %s by file-count retention retain_files=%d", path, w.retainFiles)
		}
	}
}

func (w *JSONWriter) pruneOldFilesBySizeLocked() {
	matches, err := filepath.Glob(filepath.Join(w.dir, "providapt-*.ndjson"))
	if err != nil || len(matches) == 0 {
		return
	}
	sort.Slice(matches, func(i, j int) bool {
		iInfo, iErr := os.Stat(matches[i])
		jInfo, jErr := os.Stat(matches[j])
		if iErr == nil && jErr == nil && !iInfo.ModTime().Equal(jInfo.ModTime()) {
			return iInfo.ModTime().After(jInfo.ModTime())
		}
		return matches[i] > matches[j]
	})
	var total int64
	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		total += info.Size()
	}
	if total <= w.retainBytes {
		return
	}
	for i := len(matches) - 1; i >= 0 && total > w.retainBytes; i-- {
		path := matches[i]
		if path == w.filename {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Printf("[format/json] prune %s by byte-budget retention failed: %v", path, err)
			continue
		}
		total -= info.Size()
		log.Printf("[format/json] pruned %s by byte-budget retention retained_bytes=%d retain_max_bytes=%d", path, total, w.retainBytes)
	}
}
