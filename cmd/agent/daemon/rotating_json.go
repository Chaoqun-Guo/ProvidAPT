package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	defaultAlertMaxFileBytes = 16 * 1024 * 1024
	defaultAlertRetainFiles  = 1
)

type rotatingJSONEncoder struct {
	mu           sync.Mutex
	path         string
	archiveGlob  string
	f            *os.File
	currentBytes int64
	maxFileBytes int64
	retainFiles  int
}

func newRotatingJSONEncoder(path string, maxFileBytes int64, retainFiles int) (*rotatingJSONEncoder, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create json log dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("open json log: %w", err)
	}
	var currentBytes int64
	if info, err := f.Stat(); err == nil {
		currentBytes = info.Size()
	}
	if maxFileBytes <= 0 {
		maxFileBytes = defaultAlertMaxFileBytes
	}
	if retainFiles < 0 {
		retainFiles = defaultAlertRetainFiles
	}
	ext := filepath.Ext(path)
	base := path[:len(path)-len(ext)]
	return &rotatingJSONEncoder{
		path:         path,
		archiveGlob:  base + "-*" + ext,
		f:            f,
		currentBytes: currentBytes,
		maxFileBytes: maxFileBytes,
		retainFiles:  retainFiles,
	}, nil
}

func (e *rotatingJSONEncoder) Encode(v interface{}) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}
	record := append(data, '\n')
	if err := e.rotateIfNeededLocked(int64(len(record))); err != nil {
		return err
	}
	n, err := e.f.Write(record)
	e.currentBytes += int64(n)
	return err
}

func (e *rotatingJSONEncoder) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.f == nil {
		return nil
	}
	err := e.f.Close()
	e.f = nil
	return err
}

func (e *rotatingJSONEncoder) rotateIfNeededLocked(nextBytes int64) error {
	if e.currentBytes == 0 || e.currentBytes+nextBytes <= e.maxFileBytes {
		return nil
	}
	if e.f != nil {
		if err := e.f.Close(); err != nil {
			return fmt.Errorf("close json log before rotate: %w", err)
		}
		e.f = nil
	}
	archivePath := e.archivePath()
	if err := os.Rename(e.path, archivePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("rotate json log: %w", err)
	}
	f, err := os.OpenFile(e.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open rotated json log: %w", err)
	}
	e.f = f
	e.currentBytes = 0
	e.pruneOldArchivesLocked()
	return nil
}

func (e *rotatingJSONEncoder) archivePath() string {
	ext := filepath.Ext(e.path)
	base := e.path[:len(e.path)-len(ext)]
	return fmt.Sprintf("%s-%s%s", base, time.Now().UTC().Format("20060102T150405.000000000Z"), ext)
}

func (e *rotatingJSONEncoder) pruneOldArchivesLocked() {
	if e.retainFiles <= 0 {
		matches, _ := filepath.Glob(e.archiveGlob)
		for _, path := range matches {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				log.Printf("[daemon] prune json log %s: %v", path, err)
			}
		}
		return
	}
	matches, err := filepath.Glob(e.archiveGlob)
	if err != nil || len(matches) <= e.retainFiles {
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
	for _, path := range matches[:len(matches)-e.retainFiles] {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Printf("[daemon] prune json log %s: %v", path, err)
		}
	}
}
