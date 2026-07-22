// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package replay reads stored NDJSON event logs and re-ingests them
// into a provenance graph for post-hoc analysis or recovery.
package replay

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// Result summarizes a replay operation.
type Result struct {
	Dir        string        `json:"dir"`
	FilesRead  int           `json:"files_read"`
	EventsRead int           `json:"events_read"`
	EventsOK   int           `json:"events_ok"`
	EventsSkip int           `json:"events_skip"`
	Nodes      int           `json:"nodes"`
	Edges      int           `json:"edges"`
	Duration   time.Duration `json:"duration"`
	Error      string        `json:"error,omitempty"`
}

// Option configures replay behavior.
type Option struct {
	MaxEvents int    // stop after this many events (0 = unlimited)
	InputDir  string // directory containing NDJSON files
}

// Run replays events from NDJSON files into a fresh provenance graph.
func Run(opt Option) (*Result, *provenance.Graph) {
	start := time.Now()
	res := &Result{Dir: opt.InputDir}

	graph := provenance.NewGraph()

	files := collectFiles(opt.InputDir)
	res.FilesRead = len(files)

	for _, path := range files {
		count, err := replayFile(path, graph, opt.MaxEvents-res.EventsRead)
		res.EventsRead += count.EventsTotal
		res.EventsOK += count.EventsOK
		res.EventsSkip += count.EventsSkip
		if err != nil {
			res.Error = err.Error()
			break
		}
		if opt.MaxEvents > 0 && res.EventsRead >= opt.MaxEvents {
			break
		}
	}

	stats := graph.Stats()
	res.Nodes = stats.Nodes
	res.Edges = stats.Edges
	res.Duration = time.Since(start)

	return res, graph
}

type fileCount struct {
	EventsTotal int
	EventsOK    int
	EventsSkip  int
}

func replayFile(path string, graph *provenance.Graph, max int) (fileCount, error) {
	f, err := os.Open(path)
	if err != nil {
		return fileCount{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var count fileCount
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		evt, err := collector.ParseStoredEventJSON(line)
		if err != nil {
			count.EventsSkip++
			continue
		}
		count.EventsOK++
		count.EventsTotal++

		graph.AddEvent(evt)

		if max > 0 && count.EventsTotal >= max {
			break
		}
	}

	return count, scanner.Err()
}

// collectFiles finds providapt-*.ndjson files in dir, sorted by name.
func collectFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), "providapt-") && strings.HasSuffix(e.Name(), ".ndjson") {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}

	// Sort by name (which is timestamp-ordered)
	sort.Strings(files)
	return files
}
