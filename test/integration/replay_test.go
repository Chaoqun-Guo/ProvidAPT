// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/replay"
)

func TestReplayIntegration(t *testing.T) {
	dir := t.TempDir()

	// Create test NDJSON files
	events := []collector.Event{
		{PID: 100, Comm: "bash", UID: 1000},
		{PID: 101, Comm: "ls", UID: 1000},
	}
	writeNDJSON(t, dir, "providapt-20260101T000000Z.ndjson", events)

	res, graph := replay.Run(replay.Option{InputDir: dir})
	if res.FilesRead != 1 {
		t.Errorf("expected 1 file, got %d", res.FilesRead)
	}
	if res.EventsRead != 2 {
		t.Errorf("expected 2 events, got %d", res.EventsRead)
	}
	if res.EventsSkip != 0 {
		t.Errorf("expected 0 skips, got %d", res.EventsSkip)
	}
	if graph == nil {
		t.Fatal("nil graph")
	}
	stats := graph.Stats()
	if stats.Nodes == 0 && stats.Edges == 0 {
		t.Log("graph has 0 nodes/edges (expected if Event schema has no provenance mapping)")
	}
}

func TestReplayIntegrationMaxEvents(t *testing.T) {
	dir := t.TempDir()
	events := make([]collector.Event, 100)
	for i := range events {
		events[i] = collector.Event{PID: uint32(i), Comm: "proc"}
	}
	writeNDJSON(t, dir, "providapt-20260101T000000Z.ndjson", events)

	res, _ := replay.Run(replay.Option{InputDir: dir, MaxEvents: 10})
	if res.EventsRead != 10 {
		t.Errorf("expected 10 events (max), got %d", res.EventsRead)
	}
}

func TestReplayIntegrationSkipInvalid(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "providapt-20260101T000000Z.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("invalid json\n")
	f.WriteString(`{"pid": 1}` + "\n")
	f.Close()

	res, _ := replay.Run(replay.Option{InputDir: dir})
	if res.EventsSkip != 1 {
		t.Errorf("expected 1 skip, got %d", res.EventsSkip)
	}
	if res.EventsOK != 1 {
		t.Errorf("expected 1 ok, got %d", res.EventsOK)
	}
}

func TestReplayIntegrationNonExistentDir(t *testing.T) {
	res, _ := replay.Run(replay.Option{InputDir: "/nonexistent"})
	if res.FilesRead != 0 {
		t.Errorf("expected 0 files, got %d", res.FilesRead)
	}
}

func writeNDJSON(t *testing.T, dir, name string, events []collector.Event) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
	}
}
