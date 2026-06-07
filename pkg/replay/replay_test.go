// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package replay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

func writeTestNDJSON(t *testing.T, dir string, name string, events []collector.Event) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, evt := range events {
		if err := enc.Encode(evt); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRunEmptyDir(t *testing.T) {
	dir := t.TempDir()
	res, _ := Run(Option{InputDir: dir})
	if res.FilesRead != 0 {
		t.Errorf("expected 0 files, got %d", res.FilesRead)
	}
}

func TestRunSingleFile(t *testing.T) {
	dir := t.TempDir()
	events := []collector.Event{
		{PID: 100, Comm: "bash"},
		{PID: 101, Comm: "ls"},
	}
	writeTestNDJSON(t, dir, "providapt-20260101T000000Z.ndjson", events)

	res, graph := Run(Option{InputDir: dir})
	if res.FilesRead != 1 {
		t.Errorf("expected 1 file, got %d", res.FilesRead)
	}
	if res.EventsRead != 2 {
		t.Errorf("expected 2 events read, got %d", res.EventsRead)
	}
	if res.EventsOK != 2 {
		t.Errorf("expected 2 events OK, got %d", res.EventsOK)
	}
	if res.EventsSkip != 0 {
		t.Errorf("expected 0 events skipped, got %d", res.EventsSkip)
	}
	if graph == nil {
		t.Fatal("expected non-nil graph")
	}
}

func TestRunMaxEvents(t *testing.T) {
	dir := t.TempDir()
	events := make([]collector.Event, 10)
	for i := range events {
		events[i] = collector.Event{PID: uint32(100 + i), Comm: "proc"}
	}
	writeTestNDJSON(t, dir, "providapt-20260101T000000Z.ndjson", events)

	res, _ := Run(Option{InputDir: dir, MaxEvents: 3})
	if res.EventsRead != 3 {
		t.Errorf("expected 3 events read (max), got %d", res.EventsRead)
	}
}

func TestRunSkipInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "providapt-20260101T000000Z.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("{valid json\n")
	f.WriteString(`{"pid": 100}` + "\n")
	f.Close()

	res, _ := Run(Option{InputDir: dir})
	if res.EventsSkip != 1 {
		t.Errorf("expected 1 skipped event, got %d", res.EventsSkip)
	}
	if res.EventsOK != 1 {
		t.Errorf("expected 1 OK event, got %d", res.EventsOK)
	}
}

func TestRunMultipleFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestNDJSON(t, dir, "providapt-20260101T000000Z.ndjson",
		[]collector.Event{{PID: 1, Comm: "a"}})
	writeTestNDJSON(t, dir, "providapt-20260102T000000Z.ndjson",
		[]collector.Event{{PID: 2, Comm: "b"}})

	res, _ := Run(Option{InputDir: dir})
	if res.FilesRead != 2 {
		t.Errorf("expected 2 files, got %d", res.FilesRead)
	}
	if res.EventsRead != 2 {
		t.Errorf("expected 2 events, got %d", res.EventsRead)
	}
}

func TestRunEmptyLines(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "providapt-20260101T000000Z.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("\n\n\n")
	f.WriteString(`{"pid": 1}` + "\n")
	f.Close()

	res, _ := Run(Option{InputDir: dir})
	if res.EventsOK != 1 {
		t.Errorf("expected 1 OK event, got %d", res.EventsOK)
	}
}

func TestRunNonExistentDir(t *testing.T) {
	res, _ := Run(Option{InputDir: "/nonexistent/path"})
	if res.FilesRead != 0 {
		t.Errorf("expected 0 files for non-existent dir, got %d", res.FilesRead)
	}
}

func TestRunDurationSet(t *testing.T) {
	dir := t.TempDir()
	writeTestNDJSON(t, dir, "providapt-20260101T000000Z.ndjson",
		[]collector.Event{{PID: 1, Comm: "p"}})
	res, _ := Run(Option{InputDir: dir})
	if res.Duration <= 0 {
		t.Errorf("expected positive duration, got %v", res.Duration)
	}
}

func createEmptyFile(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestCollectFilesFiltering(t *testing.T) {
	dir := t.TempDir()
	createEmptyFile(t, filepath.Join(dir, "providapt-20260101T000000Z.ndjson"))
	createEmptyFile(t, filepath.Join(dir, "providapt-20260102T000000Z.ndjson"))
	createEmptyFile(t, filepath.Join(dir, "other-file.log"))
	createEmptyFile(t, filepath.Join(dir, "random.txt"))
	os.Mkdir(filepath.Join(dir, "subdir"), 0755)

	files := collectFiles(dir)
	if len(files) != 2 {
		t.Errorf("expected 2 matching files, got %d", len(files))
	}
}


func TestReplayFile_OpenError(t *testing.T) {
	graph := provenance.NewGraph()
	_, err := replayFile("/nonexistent/file.ndjson", graph, 0)
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}
