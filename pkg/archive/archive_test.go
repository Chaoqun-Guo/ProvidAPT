// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTestNDJSON(t *testing.T, dir, name string, age time.Duration) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	// Set mtime to now - age
	past := time.Now().Add(-age)
	os.Chtimes(path, past, past)
}

func TestRunEmptyDir(t *testing.T) {
	dir := t.TempDir()
	res, err := Run(Option{InputDir: dir, Age: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesArchived != 0 {
		t.Errorf("expected 0 files archived, got %d", res.FilesArchived)
	}
}

func TestRunDryRun(t *testing.T) {
	dir := t.TempDir()
	writeTestNDJSON(t, dir, "providapt-20260101T000000Z.ndjson", 48*time.Hour)

	res, err := Run(Option{InputDir: dir, Age: time.Hour, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesArchived != 1 {
		t.Errorf("expected 1 file in dry run, got %d", res.FilesArchived)
	}
	if res.ArchivePath != "" {
		t.Errorf("expected no archive path in dry run, got %s", res.ArchivePath)
	}
	// Verify original file still exists
	if _, err := os.Stat(filepath.Join(dir, "providapt-20260101T000000Z.ndjson")); os.IsNotExist(err) {
		t.Error("original file should still exist after dry run")
	}
}

func TestRunArchiveAndRemove(t *testing.T) {
	dir := t.TempDir()
	writeTestNDJSON(t, dir, "providapt-20260101T000000Z.ndjson", 48*time.Hour)

	res, err := Run(Option{InputDir: dir, Age: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesArchived != 1 {
		t.Errorf("expected 1 file archived, got %d", res.FilesArchived)
	}
	if res.ArchivePath == "" {
		t.Fatal("expected non-empty archive path")
	}
	if res.FilesSkipped != 0 {
		t.Errorf("expected 0 files skipped, got %d", res.FilesSkipped)
	}
	// Verify archive exists
	if _, err := os.Stat(res.ArchivePath); os.IsNotExist(err) {
		t.Error("archive file should exist")
	}
	// Verify original removed
	if _, err := os.Stat(filepath.Join(dir, "providapt-20260101T000000Z.ndjson")); !os.IsNotExist(err) {
		t.Error("original file should be removed after archive")
	}
}

func TestRunOnlyOldFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestNDJSON(t, dir, "providapt-old.ndjson", 72*time.Hour)
	writeTestNDJSON(t, dir, "providapt-recent.ndjson", time.Hour)

	res, err := Run(Option{InputDir: dir, Age: 48 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesArchived != 1 {
		t.Errorf("expected 1 old file archived, got %d", res.FilesArchived)
	}
}

func TestRunOutputDir(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	writeTestNDJSON(t, input, "providapt-20260101T000000Z.ndjson", 48*time.Hour)

	res, err := Run(Option{InputDir: input, OutputDir: output, Age: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if res.ArchivePath == "" {
		t.Fatal("expected archive path")
	}
	if !strings.HasPrefix(res.ArchivePath, output) {
		t.Errorf("expected archive in output dir %s, got %s", output, res.ArchivePath)
	}
}

func TestRunDefaultAge(t *testing.T) {
	dir := t.TempDir()
	res, err := Run(Option{InputDir: dir}) // no age set, defaults to 24h
	if err != nil {
		t.Fatal(err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestRunBytesCounted(t *testing.T) {
	dir := t.TempDir()
	writeTestNDJSON(t, dir, "providapt-20260101T000000Z.ndjson", 48*time.Hour)

	res, err := Run(Option{InputDir: dir, Age: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if res.BytesBefore <= 0 {
		t.Errorf("expected positive bytes_before, got %d", res.BytesBefore)
	}
}

func TestCreateTarGz(t *testing.T) {
	dir := t.TempDir()
	files := []string{
		filepath.Join(dir, "a.ndjson"),
		filepath.Join(dir, "b.ndjson"),
	}
	os.WriteFile(files[0], []byte("data1\n"), 0644)
	os.WriteFile(files[1], []byte("data2\n"), 0644)

	archivePath := filepath.Join(dir, "test.tar.gz")
	if err := createTarGz(archivePath, files); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(archivePath); os.IsNotExist(err) {
		t.Error("archive file should exist")
	}
}

func TestCollectOldFilesFiltering(t *testing.T) {
	dir := t.TempDir()
	writeTestNDJSON(t, dir, "providapt-old.ndjson", 72*time.Hour)
	writeTestNDJSON(t, dir, "other-file.log", 72*time.Hour)
	os.WriteFile(filepath.Join(dir, "providapt-nonjson.txt"), []byte{}, 0644)

	cutoff := time.Now().Add(-48 * time.Hour)
	files, err := collectOldFiles(dir, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 old NDJSON file, got %d", len(files))
	}
}
