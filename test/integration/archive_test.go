// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/archive"
)

func TestArchiveIntegration(t *testing.T) {
	dir := t.TempDir()
	createOldFile(t, dir, "providapt-20260101T000000Z.ndjson", 72*time.Hour)

	res, err := archive.Run(archive.Option{InputDir: dir, Age: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesArchived != 1 {
		t.Errorf("expected 1 file archived, got %d", res.FilesArchived)
	}
	if res.ArchivePath == "" {
		t.Fatal("expected archive path")
	}
	if _, err := os.Stat(res.ArchivePath); os.IsNotExist(err) {
		t.Error("archive file does not exist")
	}
}

func TestArchiveIntegrationDryRun(t *testing.T) {
	dir := t.TempDir()
	createOldFile(t, dir, "providapt-20260101T000000Z.ndjson", 72*time.Hour)

	res, err := archive.Run(archive.Option{InputDir: dir, Age: 24 * time.Hour, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesArchived != 1 {
		t.Errorf("expected 1 file in dry run, got %d", res.FilesArchived)
	}
	if res.ArchivePath != "" {
		t.Errorf("expected empty archive path in dry run, got %s", res.ArchivePath)
	}
	// Original must still exist
	if _, err := os.Stat(filepath.Join(dir, "providapt-20260101T000000Z.ndjson")); os.IsNotExist(err) {
		t.Error("original file deleted during dry run")
	}
}

func TestArchiveIntegrationNoOldFiles(t *testing.T) {
	dir := t.TempDir()
	createOldFile(t, dir, "providapt-20260101T000000Z.ndjson", time.Hour)

	res, err := archive.Run(archive.Option{InputDir: dir, Age: 48 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesArchived != 0 {
		t.Errorf("expected 0 files archived (too young), got %d", res.FilesArchived)
	}
}

func createOldFile(t *testing.T, dir, name string, age time.Duration) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-age)
	os.Chtimes(path, past, past)
}
