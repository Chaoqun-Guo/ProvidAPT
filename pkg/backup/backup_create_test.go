// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package backup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cockroachdb/pebble"
)

// TestCreate verifies that Create produces a valid backup archive with
// correct metadata.
func TestCreate(t *testing.T) {
	storeDir := t.TempDir()
	db, err := pebble.Open(storeDir, &pebble.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Set([]byte("test-key"), []byte("test-value"), pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if err := db.Set([]byte("another-key"), []byte("another-value"), pebble.Sync); err != nil {
		t.Fatal(err)
	}
	db.Close()

	backupPath := filepath.Join(t.TempDir(), "backup.tar.gz")
	meta, err := Create(storeDir, backupPath)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if meta.SizeBytes <= 0 {
		t.Errorf("expected positive backup size, got %d", meta.SizeBytes)
	}
	if meta.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
	if meta.Path != backupPath {
		t.Errorf("got Path=%q, want %q", meta.Path, backupPath)
	}
	if meta.StorePath != storeDir {
		t.Errorf("got StorePath=%q, want %q", meta.StorePath, storeDir)
	}

	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= 0 {
		t.Errorf("expected positive backup file on disk, got %d", info.Size())
	}
}

// TestRestore verifies round-trip: create backup, delete original store,
// restore, and confirm data is intact.
func TestRestore(t *testing.T) {
	storeDir := t.TempDir()
	db, err := pebble.Open(storeDir, &pebble.Options{})
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]string{
		"alpha": "1",
		"beta":  "2",
		"gamma": "3",
	}
	for k, v := range entries {
		if err := db.Set([]byte(k), []byte(v), pebble.Sync); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	backupPath := filepath.Join(t.TempDir(), "backup.tar.gz")
	if _, err := Create(storeDir, backupPath); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Remove original store to prove we rely solely on the backup
	os.RemoveAll(storeDir)

	restoreDir := t.TempDir()
	if err := Restore(backupPath, restoreDir); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Open restored store and verify data
	restoredDB, err := pebble.Open(restoreDir, &pebble.Options{
		ReadOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer restoredDB.Close()

	for k, v := range entries {
		val, closer, err := restoredDB.Get([]byte(k))
		if err != nil {
			t.Errorf("Get(%q): %v", k, err)
			continue
		}
		if string(val) != v {
			t.Errorf("Get(%q) = %q, want %q", k, string(val), v)
		}
		closer.Close()
	}
}

// TestCreateEmptyStore verifies that creating a backup from an empty
// PebbleDB store succeeds and produces a valid archive.
func TestCreateEmptyStore(t *testing.T) {
	storeDir := t.TempDir()
	db, err := pebble.Open(storeDir, &pebble.Options{})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	backupPath := filepath.Join(t.TempDir(), "backup.tar.gz")
	meta, err := Create(storeDir, backupPath)
	if err != nil {
		t.Fatalf("Create on empty store: %v", err)
	}
	if meta.SizeBytes < 0 {
		t.Errorf("expected non-negative backup size, got %d", meta.SizeBytes)
	}
}

// TestCreateLargeData verifies that Create handles a store with a
// reasonably large amount of data without error.
func TestCreateLargeData(t *testing.T) {
	storeDir := t.TempDir()
	db, err := pebble.Open(storeDir, &pebble.Options{})
	if err != nil {
		t.Fatal(err)
	}
	// Write 1000 entries
	for i := 0; i < 1000; i++ {
		k := []byte{byte(i >> 8), byte(i & 0xff)}
		v := make([]byte, 128)
		for j := range v {
			v[j] = byte(i + j)
		}
		if err := db.Set(k, v, pebble.Sync); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	backupPath := filepath.Join(t.TempDir(), "backup.tar.gz")
	meta, err := Create(storeDir, backupPath)
	if err != nil {
		t.Fatalf("Create with 1000 entries: %v", err)
	}
	if meta.SizeBytes <= 0 {
		t.Errorf("expected positive backup size, got %d", meta.SizeBytes)
	}
}
