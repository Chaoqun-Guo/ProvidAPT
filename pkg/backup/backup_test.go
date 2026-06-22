// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCreateInvalidStore verifies that Create returns an error when given
// a non-existent store path.
func TestCreateInvalidStore(t *testing.T) {
	_, err := Create("/nonexistent/store/path", filepath.Join(t.TempDir(), "out.tar.gz"))
	if err == nil {
		t.Error("expected error for nonexistent store")
	}
}

// TestRestoreCorruptFile verifies that Restore rejects a corrupt archive.
func TestRestoreCorruptFile(t *testing.T) {
	corrupt := filepath.Join(t.TempDir(), "corrupt.tar.gz")
	if err := os.WriteFile(corrupt, []byte("this-is-not-a-valid-gzip-file"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Restore(corrupt, t.TempDir()); err == nil {
		t.Error("expected error for corrupt backup file")
	}
}

// TestRestoreNonexistentBackup verifies that Restore returns an error
// when the backup file does not exist.
func TestRestoreNonexistentBackup(t *testing.T) {
	err := Restore("/nonexistent/backup.tar.gz", t.TempDir())
	if err == nil {
		t.Error("expected error for nonexistent backup")
	}
}
