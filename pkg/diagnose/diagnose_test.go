// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package diagnose

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectCreatesArchive(t *testing.T) {
	dir, err := os.MkdirTemp("", "providapt-diagnose-test-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	path, err := Collect(dir)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if path == "" {
		t.Fatal("expected non-empty archive path")
	}

	// Verify it's a valid tar.gz and check contents
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	expected := map[string]bool{
		"kernel.txt":    false,
		"probes.json":   false,
		"errors.log":    false,
		"resources.txt": false,
		"config.json":   false,
		"metrics.txt":   false,
		"buildinfo.txt": false,
	}
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if _, ok := expected[hdr.Name]; ok {
			expected[hdr.Name] = true
		}
	}

	for name, found := range expected {
		if !found {
			t.Errorf("missing file in archive: %s", name)
		}
	}

	// Verify archive is in the expected directory
	if filepath.Dir(path) != dir {
		t.Errorf("archive not in output dir: %s", path)
	}
}
