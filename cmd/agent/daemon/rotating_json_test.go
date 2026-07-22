package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatingJSONEncoderRotatesAlertsAndKeepsActivePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alerts.ndjson")
	enc, err := newRotatingJSONEncoder(path, 180, 1)
	if err != nil {
		t.Fatalf("newRotatingJSONEncoder: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := enc.Encode(map[string]string{
			"id":      strings.Repeat("a", 40),
			"message": strings.Repeat("b", 80),
		}); err != nil {
			t.Fatalf("Encode %d: %v", i, err)
		}
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("active alerts.ndjson missing: %v", err)
	}
	archives, err := filepath.Glob(filepath.Join(dir, "alerts-*.ndjson"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(archives) != 1 {
		t.Fatalf("archives = %d, want 1: %#v", len(archives), archives)
	}
}
