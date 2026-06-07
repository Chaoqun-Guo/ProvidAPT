// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cockroachdb/pebble"
)

func openTestDB(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "store")
	db, err := pebble.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("pebble.Open: %v", err)
	}
	db.Close()
	return dir
}

func put(t *testing.T, db *pebble.DB, key, value string) {
	t.Helper()
	if err := db.Set([]byte(key), []byte(value), pebble.Sync); err != nil {
		t.Fatalf("Set(%q): %v", key, err)
	}
}

func TestRunChecks_EmptyStore(t *testing.T) {
	dir := openTestDB(t)
	r, err := RunChecks(dir, true)
	if err != nil {
		t.Fatalf("RunChecks: %v", err)
	}
	if r.IssueCount != 0 {
		t.Errorf("expected 0 issues, got %d", r.IssueCount)
	}
}

func TestRunChecks_ConsistentStore(t *testing.T) {
	dir := openTestDB(t)
	db, err := pebble.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("pebble.Open: %v", err)
	}

	put(t, db, "n:p:1234", `{"id":"p:1234","type":"process"}`)
	put(t, db, "n:f:5678", `{"id":"f:5678","type":"file"}`)
	put(t, db, "e:00000000000000001000:p:1234:f:5678", `{"source":"p:1234","target":"f:5678"}`)
	put(t, db, "r:f:5678:00000000000000001000:p:1234", `{"source":"p:1234","target":"f:5678"}`)
	db.Close()

	r, err := RunChecks(dir, true)
	if err != nil {
		t.Fatalf("RunChecks: %v", err)
	}
	if r.IssueCount != 0 {
		t.Errorf("expected 0 issues, got %d: %v", r.IssueCount, r.Issues)
	}
}

func TestRunChecks_MissingReverseEdge(t *testing.T) {
	dir := openTestDB(t)
	db, err := pebble.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("pebble.Open: %v", err)
	}

	put(t, db, "n:p:1", `{"id":"p:1"}`)
	put(t, db, "n:f:2", `{"id":"f:2"}`)
	put(t, db, "e:00000000000000000001:p:1:f:2", `{"source":"p:1","target":"f:2"}`)
	// Missing reverse edge!
	db.Close()

	r, err := RunChecks(dir, true)
	if err != nil {
		t.Fatalf("RunChecks: %v", err)
	}
	if r.IssueCount == 0 {
		t.Fatal("expected issues, got 0")
	}
}

func TestRunChecks_MissingNode(t *testing.T) {
	dir := openTestDB(t)
	db, err := pebble.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("pebble.Open: %v", err)
	}

	put(t, db, "n:p:1", `{"id":"p:1"}`)
	put(t, db, "e:00000000000000000001:p:1:f:2", `{}`)
	put(t, db, "r:f:2:00000000000000000001:p:1", `{}`)
	db.Close()

	r, err := RunChecks(dir, true)
	if err != nil {
		t.Fatalf("RunChecks: %v", err)
	}
	if r.IssueCount == 0 {
		t.Fatal("expected node reference issues")
	}
}

func TestRepair(t *testing.T) {
	dir := openTestDB(t)
	db, err := pebble.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("pebble.Open: %v", err)
	}

	put(t, db, "n:p:1", `{}`)
	put(t, db, "n:f:2", `{}`)
	put(t, db, "e:00000000000000000001:p:1:f:2", `{}`)
	// Missing reverse edge — should be repairable
	db.Close()

	r, err := RunChecks(dir, true)
	if err != nil {
		t.Fatalf("RunChecks: %v", err)
	}
	if r.Repairable == 0 {
		t.Fatal("expected repairable issues")
	}

	if err := Repair(r, dir); err != nil {
		t.Fatalf("Repair: %v", err)
	}

	r2, err := RunChecks(dir, true)
	if err != nil {
		t.Fatalf("RunChecks after repair: %v", err)
	}
	if r2.IssueCount != 0 {
		t.Errorf("expected 0 issues after repair, got %d: %v", r2.IssueCount, r2.Issues)
	}
}

func TestParseEdgeKeyV1(t *testing.T) {
	tests := []struct {
		key        string
		wantSrc    string
		wantTgt    string
		wantOK     bool
	}{
		{"e:00000000000000001000:p:1234:f:5678", "p:1234", "f:5678", true},
		{"e:00000000000000001000:f:5000:8:3:p:1", "f:5000:8:3", "p:1", true},
		{"invalid", "", "", false},
		{"e:short", "", "", false},
	}
	for _, tt := range tests {
		src, tgt, _, ok := parseEdgeKeyV1(tt.key)
		if ok != tt.wantOK || (ok && (src != tt.wantSrc || tgt != tt.wantTgt)) {
			t.Errorf("parseEdgeKeyV1(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.key, src, tgt, ok, tt.wantSrc, tt.wantTgt, tt.wantOK)
		}
	}
}

func TestParseReverseKeyV1(t *testing.T) {
	tests := []struct {
		key        string
		wantSrc    string
		wantTgt    string
		wantOK     bool
	}{
		{"r:f:5678:00000000000000001000:p:1234", "p:1234", "f:5678", true},
		{"r:f:5000:8:3:00000000000000001000:p:1", "p:1", "f:5000:8:3", true},
		{"invalid", "", "", false},
		{"r:short", "", "", false},
	}
	for _, tt := range tests {
		src, tgt, _, ok := parseReverseKeyV1(tt.key)
		if ok != tt.wantOK || (ok && (src != tt.wantSrc || tgt != tt.wantTgt)) {
			t.Errorf("parseReverseKeyV1(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.key, src, tgt, ok, tt.wantSrc, tt.wantTgt, tt.wantOK)
		}
	}
}

func BenchmarkRunChecks(b *testing.B) {
	dir, err := os.MkdirTemp("", "verify-bench-*")
	if err != nil {
		b.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	storeDir := filepath.Join(dir, "store")
	db, err := pebble.Open(storeDir, &pebble.Options{})
	if err != nil {
		b.Fatalf("pebble.Open: %v", err)
	}

	// Insert 2000 nodes and 1000 edges
	for i := 0; i < 1000; i++ {
		db.Set([]byte(fmt.Sprintf("n:p:%d", i)), []byte(`{}`), pebble.Sync)
		db.Set([]byte(fmt.Sprintf("n:f:%d", i+1000)), []byte(`{}`), pebble.Sync)
	}
	for i := 0; i < 1000; i++ {
		ek := fmt.Sprintf("e:%020d:p:%d:f:%d", i+1, i, i+1000)
		rk := fmt.Sprintf("r:f:%d:%020d:p:%d", i+1000, i+1, i)
		db.Set([]byte(ek), []byte(`{}`), pebble.Sync)
		db.Set([]byte(rk), []byte(`{}`), pebble.Sync)
	}
	db.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := RunChecks(storeDir, true)
		if err != nil {
			b.Fatalf("RunChecks: %v", err)
		}
		if r.IssueCount > 0 {
			b.Fatalf("expected 0 issues, got %d", r.IssueCount)
		}
	}
}
