package purge

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
)

func setupTestDB(t *testing.T) string {
	dir, err := os.MkdirTemp("", "providapt-purge-test-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	db, err := pebble.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("pebble open: %v", err)
	}
	defer db.Close()

	// Insert common test data
	insertTestEdge(t, db, 100, "p:1", "f:1")
	insertTestEdge(t, db, 200, "p:1", "f:2")
	insertTestEdge(t, db, 300, "p:2", "n:1")
	insertTestNode(t, db, "p:1")
	insertTestNode(t, db, "f:1")
	insertTestNode(t, db, "f:2")
	insertTestNode(t, db, "p:2")
	insertTestNode(t, db, "n:1")

	return dir
}

func insertTestEdge(t *testing.T, db *pebble.DB, ts uint64, src, tgt string) {
	key := fmt.Sprintf("e:%020d:%s:%s", ts, src, tgt)
	if err := db.Set([]byte(key), []byte(`{}`), pebble.Sync); err != nil {
		t.Fatalf("set edge: %v", err)
	}
	revKey := fmt.Sprintf("r:%s:%020d:%s", tgt, ts, src)
	if err := db.Set([]byte(revKey), []byte(`{}`), pebble.Sync); err != nil {
		t.Fatalf("set rev edge: %v", err)
	}
}

func insertTestNode(t *testing.T, db *pebble.DB, id string) {
	key := "n:" + id
	if err := db.Set([]byte(key), []byte(`{}`), pebble.Sync); err != nil {
		t.Fatalf("set node: %v", err)
	}
}

func countKeys(db *pebble.DB, prefix string) int {
	iter, err := db.NewIter(nil)
	if err != nil {
		return 0
	}
	defer iter.Close()
	count := 0
	p := []byte(prefix)
	for iter.SeekGE(p); iter.Valid(); iter.Next() {
		k := string(iter.Key())
		if !startsWith(k, prefix) {
			break
		}
		count++
	}
	return count
}

func startsWith(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return s[:len(prefix)] == prefix
}

func TestPurgeByTime(t *testing.T) {
	dir := setupTestDB(t)

	cutoff := time.Unix(0, 250)

	cfg := &PurgeConfig{
		Mode:      PurgeByTime,
		StorePath: dir,
		Cutoff:    cutoff,
		DryRun:    false,
	}

	report, err := Execute(cfg)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if report.EdgesDeleted != 2 {
		t.Errorf("expected 2 edges deleted, got %d", report.EdgesDeleted)
	}
	if report.ReverseEdgesDeleted != 2 {
		t.Errorf("expected 2 reverse edges deleted, got %d", report.ReverseEdgesDeleted)
	}

	// Re-open and verify remaining data
	db, err := pebble.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db.Close()

	remaining := countKeys(db, "e:")
	if remaining != 1 {
		t.Fatalf("expected 1 remaining edge, got %d", remaining)
	}
}

func TestPurgeDryRun(t *testing.T) {
	dir := setupTestDB(t)

	cfg := &PurgeConfig{
		Mode:      PurgeByTime,
		StorePath: dir,
		Cutoff:    time.Unix(0, 150),
		DryRun:    true,
	}

	report, err := Execute(cfg)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if report.EdgesDeleted != 1 {
		t.Errorf("expected 1 edge reported, got %d", report.EdgesDeleted)
	}
	if !report.DryRun {
		t.Error("expected DryRun=true in report")
	}

	// Verify no actual deletion happened
	db, err := pebble.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db.Close()

	remaining := countKeys(db, "e:")
	if remaining != 3 {
		t.Errorf("expected 3 edges still present after dry-run, got %d", remaining)
	}
}

func TestPurgeCompliance(t *testing.T) {
	dir := setupTestDB(t)

	cfg := &PurgeConfig{
		Mode:      PurgeCompliance,
		StorePath: dir,
		DryRun:    false,
	}

	report, err := Execute(cfg)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if report.TotalKeysDeleted < 4 {
		t.Errorf("expected at least 4 keys deleted in compliance mode, got %d", report.TotalKeysDeleted)
	}

	// Verify store is empty
	db, err := pebble.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db.Close()

	iter, err := db.NewIter(nil)
	if err != nil {
		t.Fatalf("iter: %v", err)
	}
	defer iter.Close()

	count := 0
	for iter.First(); iter.Valid(); iter.Next() {
		count++
	}
	if count != 0 {
		t.Errorf("expected 0 remaining keys after compliance wipe, got %d", count)
	}
}

func TestPurgeByCapacity(t *testing.T) {
	dir := setupTestDB(t)

	// Open to get current disk size
	db, err := pebble.Open(dir, &pebble.Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	currentSize := db.Metrics().DiskSpaceUsage()
	db.Close()

	cfg := &PurgeConfig{
		Mode:      PurgeByCapacity,
		StorePath: dir,
		MaxBytes:  int64(currentSize) - 1, // delete until at least 1 byte freed
		DryRun:    false,
	}

	report, err := Execute(cfg)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if report.EdgesDeleted < 1 {
		t.Errorf("expected at least 1 edge deleted, got %d", report.EdgesDeleted)
	}
}
