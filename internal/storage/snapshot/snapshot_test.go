package snapshot

import (
	"os"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
)

func openDB(t *testing.T) *pebble.DB {
	t.Helper()
	dir, err := os.MkdirTemp("", "providapt-snap-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	db, err := pebble.Open(dir+"/pebble", &pebble.Options{})
	if err != nil {
		t.Fatalf("pebble: %v", err)
	}
	return db
}

// ─── Snapshot manager tests ─────────────────────────────────

func TestNewSnapManager(t *testing.T) {
	db := openDB(t)
	sm := NewSnapManager(db, nil)
	if sm == nil {
		t.Fatal("NewSnapManager returned nil")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultSnapshotConfig()
	if cfg.SnapInterval != 10*time.Minute {
		t.Errorf("interval = %v", cfg.SnapInterval)
	}
	if cfg.Retention != 72 {
		t.Errorf("retention = %d", cfg.Retention)
	}
	if !cfg.EnableSnapshots {
		t.Error("snapshots should be enabled")
	}
}

func TestCreateSnapshot(t *testing.T) {
	db := openDB(t)
	cfg := DefaultSnapshotConfig()
	cfg.SnapDir = t.TempDir()
	sm := NewSnapManager(db, cfg)

	meta, err := sm.CreateSnapshot()
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if meta.ID == "" {
		t.Error("empty snapshot ID")
	}
	if _, err := os.Stat(meta.Path); os.IsNotExist(err) {
		t.Error("snapshot directory not created")
	}
	t.Logf("Snapshot: %s (%d bytes)", meta.ID, meta.SizeBytes)
}

func TestListSnapshots(t *testing.T) {
	db := openDB(t)
	cfg := DefaultSnapshotConfig()
	cfg.SnapDir = t.TempDir()
	sm := NewSnapManager(db, cfg)

	sm.CreateSnapshot()
	sm.CreateSnapshot()

	snaps := sm.ListSnapshots()
	if len(snaps) != 2 {
		t.Errorf("snapshots = %d", len(snaps))
	}
}

func TestRetention(t *testing.T) {
	db := openDB(t)
	cfg := DefaultSnapshotConfig()
	cfg.SnapDir = t.TempDir()
	cfg.Retention = 2
	sm := NewSnapManager(db, cfg)

	for i := 0; i < 5; i++ {
		sm.CreateSnapshot()
	}

	snaps := sm.ListSnapshots()
	if len(snaps) > 2 {
		t.Errorf("retention failed: %d snapshots", len(snaps))
	}
}

func TestStartStop(t *testing.T) {
	db := openDB(t)
	cfg := DefaultSnapshotConfig()
	cfg.SnapDir = t.TempDir()
	sm := NewSnapManager(db, cfg)

	sm.Start()
	time.Sleep(50 * time.Millisecond)
	sm.Stop()
}

func TestStats(t *testing.T) {
	db := openDB(t)
	cfg := DefaultSnapshotConfig()
	cfg.SnapDir = t.TempDir()
	sm := NewSnapManager(db, cfg)
	sm.CreateSnapshot()

	stats := sm.Stats()
	if stats["total_snapshots"].(int) != 1 {
		t.Errorf("snapshots = %d", stats["total_snapshots"])
	}
}

// ─── Active table tests ─────────────────────────────────────

func TestNewActiveTable(t *testing.T) {
	at := NewActiveTable(5 * time.Minute)
	if at == nil {
		t.Fatal("NewActiveTable returned nil")
	}
}

func TestTouch(t *testing.T) {
	at := NewActiveTable(time.Hour)
	at.Touch("p:100", EntityProcess)
	at.Touch("f:5000", EntityFile)

	active := at.GetActive()
	if len(active) != 2 {
		t.Errorf("active = %d", len(active))
	}
}

func TestGetActiveIDs(t *testing.T) {
	at := NewActiveTable(time.Hour)
	at.Touch("p:100", EntityProcess)
	at.Touch("p:200", EntityProcess)

	ids := at.GetActiveIDs()
	if len(ids) != 2 {
		t.Errorf("ids = %d", len(ids))
	}
}

func TestCleanExpired(t *testing.T) {
	at := NewActiveTable(time.Nanosecond)
	at.Touch("p:100", EntityProcess)
	time.Sleep(10 * time.Millisecond)

	n := at.CleanExpired()
	if n != 1 {
		t.Errorf("cleaned = %d", n)
	}
}

func TestActiveTableStats(t *testing.T) {
	at := NewActiveTable(time.Hour)
	at.Touch("p:100", EntityProcess)
	at.Touch("f:500", EntityFile)

	stats := at.Stats()
	if stats["total_active"].(int) != 2 {
		t.Errorf("active = %d", stats["total_active"])
	}
	if stats["processes"].(int) != 1 {
		t.Errorf("processes = %d", stats["processes"])
	}
}

func TestSummary(t *testing.T) {
	at := NewActiveTable(5 * time.Minute)
	at.Touch("p:100", EntityProcess)
	s := at.Summary()
	if len(s) == 0 {
		t.Error("empty summary")
	}
	t.Logf("Summary: %s", s)
}

// ─── Diff engine tests ──────────────────────────────────────

func TestNewDiffEngine(t *testing.T) {
	de := NewDiffEngine(nil, nil)
	if de == nil {
		t.Fatal("NewDiffEngine returned nil")
	}
}

func TestGetDiffWithActive(t *testing.T) {
	db := openDB(t)
	cfg := DefaultSnapshotConfig()
	cfg.SnapDir = t.TempDir()
	sm := NewSnapManager(db, cfg)
	at := NewActiveTable(time.Hour)

	at.Touch("p:100", EntityProcess)
	at.Touch("f:5000", EntityFile)

	de := NewDiffEngine(at, sm)
	result, err := de.GetDiff(time.Now().Add(-1*time.Hour), time.Now())
	if err != nil {
		t.Fatalf("GetDiff: %v", err)
	}
	if result.TotalNodes == 0 {
		t.Error("expected at least 1 node in diff")
	}
	t.Logf("Diff: %s", result.Summary())
}

func TestGetActiveDiff(t *testing.T) {
	at := NewActiveTable(time.Hour)
	at.Touch("p:100", EntityProcess)
	at.Touch("n:5.6.7.8", EntityNetwork)

	de := NewDiffEngine(at, nil)
	result := de.GetActiveDiff()
	if result.TotalNodes != 2 {
		t.Errorf("nodes = %d", result.TotalNodes)
	}
	t.Logf("Active diff: %s", result.Summary())
}

func TestDiffDuration(t *testing.T) {
	at := NewActiveTable(time.Hour)
	de := NewDiffEngine(at, nil)
	result := de.GetActiveDiff()
	if result.Duration == "" {
		t.Error("no duration")
	}
}

// ─── Integration test ───────────────────────────────────────

func TestSnapshotIntegration(t *testing.T) {
	t.Log("=== Snapshot & Diff Integration ===")

	// 1. Create database and snapshot manager
	db := openDB(t)
	cfg := DefaultSnapshotConfig()
	cfg.SnapDir = t.TempDir()
	sm := NewSnapManager(db, cfg)

	// 2. Create a few snapshots
	for i := 0; i < 3; i++ {
		_, err := sm.CreateSnapshot()
		if err != nil {
			t.Fatalf("snapshot %d: %v", i, err)
		}
	}
	t.Logf("Snapshots: %d", len(sm.ListSnapshots()))
	for _, s := range sm.ListSnapshots() {
		t.Logf("  %s (%d bytes)", s.ID, s.SizeBytes)
	}

	// 3. Active entity tracking
	at := NewActiveTable(time.Hour)
	at.Touch("p:100", EntityProcess)
	at.Touch("p:101", EntityProcess)
	at.Touch("f:5000", EntityFile)
	at.Touch("n:5.6.7.8", EntityNetwork)
	t.Logf("Active: %s", at.Summary())

	// 4. Diff computation
	de := NewDiffEngine(at, sm)
	result := de.GetActiveDiff()
	t.Logf("Diff: %s", result.Summary())
	for _, n := range result.NewNodes {
		t.Logf("  %s [%s]", n.ID, n.Type)
	}

	// 5. Verify active entity IDs
	ids := at.GetActiveIDs()
	t.Logf("Active IDs: %v", ids)
	if len(ids) != 4 {
		t.Errorf("expected 4 active IDs, got %d", len(ids))
	}

	t.Log("Snapshot integration OK")
}
