// Package snapshot provides snapshot and differential analysis for
// ProvidAPT v2.1 storage layer.
//
// Features:
//   1. RocksDB Checkpoint snapshots — every 10 minutes
//   2. Active entity table — PIDs/inodes changed in last 5 minutes
//   3. GetDiff(t1, t2) — efficient delta extraction for AI engine
package snapshot

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
)

// ═══════════════════════════════════════════════════════════════
// Snapshot manager
// ═══════════════════════════════════════════════════════════════

// SnapshotConfig controls the snapshot behaviour.
type SnapshotConfig struct {
	// SnapDir — directory for checkpoint snapshots.
	SnapDir string

	// SnapInterval — how often to create snapshots (default 10m).
	SnapInterval time.Duration

	// Retention — how many snapshots to keep (default 72 = 12h).
	Retention int

	// EnableSnapshots — master switch.
	EnableSnapshots bool
}

// DefaultSnapshotConfig returns sensible defaults.
func DefaultSnapshotConfig() *SnapshotConfig {
	return &SnapshotConfig{
		SnapDir:        "/var/lib/providapt/snapshots",
		SnapInterval:   10 * time.Minute,
		Retention:      72,
		EnableSnapshots: true,
	}
}

// SnapManager manages RocksDB checkpoint snapshots.
type SnapManager struct {
	cfg      *SnapshotConfig
	db       *pebble.DB
	mu       sync.Mutex
	snapshots []*SnapshotMeta
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// SnapshotMeta holds metadata about a checkpoint.
type SnapshotMeta struct {
	ID        string    `json:"id"`
	Path      string    `json:"path"`
	CreatedAt time.Time `json:"created_at"`
	SizeBytes int64     `json:"size_bytes"`
}

// NewSnapManager creates a snapshot manager.
func NewSnapManager(db *pebble.DB, cfg *SnapshotConfig) *SnapManager {
	if cfg == nil {
		cfg = DefaultSnapshotConfig()
	}
	os.MkdirAll(cfg.SnapDir, 0755)
	return &SnapManager{
		cfg: cfg,
		db:  db,
		stopCh: make(chan struct{}),
	}
}

// Start begins periodic snapshot creation.
func (sm *SnapManager) Start() {
	if !sm.cfg.EnableSnapshots {
		return
	}
	sm.wg.Add(1)
	go sm.loop()
	log.Printf("[snap] started (interval=%v, dir=%s)", sm.cfg.SnapInterval, sm.cfg.SnapDir)
}

func (sm *SnapManager) loop() {
	defer sm.wg.Done()
	ticker := time.NewTicker(sm.cfg.SnapInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.CreateSnapshot()
		case <-sm.stopCh:
			return
		}
	}
}

// Stop shuts down the snapshot manager.
func (sm *SnapManager) Stop() {
	close(sm.stopCh)
	sm.wg.Wait()
}

// CreateSnapshot creates a new RocksDB checkpoint snapshot.
func (sm *SnapManager) CreateSnapshot() (*SnapshotMeta, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now().UTC()
	id := fmt.Sprintf("snap-%s-%06d", now.Format("20060102T150405"), now.UnixNano()%1000000)
	snapPath := filepath.Join(sm.cfg.SnapDir, id)

	// Create RocksDB checkpoint
	if err := sm.db.Checkpoint(snapPath); err != nil {
		return nil, fmt.Errorf("checkpoint: %w", err)
	}

	// Measure size
	var size int64
	filepath.Walk(snapPath, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			size += info.Size()
		}
		return nil
	})

	meta := &SnapshotMeta{
		ID:        id,
		Path:      snapPath,
		CreatedAt: time.Now(),
		SizeBytes: size,
	}
	sm.snapshots = append(sm.snapshots, meta)

	// Cleanup old snapshots
	if len(sm.snapshots) > sm.cfg.Retention {
		old := sm.snapshots[0]
		os.RemoveAll(old.Path)
		sm.snapshots = sm.snapshots[1:]
	}

	log.Printf("[snap] created %s (%d MB, %d total)", id, size/1024/1024, len(sm.snapshots))
	return meta, nil
}

// ListSnapshots returns all available snapshots.
func (sm *SnapManager) ListSnapshots() []*SnapshotMeta {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	out := make([]*SnapshotMeta, len(sm.snapshots))
	copy(out, sm.snapshots)
	return out
}

// OpenSnapshot opens a historical snapshot as a read-only DB.
func (sm *SnapManager) OpenSnapshot(id string) (*pebble.DB, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, meta := range sm.snapshots {
		if meta.ID == id {
			return pebble.Open(meta.Path, &pebble.Options{
				ReadOnly: true,
				FS:       vfs.Default,
			})
		}
	}
	return nil, fmt.Errorf("snapshot %s not found", id)
}

// Stats returns snapshot manager statistics.
func (sm *SnapManager) Stats() map[string]interface{} {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return map[string]interface{}{
		"total_snapshots": len(sm.snapshots),
		"interval":        sm.cfg.SnapInterval.String(),
		"retention":       sm.cfg.Retention,
		"enabled":         sm.cfg.EnableSnapshots,
	}
}
