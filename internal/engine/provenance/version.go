package provenance

import (
	"fmt"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
)

// ═══════════════════════════════════════════════════════════════
// Entity versioning
//
// When a file is written (EV_FILE_CREATE / EV_FILE_MODIFY), the
// previous version of that file is preserved and a new version node
// is created.  A wasDerivedFrom edge links the new version to the
// old one, forming a version chain:
//
//   f:12345:8:3#v1 ──wasDerivedFrom──▶ f:12345:8:3#v2
//   (initial state)                      (after first write)
//
// The write edge (wasGeneratedBy) points to the NEW version.
// Read operations (used) also target the latest version.
// ═══════════════════════════════════════════════════════════════

// VersionTracker manages version numbers for file entities.
type VersionTracker struct {
	mu        sync.Mutex
	latest    map[string]int64  // baseID → current version number
	created   map[string]bool   // versioned node ID → exists
}

// NewVersionTracker creates a version tracker.
func NewVersionTracker() *VersionTracker {
	return &VersionTracker{
		latest:  make(map[string]int64),
		created: make(map[string]bool),
	}
}

// baseKey computes the version-tracking key from a file base ID.
// Strips any existing version suffix.
func baseKey(fileID string) string {
	return fileID
}

// InitVersion ensures a file has version 1.  Called the first time
// a file is seen (read or write).
func (vt *VersionTracker) InitVersion(baseID string) string {
	vt.mu.Lock()
	defer vt.mu.Unlock()
	if _, ok := vt.latest[baseID]; !ok {
		vt.latest[baseID] = 1
	}
	return vt.versionedID(baseID, vt.latest[baseID])
}

// NextVersion creates a new version for the given base ID.
// Returns the NEW versioned node ID.
func (vt *VersionTracker) NextVersion(baseID string) (prevID, newID string) {
	vt.mu.Lock()
	defer vt.mu.Unlock()

	prev := vt.latest[baseID]
	if prev == 0 {
		prev = 1
		vt.latest[baseID] = 1
	}
	prevID = vt.versionedID(baseID, prev)

	vt.latest[baseID]++
	newID = vt.versionedID(baseID, vt.latest[baseID])
	vt.created[newID] = true
	return
}

// LatestVersion returns the current latest versioned ID for a base ID.
func (vt *VersionTracker) LatestVersion(baseID string) string {
	vt.mu.Lock()
	defer vt.mu.Unlock()
	ver := vt.latest[baseID]
	if ver == 0 {
		ver = 1
	}
	return vt.versionedID(baseID, ver)
}

// IsVersioned checks whether a node ID is a versioned entity.
func (vt *VersionTracker) IsVersioned(id string) bool {
	vt.mu.Lock()
	defer vt.mu.Unlock()
	return vt.created[id]
}

// versionedID builds a versioned node ID from a base and version number.
func (vt *VersionTracker) versionedID(baseID string, version int64) string {
	return fmt.Sprintf("%s#v%d", baseID, version)
}

// StripVersion strips the version suffix from a node ID.
func StripVersion(id string) string {
	for i := len(id) - 1; i >= 0; i-- {
		if id[i] == '#' {
			return id[:i]
		}
	}
	return id
}

// ── Integration in the Graph ────────────────────────────────

// getOrCreateBaseFileNode returns the INITIAL (version 1) node for a file,
// creating it if needed.  Used by read operations to always point to
// the first known version.
func (g *Graph) getOrCreateBaseFileNode(evt *collector.Event, ts time.Time) (*Node, string) {
	baseID := g.fileID(evt)
	versionedID := g.versionTracker.InitVersion(baseID)

	n := g.getOrCreateNode(versionedID, ProvEntity, SubFile, evt.Pathname, ts)
	n.upsertAttr("inode", evt.Inode)
	n.upsertAttr("mode", fmt.Sprintf("%o", evt.Mode))
	n.touch(ts)
	return n, versionedID
}

// createNextFileVersion creates a NEW version node for a file write.
// Returns the new versioned node ID.
func (g *Graph) createNextFileVersion(evt *collector.Event, ts time.Time) (string, string) {
	baseID := g.fileID(evt)
	prevID, newID := g.versionTracker.NextVersion(baseID)

	prevNode := g.getOrCreateNode(prevID, ProvEntity, SubFile, evt.Pathname, ts)
	prevNode.touch(ts)

	n := newNode(newID, ProvEntity, SubFile, evt.Pathname, ts)
	n.upsertAttr("inode", evt.Inode)
	n.upsertAttr("mode", fmt.Sprintf("%o", evt.Mode))
	n.upsertAttr("version", g.versionTracker.LatestVersion(baseID))
	g.nodes[newID] = n

	// Link: new ──wasDerivedFrom──▶ old
	if prevID != newID {
		g.addEdge(ProvWasDerivedFrom, newID, prevID, ts, nil)
	}
	return prevID, newID
}
