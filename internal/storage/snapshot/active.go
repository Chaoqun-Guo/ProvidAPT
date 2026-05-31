package snapshot

import (
	"fmt"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Active entity table
// ═══════════════════════════════════════════════════════════════

// EntityType indicates what kind of entity changed.
type EntityType int

const (
	EntityProcess EntityType = iota
	EntityFile
	EntityNetwork
)

func (et EntityType) String() string {
	switch et {
	case EntityProcess:
		return "process"
	case EntityFile:
		return "file"
	case EntityNetwork:
		return "network"
	default:
		return "unknown"
	}
}

// ActiveEntry records a recent change to an entity.
type ActiveEntry struct {
	ID        string     `json:"id"`         // entity ID (PID, inode key)
	EntityType EntityType `json:"entity_type"`
	LastSeen  time.Time  `json:"last_seen"`
	ChangeCount int      `json:"change_count"`
}

// ActiveTable tracks entities that changed in the last N minutes.
// Used to limit diff computation to only recently active entities.
type ActiveTable struct {
	mu       sync.Mutex
	entries  map[string]*ActiveEntry
	window   time.Duration // default 5 min
}

// NewActiveTable creates an active entity tracker.
func NewActiveTable(window time.Duration) *ActiveTable {
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &ActiveTable{
		entries: make(map[string]*ActiveEntry),
		window:  window,
	}
}

// Touch marks an entity as recently active.
func (at *ActiveTable) Touch(id string, etype EntityType) {
	now := time.Now()
	at.mu.Lock()
	defer at.mu.Unlock()

	entry, ok := at.entries[id]
	if ok {
		entry.LastSeen = now
		entry.ChangeCount++
	} else {
		at.entries[id] = &ActiveEntry{
			ID:           id,
			EntityType:   etype,
			LastSeen:     now,
			ChangeCount:  1,
		}
	}
}

// GetActive returns all entities active within the window.
func (at *ActiveTable) GetActive() []*ActiveEntry {
	cutoff := time.Now().Add(-at.window)
	at.mu.Lock()
	defer at.mu.Unlock()

	var out []*ActiveEntry
	for _, entry := range at.entries {
		if entry.LastSeen.After(cutoff) {
			out = append(out, entry)
		}
	}
	return out
}

// GetActiveIDs returns only IDs of recently active entities.
func (at *ActiveTable) GetActiveIDs() []string {
	entries := at.GetActive()
	ids := make([]string, len(entries))
	for i, e := range entries {
		ids[i] = e.ID
	}
	return ids
}

// CleanExpired removes entries older than the window.
func (at *ActiveTable) CleanExpired() int {
	cutoff := time.Now().Add(-at.window)
	at.mu.Lock()
	defer at.mu.Unlock()

	removed := 0
	for id, entry := range at.entries {
		if entry.LastSeen.Before(cutoff) {
			delete(at.entries, id)
			removed++
		}
	}
	return removed
}

// Stats returns active table statistics.
func (at *ActiveTable) Stats() map[string]interface{} {
	at.mu.Lock()
	defer at.mu.Unlock()

	byType := map[EntityType]int{}
	for _, e := range at.entries {
		byType[e.EntityType]++
	}

	return map[string]interface{}{
		"total_active":   len(at.entries),
		"processes":      byType[EntityProcess],
		"files":          byType[EntityFile],
		"networks":       byType[EntityNetwork],
		"window":         at.window.String(),
	}
}

// Summary returns a human-readable summary.
func (at *ActiveTable) Summary() string {
	stats := at.Stats()
	return fmt.Sprintf("Active: %d entities (%d processes, %d files, %d networks) in %v",
		stats["total_active"], stats["processes"], stats["files"], stats["networks"],
		stats["window"])
}
