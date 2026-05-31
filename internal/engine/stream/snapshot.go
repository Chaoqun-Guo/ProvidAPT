package stream

import (
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
)

// ═══════════════════════════════════════════════════════════════
// Rolling memory snapshot
//
// Maintains a fixed-size window of recent events in memory for
// fast retrieval without disk I/O.  The snapshot is organized as:
//
//   1. events: ring buffer of recent events
//   2. byPID:  index mapping PID → events
//   3. byType: index mapping event type → events
//
// The snapshot automatically evicts entries older than the
// configured window (default 1 hour).
// ═══════════════════════════════════════════════════════════════

// RollingSnapshot maintains a time-windowed view of recent events.
type RollingSnapshot struct {
	mu      sync.RWMutex
	window  time.Duration
	events  []*snapEntry
	byPID   map[uint32][]int  // PID → event indices
	head    int               // ring buffer head
	tail    int               // ring buffer tail
	maxSize int               // ring buffer capacity
}

type snapEntry struct {
	event *collector.Event
	time  time.Time
}

// NewRollingSnapshot creates a snapshot with the given time window.
func NewRollingSnapshot(window time.Duration) *RollingSnapshot {
	if window <= 0 {
		window = 1 * time.Hour
	}
	// Estimate: 50K events/sec × 3600s = 180M events → too large.
	// Use a ring buffer with a reasonable max size (500K events ≈ 10s at 50K/s).
	// The time window determines eviction, the ring buffer prevents unbounded growth.
	maxSize := 500000
	return &RollingSnapshot{
		window:  window,
		events:  make([]*snapEntry, maxSize),
		byPID:   make(map[uint32][]int),
		maxSize: maxSize,
	}
}

// Add inserts an event into the snapshot.
func (rs *RollingSnapshot) Add(evt *collector.Event) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	entry := &snapEntry{
		event: evt,
		time:  time.Now(),
	}

	// Ring buffer insert
	rs.events[rs.head] = entry
	idx := rs.head
	rs.head = (rs.head + 1) % rs.maxSize

	// If we wrapped around, evict the oldest
	if rs.head == rs.tail {
		// Remove old entry from indexes
		old := rs.events[rs.tail]
		if old != nil {
			rs.removeFromIndex(old.event.PID, rs.tail)
		}
		rs.tail = (rs.tail + 1) % rs.maxSize
	}

	// Add to PID index
	rs.byPID[evt.PID] = append(rs.byPID[evt.PID], idx)
}

// GetByPID returns all events for a given PID within the window.
func (rs *RollingSnapshot) GetByPID(pid uint32) []*collector.Event {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	indices := rs.byPID[pid]
	if len(indices) == 0 {
		return nil
	}

	cutoff := time.Now().Add(-rs.window)
	var result []*collector.Event

	for _, idx := range indices {
		entry := rs.events[idx]
		if entry != nil && entry.time.After(cutoff) {
			result = append(result, entry.event)
		}
	}
	return result
}

// RecentEvents returns all events from the last N seconds.
func (rs *RollingSnapshot) RecentEvents(seconds int) []*collector.Event {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	cutoff := time.Now().Add(-time.Duration(seconds) * time.Second)
	var result []*collector.Event

	idx := rs.tail
	for idx != rs.head {
		entry := rs.events[idx]
		if entry != nil && entry.time.After(cutoff) {
			result = append(result, entry.event)
		}
		idx = (idx + 1) % rs.maxSize
	}
	return result
}

// Evict removes entries older than the configured window.
func (rs *RollingSnapshot) Evict() int {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	cutoff := time.Now().Add(-rs.window)
	evicted := 0

	// Walk from tail, evict old entries
	for rs.tail != rs.head {
		entry := rs.events[rs.tail]
		if entry == nil {
			rs.tail = (rs.tail + 1) % rs.maxSize
			continue
		}
		if entry.time.After(cutoff) {
			break // all remaining are recent enough
		}
		rs.removeFromIndex(entry.event.PID, rs.tail)
		rs.events[rs.tail] = nil
		rs.tail = (rs.tail + 1) % rs.maxSize
		evicted++
	}
	return evicted
}

// removeFromIndex removes an event index from the PID index.
func (rs *RollingSnapshot) removeFromIndex(pid uint32, idx int) {
	indices := rs.byPID[pid]
	for i, v := range indices {
		if v == idx {
			rs.byPID[pid] = append(indices[:i], indices[i+1:]...)
			return
		}
	}
}

// ContainsPID checks if a PID has events in the snapshot.
func (rs *RollingSnapshot) ContainsPID(pid uint32) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return len(rs.byPID[pid]) > 0
}

// Size returns the number of events currently in the snapshot.
func (rs *RollingSnapshot) Size() int {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	if rs.head >= rs.tail {
		return rs.head - rs.tail
	}
	return rs.maxSize - rs.tail + rs.head
}
