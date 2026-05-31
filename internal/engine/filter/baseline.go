// Package filter implements a benign behaviour filtering engine for
// ProvidAPT.  It learns normal system activity patterns and suppresses
// repetitive low-value events to reduce storage and analysis overhead.
//
// Components:
//
//   Baseline — 24h training mode records hashes of normal operations
//   Reputation — path-based scoring (/usr/bin=high, /tmp=low)
//   Engine — combines baseline + reputation + runtime filtering
package filter

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
)

// ═══════════════════════════════════════════════════════════════
// Behavioural hash
// ═══════════════════════════════════════════════════════════════

// Hash computes a behavioural signature for an event.
// Signature = SHA256(comm + operation + target_path).
// Two events with the same hash are behaviourally identical.
func Hash(evt *collector.Event) string {
	op := evt.Type.String()
	comm := strings.TrimSpace(evt.Comm)
	path := strings.TrimSpace(evt.Pathname)
	data := fmt.Sprintf("%s|%s|%s", comm, op, path)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(data)))[:16]
}

// ═══════════════════════════════════════════════════════════════
// Baseline — trained behavioural whitelist
// ═══════════════════════════════════════════════════════════════

// Baseline stores a set of "normal" behavioural hashes learned during
// the training period.  The set is persisted to disk as a JSON blob
// under a well-known RocksDB key.
type Baseline struct {
	persist   PersistReadWriter
	mu        sync.RWMutex
	known     map[string]int64 // hash → occurrence count
	training  bool
	startedAt time.Time
	endsAt    time.Time
}

const baselineStoreKey = "filter:baseline"

// PersistReadWriter is the minimal interface needed for baseline persistence.
type PersistReadWriter interface {
	Get(key string) ([]byte, error)
	Put(key string, value []byte) error
}

// NewBaseline creates a baseline learner, optionally loading from store.
func NewBaseline(store PersistReadWriter) *Baseline {
	b := &Baseline{
		persist: store,
		known:   make(map[string]int64),
	}
	b.load()
	return b
}

// ── Training lifecycle ──────────────────────────────────────

func (b *Baseline) StartTraining() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.training = true
	b.startedAt = time.Now()
	b.endsAt = time.Now().Add(24 * time.Hour)
	log.Printf("[filter] training started — ends at %s", b.endsAt.Format(time.RFC3339))
}

func (b *Baseline) StopTraining() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.training = false
	b.save()
}

func (b *Baseline) IsTraining() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.training && time.Now().Before(b.endsAt)
}

func (b *Baseline) TrainingRemaining() time.Duration {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if !b.training {
		return 0
	}
	r := time.Until(b.endsAt)
	if r < 0 {
		return 0
	}
	return r
}

// ── Core operations ─────────────────────────────────────────

func (b *Baseline) Record(hash string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.known[hash]++
}

func (b *Baseline) IsKnown(hash string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.known[hash]
	return ok
}

// ── Persistence ─────────────────────────────────────────────

func (b *Baseline) save() {
	if b.persist == nil {
		return
	}
	b.mu.RLock()
	data, err := json.Marshal(b.known)
	b.mu.RUnlock()
	if err != nil {
		log.Printf("[filter] baseline save marshal: %v", err)
		return
	}
	if err := b.persist.Put(baselineStoreKey, data); err != nil {
		log.Printf("[filter] baseline save put: %v", err)
		return
	}
	log.Printf("[filter] saved %d baseline entries", len(b.known))
}

func (b *Baseline) load() {
	if b.persist == nil {
		return
	}
	data, err := b.persist.Get(baselineStoreKey)
	if err != nil || data == nil {
		return
	}
	var loaded map[string]int64
	if err := json.Unmarshal(data, &loaded); err != nil {
		log.Printf("[filter] baseline load unmarshal: %v", err)
		return
	}
	b.mu.Lock()
	b.known = loaded
	b.mu.Unlock()
	log.Printf("[filter] loaded %d baseline entries from store", len(loaded))
}

func (b *Baseline) Stats() map[string]interface{} {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return map[string]interface{}{
		"known_hashes": len(b.known),
		"training":     b.training,
	}
}
