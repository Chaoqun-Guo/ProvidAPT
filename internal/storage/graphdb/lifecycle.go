package graphdb

import (
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Data lifecycle — hot/cold separation and archiving
// ═══════════════════════════════════════════════════════════════

// DataTier indicates the storage tier of a record.
type DataTier int

const (
	TierHot  DataTier = 0 // < 7 days, full graph, fast query
	TierWarm DataTier = 1 // 7-30 days, compressed
	TierCold DataTier = 2 // > 30 days, archived, alert chains only
)

// LifecycleConfig controls data retention.
type LifecycleConfig struct {
	// HotRetention — days before hot→warm transition (default 7).
	HotRetention int

	// WarmRetention — days before warm→cold transition (default 30).
	WarmRetention int

	// ColdArchivePath — where to store archived data.
	ColdArchivePath string

	// EnableAutoArchival — automatically archive old data.
	EnableAutoArchival bool

	// DryRun — log actions without deleting.
	DryRun bool
}

// DefaultLifecycleConfig returns sensible defaults.
func DefaultLifecycleConfig() *LifecycleConfig {
	return &LifecycleConfig{
		HotRetention:      7,
		WarmRetention:     30,
		EnableAutoArchival: true,
		DryRun:            true,
	}
}

// DataRecord tracks a single record's lifecycle.
type DataRecord struct {
	ID        string    `json:"id"`
	Tier      DataTier  `json:"tier"`
	CreatedAt time.Time `json:"created_at"`
	IsAlert   bool      `json:"is_alert"`
	SizeBytes int64     `json:"size_bytes"`
}

// LifecycleManager handles data tier transitions.
type LifecycleManager struct {
	cfg    *LifecycleConfig
	mu     sync.Mutex
	stats  LifecycleStats
}

// LifecycleStats tracks archival operations.
type LifecycleStats struct {
	HotToWarm  int
	WarmToCold int
	AlertOnly  int
	TotalSize  int64
}

// NewLifecycleManager creates a data lifecycle manager.
func NewLifecycleManager(cfg *LifecycleConfig) *LifecycleManager {
	if cfg == nil {
		cfg = DefaultLifecycleConfig()
	}
	return &LifecycleManager{cfg: cfg}
}

// Classify determines which tier a record belongs to.
func (lm *LifecycleManager) Classify(createdAt time.Time, isAlert bool) DataTier {
	age := time.Since(createdAt)

	if age < time.Duration(lm.cfg.HotRetention)*24*time.Hour {
		return TierHot
	}
	if age < time.Duration(lm.cfg.WarmRetention)*24*time.Hour {
		return TierWarm
	}

	// Cold tier: only keep alert chains
	if isAlert {
		return TierCold
	}
	return TierCold // will be pruned
}

// ShouldPrune checks if a non-alert record should be removed.
func (lm *LifecycleManager) ShouldPrune(createdAt time.Time, isAlert bool) bool {
	age := time.Since(createdAt)
	coldThreshold := time.Duration(lm.cfg.WarmRetention) * 24 * time.Hour

	if age <= coldThreshold {
		return false // within retention
	}
	if isAlert {
		return false // always keep alerts
	}
	return true // prune non-alert old data
}

// Archive moves data to the appropriate tier.
func (lm *LifecycleManager) Archive(record *DataRecord) DataTier {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	newTier := lm.Classify(record.CreatedAt, record.IsAlert)

	if newTier == record.Tier {
		return newTier // no transition needed
	}

	switch newTier {
	case TierWarm:
		lm.stats.HotToWarm++
		if !lm.cfg.DryRun {
			log.Printf("[lifecycle] HOT→WARM: %s", record.ID)
		}
	case TierCold:
		if record.IsAlert {
			lm.stats.AlertOnly++
			if !lm.cfg.DryRun {
				log.Printf("[lifecycle] WARM→COLD (alert): %s", record.ID)
			}
		} else {
			lm.stats.WarmToCold++
			if lm.cfg.DryRun {
				log.Printf("[lifecycle] DRY: would archive %s to cold", record.ID)
			} else {
				log.Printf("[lifecycle] COLD: %s archived", record.ID)
			}
		}
	}

	record.Tier = newTier
	lm.stats.TotalSize += record.SizeBytes
	return newTier
}

// Tick runs periodic archival. Call every hour.
func (lm *LifecycleManager) Tick() {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	log.Printf("[lifecycle] tick: hot→warm=%d warm→cold=%d alerts=%d",
		lm.stats.HotToWarm, lm.stats.WarmToCold, lm.stats.AlertOnly)
}

// Stats returns lifecycle statistics.
func (lm *LifecycleManager) Stats() map[string]interface{} {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	return map[string]interface{}{
		"hot_retention_days": lm.cfg.HotRetention,
		"warm_retention_days": lm.cfg.WarmRetention,
		"hot_to_warm":        lm.stats.HotToWarm,
		"warm_to_cold":       lm.stats.WarmToCold,
		"alert_chains_kept":  lm.stats.AlertOnly,
		"dry_run":            lm.cfg.DryRun,
	}
}
