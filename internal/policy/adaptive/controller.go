package adaptive

import (
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// BPF Map interface
// ═══════════════════════════════════════════════════════════════

// BPFMapWriter is the minimal interface for writing to a kernel BPF map.
// In production this is backed by *ebpf.Map.
type BPFMapWriter interface {
	Put(key interface{}, value interface{}) error
	Delete(key interface{}) error
}

// ═══════════════════════════════════════════════════════════════
// Process state
// ═══════════════════════════════════════════════════════════════

// procState tracks the monitoring state of a single process.
type procState struct {
	PID         int
	Level       Level
	UpgradedAt  time.Time
	LastAlertAt time.Time
	AlertCount  int
	DowngradeAt time.Time
}

// ═══════════════════════════════════════════════════════════════
// AdaptiveController
// ═══════════════════════════════════════════════════════════════

// AdaptiveController manages per-process monitoring levels and
// implements the feedback loop for auto-downgrade.
type AdaptiveController struct {
	bpfMap BPFMapWriter

	mu      sync.RWMutex
	procs   map[int]*procState
	history []*procState // completed states (for stats)

	// Configuration
	downgradeAfter time.Duration // Level1→2 default cooldown
	upgradeCooldown time.Duration // min time between upgrades

	stats Stats
}

// Stats tracks controller performance.
type Stats struct {
	TotalUpgrades   int
	TotalDowngrades int
	ActiveHigh       int // processes at LevelInvestigating
	ActiveMedium     int // processes at LevelSuspicious
}

// New creates an adaptive controller.
func New(bpfMap BPFMapWriter) *AdaptiveController {
	return &AdaptiveController{
		bpfMap:          bpfMap,
		procs:           make(map[int]*procState),
		downgradeAfter:  600 * time.Second,
		upgradeCooldown: 30 * time.Second,
	}
}

// ── Core operations ─────────────────────────────────────────

// GetLevel returns the current monitoring level for a PID.
func (ac *AdaptiveController) GetLevel(pid int) Level {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	if ps, ok := ac.procs[pid]; ok {
		return ps.Level
	}
	return LevelDefault
}

// Upgrade raises the monitoring level for a process.
// Called by the analysis engine when an alert is triggered.
func (ac *AdaptiveController) Upgrade(pid int, reason string) Level {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	ps := ac.getOrCreate(pid)
	newLevel := ps.Level

	// Determine appropriate level based on alert frequency
	switch {
	case ps.AlertCount >= 3:
		newLevel = LevelInvestigating
	case ps.AlertCount >= 1:
		newLevel = LevelSuspicious
	}
	// Respect cooldown
	if time.Since(ps.UpgradedAt) < ac.upgradeCooldown && ps.Level > LevelDefault {
		return ps.Level
	}

	ps.Level = newLevel
	ps.UpgradedAt = time.Now()
	ps.LastAlertAt = time.Now()
	ps.AlertCount++

	// Compute downgrade time based on level
	downgradeSec := newLevel.DowngradeAfter()
	if downgradeSec > 0 {
		ps.DowngradeAt = time.Now().Add(time.Duration(downgradeSec) * time.Second)
	}

	// Write to BPF map
	if ac.bpfMap != nil {
		if err := ac.bpfMap.Put(uint32(pid), uint32(newLevel)); err != nil {
			log.Printf("[adaptive] bpf put pid=%d level=%d: %v", pid, newLevel, err)
		}
	}

	log.Printf("[adaptive] UPGRADE pid=%d %s→%s (reason=%s, alerts=%d)",
		pid, LevelFor(ps.Level, newLevel), newLevel, reason, ps.AlertCount)
	ac.stats.TotalUpgrades++
	ac.refreshStats()
	return newLevel
}

// Downgrade lowers the monitoring level for a process.
func (ac *AdaptiveController) Downgrade(pid int) Level {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	ps, ok := ac.procs[pid]
	if !ok {
		return LevelDefault
	}

	oldLevel := ps.Level
	ps.Level = LevelDefault
	ps.DowngradeAt = time.Time{}

	// Update BPF map
	if ac.bpfMap != nil {
		if err := ac.bpfMap.Delete(uint32(pid)); err != nil {
			log.Printf("[adaptive] bpf delete pid=%d: %v", pid, err)
		}
	}

	log.Printf("[adaptive] DOWNGRADE pid=%d %s→DEFAULT", pid, oldLevel)
	ac.stats.TotalDowngrades++
	ac.refreshStats()
	return LevelDefault
}

// ── Feedback loop ───────────────────────────────────────────

// Tick is called periodically (every 30s) to check for
// processes that need downgrading.
func (ac *AdaptiveController) Tick() int {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	downgraded := 0
	now := time.Now()

	for pid, ps := range ac.procs {
		if ps.Level <= LevelDefault {
			continue
		}

		// Check if downgrade time has elapsed
		if !ps.DowngradeAt.IsZero() && now.After(ps.DowngradeAt) {
			oldLevel := ps.Level
			ps.Level = LevelDefault
			ps.DowngradeAt = time.Time{}

			if ac.bpfMap != nil {
				if err := ac.bpfMap.Delete(uint32(pid)); err != nil {
					log.Printf("[adaptive] bpf delete pid=%d: %v", pid, err)
				}
			}

			log.Printf("[adaptive] FEEDBACK DOWNGRADE pid=%d %s→DEFAULT (cooldown expired)",
				pid, oldLevel)
			downgraded++
			ac.stats.TotalDowngrades++
		}
	}

	ac.refreshStats()
	return downgraded
}

// BackgroundLoop runs the feedback loop in a goroutine.
// Checks every 30 seconds for processes to downgrade.
func (ac *AdaptiveController) BackgroundLoop(stopCh <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			n := ac.Tick()
			if n > 0 {
				log.Printf("[adaptive] feedback loop: downgraded %d processes", n)
			}
		case <-stopCh:
			return
		}
	}
}

// ── Alert integration ───────────────────────────────────────

// OnAlert is called by the analysis engine when a finding is produced.
// It uses the alert's score to determine the appropriate level.
func (ac *AdaptiveController) OnAlert(pid int, score float64, reason string) Level {
	// Never upgrade for very low scores
	if score < LevelDefault.AlertThreshold() {
		return ac.GetLevel(pid)
	}

	// Upgrade chain:
	// score 5-19  → Suspicious
	// score 20+   → Investigating
	if score >= LevelInvestigating.AlertThreshold() {
		// Override directly to Investigating
		ac.mu.Lock()
		ps := ac.getOrCreate(pid)
		ps.Level = LevelInvestigating
		ps.AlertCount++
		ps.LastAlertAt = time.Now()
		ps.DowngradeAt = time.Now().Add(5 * time.Minute)
		if ac.bpfMap != nil {
			ac.bpfMap.Put(uint32(pid), uint32(LevelInvestigating))
		}
		log.Printf("[adaptive] FAST UPGRADE pid=%d → INVESTIGATING (score=%.1f, reason=%s)",
			pid, score, reason)
		ac.mu.Unlock()
		return LevelInvestigating
	}

	return ac.Upgrade(pid, reason)
}

// ── Process management ─────────────────────────────────────

func (ac *AdaptiveController) getOrCreate(pid int) *procState {
	if ps, ok := ac.procs[pid]; ok {
		return ps
	}
	ps := &procState{PID: pid, Level: LevelDefault}
	ac.procs[pid] = ps
	return ps
}

func (ac *AdaptiveController) refreshStats() {
	var high, med int
	for _, ps := range ac.procs {
		switch ps.Level {
		case LevelInvestigating:
			high++
		case LevelSuspicious:
			med++
		}
	}
	ac.stats.ActiveHigh = high
	ac.stats.ActiveMedium = med
}

// ── Stats and reporting ─────────────────────────────────────

// Stats returns a snapshot of controller statistics.
func (ac *AdaptiveController) Stats() map[string]interface{} {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return map[string]interface{}{
		"active_high":       ac.stats.ActiveHigh,
		"active_medium":     ac.stats.ActiveMedium,
		"total_upgrades":    ac.stats.TotalUpgrades,
		"total_downgrades":  ac.stats.TotalDowngrades,
		"tracked_pids":      len(ac.procs),
	}
}

// ActiveProcesses returns the list of processes currently at elevated levels.
func (ac *AdaptiveController) ActiveProcesses() []struct {
	PID   int
	Level Level
	Since time.Duration
} {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	var out []struct {
		PID   int
		Level Level
		Since time.Duration
	}
	for pid, ps := range ac.procs {
		if ps.Level > LevelDefault {
			out = append(out, struct {
				PID   int
				Level Level
				Since time.Duration
			}{pid, ps.Level, time.Since(ps.UpgradedAt)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Level > out[j].Level
	})
	return out
}

// ── Helper ──────────────────────────────────────────────────

// LevelFor returns a string describing a level transition.
func LevelFor(old, new Level) string {
	if old == new {
		return new.String()
	}
	return fmt.Sprintf("%s→%s", old, new)
}
