// Package analyzer implements APT detection logic on top of the
// provenance graph.  It follows the approaches described in:
//
//	HOLMES (CCS 2017)       — Real-time APT detection through
//	                          correlation of suspicious information flows
//	Unicorn (NDSS 2017)    — Runtime program shepherding and
//	                          cross-application information flow tracking
//	NoDoze (NDSS 2019)     — Dependency graph scoring for attack
//	                          prioritization
//	SIGL (SEC 2023)        — Scenario-specific information flow
//	                          graph mining
//
// High-level flow:
//
//	Provenance Graph → Taint Propagation → Pattern Matching → Alert
//	     │                                      │
//	     └── Snapshot (thread-safe copy)         └── Subgraph Extraction
package analyzer

import (
	"log"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ═══════════════════════════════════════════════════════════════
// Config
// ═══════════════════════════════════════════════════════════════

// Config tunes the analyzer's sensitivity and scan behaviour.
type Config struct {
	// ScanInterval is how often the analyzer takes a snapshot and
	// re-runs detection.  Shorter intervals catch attacks faster but
	// consume more CPU.
	ScanInterval time.Duration

	// DeepTaintThreshold is the minimum propagation depth for
	// PatDeepTaint alerts.  HOLMES typically uses 3-4.
	DeepTaintThreshold int

	// EnablePatterns selects which patterns are active.
	EnablePatterns []PatternID

	// Quiet mode: only log alerts at SeverityHigh+.
	Quiet bool
}

// DefaultConfig returns a sensible starting configuration.
func DefaultConfig() *Config {
	return &Config{
		ScanInterval:       30 * time.Second,
		DeepTaintThreshold: 3,
		EnablePatterns: []PatternID{
			PatSensitiveExfil,
			PatScriptChild,
			PatDeepTaint,
			PatPrivEsc,
			PatMemoryAnomaly,
		},
		Quiet: false,
	}
}

// ═══════════════════════════════════════════════════════════════
// Analyzer
// ═══════════════════════════════════════════════════════════════

// Analyzer periodically scans the provenance graph, runs taint
// propagation and pattern matching, and emits alerts.
type Analyzer struct {
	graph *provenance.Graph
	cfg   *Config

	mu        sync.Mutex
	alerts    []*Alert
	eventBase int // number of events at last scan (for delta detection)

	// AlertCh is consumed by the caller (e.g., main.go) for
	// real-time notification.
	AlertCh chan *Alert

	sketchIntegrator *SketchIntegrator // optional graph sketching

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// New creates an analyzer attached to a provenance graph.
func New(graph *provenance.Graph, cfg *Config) *Analyzer {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Analyzer{
		graph:   graph,
		cfg:     cfg,
		alerts:  make([]*Alert, 0),
		AlertCh: make(chan *Alert, 128),
		stopCh:  make(chan struct{}),
	}
}

// Start begins periodic scanning in a background goroutine.
func (a *Analyzer) Start() {
	a.wg.Add(1)
	go a.loop()
	log.Printf("[analyzer] started (interval=%s, deep_taint_threshold=%d)",
		a.cfg.ScanInterval, a.cfg.DeepTaintThreshold)
}

// Stop signals the background goroutine to exit and waits for it.
func (a *Analyzer) Stop() {
	close(a.stopCh)
	a.wg.Wait()
	close(a.AlertCh)
}

// Alerts returns a copy of all alerts generated so far.
func (a *Analyzer) Alerts() []*Alert {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*Alert, len(a.alerts))
	copy(out, a.alerts)
	return out
}

// ── Scan loop ───────────────────────────────────────────────

func (a *Analyzer) loop() {
	defer a.wg.Done()

	// First scan immediately
	a.scan()

	ticker := time.NewTicker(a.cfg.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.scan()
		case <-a.stopCh:
			return
		}
	}
}

// scan takes a snapshot of the current graph and runs detection.
func (a *Analyzer) scan() {
	stats := a.graph.Stats()
	if stats.Nodes == 0 {
		return
	}

	snap := SnapshotFromGraph(a.graph)
	te := NewTaintEngine(snap)

	var alerts []*Alert
	enabled := make(map[PatternID]bool)
	for _, p := range a.cfg.EnablePatterns {
		enabled[p] = true
	}

	if enabled[PatSensitiveExfil] {
		alerts = append(alerts, checkSensitiveExfil(te)...)
	}
	if enabled[PatScriptChild] {
		alerts = append(alerts, checkScriptChild(te)...)
	}
	if enabled[PatDeepTaint] {
		alerts = append(alerts, checkDeepTaint(te, a.cfg.DeepTaintThreshold)...)
	}
	if enabled[PatPrivEsc] {
		alerts = append(alerts, checkPrivEsc(te)...)
	}
	if enabled[PatMemoryAnomaly] {
		alerts = append(alerts, checkMemoryAnomaly(te)...)
	}

	// Attach subgraphs and deduplicate
	seen := make(map[string]bool)
	for _, al := range alerts {
		al.DetectedAt = time.Now()
		al.ExtractSubgraph(te)

		key := string(al.Pattern) + ":" + al.AlertNodeID
		if seen[key] {
			continue
		}
		seen[key] = true

		a.mu.Lock()
		a.alerts = append(a.alerts, al)
		a.mu.Unlock()

		// Non-blocking send
		select {
		case a.AlertCh <- al:
		default:
		}

		if a.cfg.Quiet && al.Severity < SeverityHigh {
			continue
		}
		log.Printf("[analyzer] %s", al)
	}

	log.Printf("[analyzer] scan complete: %d nodes, %d edges, %d taint seeds, %d alerts",
		stats.Nodes, stats.Edges, len(te.TaintedProcesses()), len(alerts))

	// Graph sketching: produce feature vectors and check entropy.
	if a.sketchIntegrator != nil {
		a.sketchIntegrator.ProcessSnapshot(snap)
	}
}
