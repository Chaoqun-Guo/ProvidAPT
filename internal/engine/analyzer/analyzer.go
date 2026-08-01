// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

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
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/policy/sigma"
)

// ═══════════════════════════════════════════════════════════════
// Config
// ═══════════════════════════════════════════════════════════════

// Config tunes the analyzer's sensitivity and scan behavior.
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

	OnlineMLEnabled     bool
	MLModelDir          string
	MLDeployGatePath    string
	RequireMLDeployGate bool
	MLThreshold         float64
	MLMinNodes          int
	MLMinEdges          int
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
		Quiet:       false,
		MLThreshold: 0.85,
		MLMinNodes:  3,
		MLMinEdges:  2,
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

	mu     sync.Mutex
	alerts []*Alert

	// AlertCh is consumed by the caller (e.g., main.go) for
	// real-time notification.
	AlertCh chan *Alert

	sketchIntegrator *SketchIntegrator // optional graph sketching

	sigmaRules map[string]*sigma.Rule // rule ID → parsed rule
	sigmaMu    sync.RWMutex

	mlScorer *OnlineMLScorer

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// New creates an analyzer attached to a provenance graph.
func New(graph *provenance.Graph, cfg *Config) *Analyzer {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	a := &Analyzer{
		graph:      graph,
		cfg:        cfg,
		alerts:     make([]*Alert, 0),
		AlertCh:    make(chan *Alert, 128),
		sigmaRules: make(map[string]*sigma.Rule),
		stopCh:     make(chan struct{}),
	}
	// Load built-in Sigma rules
	for _, rule := range sigma.DefaultRules() {
		id := rule.ID
		if id == "" {
			id = rule.Title
		}
		a.sigmaRules[id] = rule
	}
	a.configureOnlineML(cfg)
	return a
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

// ReloadConfig atomically swaps the analyzer configuration.
// The change takes effect on the next scan() iteration.
func (a *Analyzer) ReloadConfig(cfg *Config) {
	a.cfg = cfg
	a.configureOnlineML(cfg)
	log.Printf("[analyzer] config reloaded (interval=%s, patterns=%d)",
		cfg.ScanInterval, len(cfg.EnablePatterns))
}

func (a *Analyzer) configureOnlineML(cfg *Config) {
	if cfg == nil || !cfg.OnlineMLEnabled {
		a.mlScorer = nil
		return
	}
	scorer, err := NewOnlineMLScorer(OnlineMLConfig{
		ModelDir:          cfg.MLModelDir,
		DeployGatePath:    cfg.MLDeployGatePath,
		RequireDeployGate: cfg.RequireMLDeployGate,
		Threshold:         cfg.MLThreshold,
		MinNodes:          cfg.MLMinNodes,
		MinEdges:          cfg.MLMinEdges,
	})
	if err != nil {
		log.Printf("[analyzer] online ML disabled: %v", err)
		a.mlScorer = nil
		return
	}
	a.mlScorer = scorer
	log.Printf("[analyzer] online ML enabled (model=%s version=%s threshold=%.3f deploy_gate=%s status=%s)",
		scorer.ModelName(), scorer.ModelVersion(), scorer.Threshold(), scorer.DeployGatePath(), scorer.DeployGateStatus())
}

// Alerts returns a copy of all alerts generated so far.
func (a *Analyzer) Alerts() []*Alert {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*Alert, len(a.alerts))
	copy(out, a.alerts)
	return out
}

// AddSigmaRule stores a Sigma rule for evaluation during each scan cycle.
func (a *Analyzer) AddSigmaRule(id string, rule *sigma.Rule) {
	a.sigmaMu.Lock()
	defer a.sigmaMu.Unlock()
	a.sigmaRules[id] = rule
	log.Printf("[analyzer] sigma rule added: %s (%s)", id, rule.Title)
}

// RemoveSigmaRule deletes a previously added Sigma rule by ID.
func (a *Analyzer) RemoveSigmaRule(id string) {
	a.sigmaMu.Lock()
	defer a.sigmaMu.Unlock()
	delete(a.sigmaRules, id)
	log.Printf("[analyzer] sigma rule removed: %s", id)
}

func (a *Analyzer) SigmaRuleIDs() []string {
	a.sigmaMu.RLock()
	defer a.sigmaMu.RUnlock()

	ids := make([]string, 0, len(a.sigmaRules))
	for id := range a.sigmaRules {
		ids = append(ids, id)
	}
	return ids
}

// sigmaLevelToSeverity maps a Sigma rule level string to an analyzer Severity.
func sigmaLevelToSeverity(level string) Severity {
	switch level {
	case "critical", "CRITICAL":
		return SeverityCritical
	case "high", "HIGH":
		return SeverityHigh
	case "medium", "MEDIUM":
		return SeverityMedium
	case "low", "LOW":
		return SeverityLow
	default:
		return SeverityMedium
	}
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

	// Sigma rules (no taint required — match on node/edge patterns directly)
	if a.mlScorer != nil {
		if alert := a.mlScorer.Score(snap, te); alert != nil {
			alerts = append(alerts, alert)
		}
	}

	a.sigmaMu.RLock()
	ruleCount := len(a.sigmaRules)
	a.sigmaMu.RUnlock()

	if ruleCount > 0 {
		a.sigmaMu.RLock()
		for id, rule := range a.sigmaRules {
			matches := sigma.EvaluateRule(rule, snap.Nodes, snap.Edges)
			for _, match := range matches {
				alertNodeID := match[0]
				alerts = append(alerts, &Alert{
					Pattern:     PatternID("SIGMA:" + id),
					Severity:    sigmaLevelToSeverity(rule.Level),
					Headline:    fmt.Sprintf("[Sigma] %s: matched %d nodes", rule.Title, len(match)),
					Reason:      fmt.Sprintf("Sigma rule %q matched nodes %v", rule.Title, match),
					AlertNodeID: alertNodeID,
				})
			}
		}
		a.sigmaMu.RUnlock()
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
