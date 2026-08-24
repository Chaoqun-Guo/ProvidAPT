// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package predict

import (
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
	"strings"
)

// ── ATT&CK tests ───────────────────────────────────────────

func TestKnownAttacks(t *testing.T) {
	chains := KnownAttacks()
	if len(chains) == 0 {
		t.Fatal("no known attacks")
	}
	t.Logf("Known attack chains: %d", len(chains))
	for _, c := range chains {
		t.Logf("  %s (%d phases)", c.Name, len(c.Phases))
	}
}

func TestNewPredictor(t *testing.T) {
	p := NewPredictor()
	if p == nil {
		t.Fatal("NewPredictor returned nil")
	}
}

func TestPredict(t *testing.T) {
	g := provenance.NewGraph()
	// Simulate: web server exploited → bash shell spawned
	g.AddEvent(&collector.Event{
		Type: syscall.EventProcessFork, TimestampNS: 1000,
		PID: 100, ChildPID: 101, Comm: "nginx",
	})
	g.AddEvent(&collector.Event{
		Type: syscall.EventProcessExec, TimestampNS: 2000,
		PID: 101, Comm: "bash", Pathname: "/tmp/evil.sh",
		Inode: 5000, DevMajor: 8, DevMinor: 3,
	})

	p := NewPredictor()
	results := p.Predict(g, "p:100")
	t.Logf("Predictions: %d", len(results))
	for _, r := range results {
		t.Logf("  %s", r.Summary())
	}
}

func TestExtractSignals(t *testing.T) {
	g := provenance.NewGraph()
	g.AddEvent(&collector.Event{
		Type: syscall.EventFileOpen, TimestampNS: 1000,
		PID: 100, Comm: "cat", Pathname: "/etc/shadow",
		Inode: 5000, DevMajor: 8, DevMinor: 3,
	})
	p := NewPredictor()
	signals := p.extractSignals(g, "p:100")
	t.Logf("Signals: %v", signals)
}

func TestPredictionSummary(t *testing.T) {
	pr := &PredictionResult{
		MatchedChain: "Web Shell",
		CurrentPhase: "execution",
		NextPhases:   []string{"persistence:install backdoor"},
		Confidence:   0.67,
	}
	summary := pr.Summary()
	if len(summary) == 0 {
		t.Error("empty summary")
	}
	t.Logf("Prediction: %s", summary)
}

// ── Blast radius tests ─────────────────────────────────────

func TestNewBlastCalculator(t *testing.T) {
	bc := NewBlastCalculator()
	if bc == nil {
		t.Fatal("NewBlastCalculator returned nil")
	}
}

func TestCalculateBlastRadius(t *testing.T) {
	g := testGraph(t)
	bc := NewBlastCalculator()
	blast := bc.Calculate(g, "p:100")
	if blast == nil {
		t.Fatal("Calculate returned nil")
	}
	t.Logf("Blast radius: %s", blast.Summary())
	if blast.TotalImpacted == 0 {
		t.Log("(no impacted assets — graph may be too small)")
	}
}

func TestBlastRadiusSummary(t *testing.T) {
	br := &BlastRadius{
		CompromisedComm: "bash",
		Files:           []Asset{{ID: "f:1", Label: "/etc/shadow", Critical: true}},
	}
	s := br.Summary()
	if !strings.Contains(s, "shadow") {
		t.Errorf("summary = %s", s)
	}
}

// ── Defense recommendation tests ────────────────────────────

func TestNewDefenseEngine(t *testing.T) {
	de := NewDefenseEngine()
	if de == nil {
		t.Fatal("NewDefenseEngine returned nil")
	}
}

func TestRecommend(t *testing.T) {
	g := testGraph(t)
	de := NewDefenseEngine()
	recs := de.Recommend(g, "p:100", "bash", 100)
	t.Logf("Recommendations: %d", len(recs))
	for _, r := range recs {
		t.Logf("  [%s] %s", r.Priority, r.Suggestion)
	}
}

func TestContainmentRecs(t *testing.T) {
	de := NewDefenseEngine()
	recs := de.containmentRecs("p:100", "curl", 1234)
	if len(recs) == 0 {
		t.Error("curl should trigger containment")
	} else {
		t.Logf("Containment: %s", recs[0].Suggestion)
	}
}

func TestFormatRecommendations(t *testing.T) {
	recs := []*DefenseRecommendation{
		{Priority: "HIGH", Action: "contain", Suggestion: "test", Target: "p:1", Rationale: "testing"},
	}
	formatted := FormatRecommendations(recs)
	if !strings.Contains(formatted, "HIGH") {
		t.Errorf("formatted = %s", formatted)
	}
	t.Logf("Formatted:\n%s", formatted)
}

func TestDedup(t *testing.T) {
	recs := []*DefenseRecommendation{
		{Suggestion: "do X"},
		{Suggestion: "do X"},
		{Suggestion: "do Y"},
	}
	deduped := dedupRecs(recs)
	if len(deduped) != 2 {
		t.Errorf("deduped = %d", len(deduped))
	}
}

// ── Integration test ────────────────────────────────────────

func testGraph(t *testing.T) *provenance.Graph {
	t.Helper()
	g := provenance.NewGraph()
	g.AddEvent(&collector.Event{
		Type: syscall.EventProcessFork, TimestampNS: 1000,
		PID: 100, ChildPID: 101, Comm: "nginx",
	})
	g.AddEvent(&collector.Event{
		Type: syscall.EventProcessExec, TimestampNS: 2000,
		PID: 101, Comm: "bash", Pathname: "/tmp/evil.sh",
		Inode: 5000, DevMajor: 8, DevMinor: 3,
	})
	g.AddEvent(&collector.Event{
		Type: syscall.EventFileOpen, TimestampNS: 3000,
		PID: 101, Comm: "bash", Pathname: "/etc/shadow",
		Inode: 5001, DevMajor: 8, DevMinor: 3,
	})
	return g
}

func TestPredictIntegration(t *testing.T) {
	g := testGraph(t)

	// 1. Predict
	p := NewPredictor()
	predictions := p.Predict(g, "p:101")
	t.Logf("=== Predictions ===")
	for _, pr := range predictions {
		t.Logf("  %s", pr.Summary())
	}

	// 2. Blast radius
	bc := NewBlastCalculator()
	blast := bc.Calculate(g, "p:101")
	t.Logf("=== Blast Radius ===")
	t.Logf("  %s", blast.Summary())

	// 3. Defend
	de := NewDefenseEngine()
	recs := de.Recommend(g, "p:101", "bash", 101)
	t.Logf("=== Recommendations ===")
	t.Logf("%s", FormatRecommendations(recs))

	t.Log("=== Prediction Integration Complete ===")
}
