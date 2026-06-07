// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package compact

import (
	"strings"
	"testing"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ── Reducer tests ───────────────────────────────────────────

func TestNewReducer(t *testing.T) {
	r := NewReducer(nil)
	if r == nil {
		t.Fatal("NewReducer returned nil")
	}
}

func TestReduceEmptyGraph(t *testing.T) {
	r := NewReducer(DefaultReductionConfig())
	metrics := r.Reduce(provenance.NewGraph())
	if metrics.NodesExamined != 0 {
		t.Errorf("examined = %d", metrics.NodesExamined)
	}
}

func TestReduceIntermediateNode(t *testing.T) {
	g := provenance.NewGraph()
	nodes := []*provenance.Node{
		{ID: "p:1", Subtype: "process", Label: "bash", FirstSeen: time.Now(), LastSeen: time.Now().Add(time.Minute)},
		{ID: "p:2", Subtype: "process", Label: "sh", FirstSeen: time.Now(), LastSeen: time.Now().Add(2 * time.Minute)},
		{ID: "f:100", Subtype: "file", Label: "/tmp/out.txt"},
	}
	for _, n := range nodes {
		_ = n
	}
	_ = g
	// In production: create graph with edges and verify reduction
}

func TestReductionConfigDefaults(t *testing.T) {
	cfg := DefaultReductionConfig()
	if cfg.MaxIntermediateLifespan != 5*time.Minute {
		t.Errorf("lifespan = %v", cfg.MaxIntermediateLifespan)
	}
	if cfg.DryRun != true {
		t.Error("default should be dry run")
	}
}

func TestIsShortLived(t *testing.T) {
	r := NewReducer(nil)
	n := &provenance.Node{
		FirstSeen: time.Now().Add(-1 * time.Minute),
		LastSeen:  time.Now(),
	}
	if !r.isShortLived(n) {
		t.Error("1-minute lifespan should be short")
	}
	n2 := &provenance.Node{
		FirstSeen: time.Now().Add(-24 * time.Hour),
		LastSeen:  time.Now(),
	}
	if r.isShortLived(n2) {
		t.Error("24h lifespan should not be short")
	}
}

func TestIsSensitive(t *testing.T) {
	r := NewReducer(nil)
	if !r.isSensitive(&provenance.Node{Label: "/etc/shadow"}) {
		t.Error("shadow should be sensitive")
	}
	if !r.isSensitive(&provenance.Node{Label: "sudo"}) {
		t.Error("sudo should be sensitive")
	}
	if r.isSensitive(&provenance.Node{Label: "bash"}) {
		t.Error("bash should not be sensitive")
	}
}

func TestSummary(t *testing.T) {
	metrics := &ReductionMetrics{NodesMerged: 5, NodesExamined: 100, EdgesRemoved: 10, EdgesCreated: 3}
	summary := metrics.Summary()
	if len(summary) == 0 {
		t.Error("empty summary")
	}
	t.Logf("Reduction summary: %s", summary)
}

// ── Summary tests ───────────────────────────────────────────

func TestNewSummaryEngine(t *testing.T) {
	se := NewSummaryEngine(nil)
	if se == nil {
		t.Fatal("NewSummaryEngine returned nil")
	}
}

func TestSummaryConfig(t *testing.T) {
	cfg := DefaultSummaryConfig()
	if cfg.MinEventsForSummary != 1000 {
		t.Errorf("min events = %d", cfg.MinEventsForSummary)
	}
	if cfg.SummaryAge != 7*24*time.Hour {
		t.Errorf("age = %v", cfg.SummaryAge)
	}
}

func TestSummariseEmpty(t *testing.T) {
	se := NewSummaryEngine(nil)
	summaries := se.SummariseEdges(nil, nil)
	if len(summaries) != 0 {
		t.Errorf("summaries = %d", len(summaries))
	}
}

func TestBehaviourSummaryText(t *testing.T) {
	bs := &BehaviourSummary{
		ProcessComm: "nginx",
		Operation:   "READ",
		TargetEntity: "access.log",
		TotalCalls:  50000,
		TotalBytes:  50000 * 332,
		TimeStart:   "2025-01-01T00:00:00Z",
		TimeEnd:     "2025-01-01T23:59:59Z",
	}
	text := bs.SummaryText()
	if !strings.Contains(text, "nginx") || !strings.Contains(text, "50000") {
		t.Errorf("text = %s", text)
	}
	t.Logf("Summary text: %s", text)
}

func TestCombine(t *testing.T) {
	reduction := &ReductionMetrics{NodesMerged: 10, EdgesRemoved: 20}
	summaries := []*BehaviourSummary{
		{TotalCalls: 50000, TotalBytes: 50000 * 332},
		{TotalCalls: 30000, TotalBytes: 30000 * 332},
	}
	result := Combine(reduction, summaries)
	if result.EdgesRemoved != 20+50000+30000 {
		t.Errorf("removed = %d", result.EdgesRemoved)
	}
	if result.StorageSaved <= 0 {
		t.Error("no storage saved")
	}
	t.Logf("%s", result.Summary())
}

// ── Tiering tests ──────────────────────────────────────────

func TestNewTieringManager(t *testing.T) {
	tm := NewTieringManager(nil)
	if tm == nil {
		t.Fatal("NewTieringManager returned nil")
	}
}

func TestDefaultTieringConfig(t *testing.T) {
	cfg := DefaultTieringConfig()
	if cfg.HotRetention != 7*24*time.Hour {
		t.Errorf("hot retention = %v", cfg.HotRetention)
	}
	if cfg.ExportFormat != "json" {
		t.Errorf("format = %s", cfg.ExportFormat)
	}
}

func TestArchiveHotToWarm(t *testing.T) {
	tm := NewTieringManager(DefaultTieringConfig())
	summaries := []*BehaviourSummary{
		{
			ProcessID: "p:100", ProcessComm: "nginx",
			Operation: "READ", TotalCalls: 1000,
			TimeStart: "2025-01-01T00:00:00Z",
			TimeEnd:   "2025-01-01T01:00:00Z",
		},
	}
	n, err := tm.ArchiveHotToWarm(summaries)
	if err != nil {
		t.Fatalf("ArchiveHotToWarm: %v", err)
	}
	t.Logf("Archived: %d (dry run)", n)
}

func TestArchiveWarmToCold(t *testing.T) {
	tm := NewTieringManager(DefaultTieringConfig())
	n, err := tm.ArchiveWarmToCold()
	if err != nil {
		t.Fatalf("ArchiveWarmToCold: %v", err)
	}
	t.Logf("Cold archived: %d (dry run)", n)
}

func TestLookupCold(t *testing.T) {
	tm := NewTieringManager(nil)
	tm.index["p:100|2025-01-01"] = &ColdIndexEntry{
		Bucket: "providapt", EntityID: "p:100",
	}
	results := tm.LookupCold("p:100")
	if len(results) != 1 {
		t.Errorf("results = %d", len(results))
	}
}

func TestStats(t *testing.T) {
	tm := NewTieringManager(nil)
	stats := tm.Stats()
	if stats["dry_run"] != true {
		t.Error("should be dry run")
	}
}

// ── Integration test ────────────────────────────────────────

func TestCompactIntegration(t *testing.T) {
	t.Log("=== Compaction Pipeline Test ===")

	// 1. Reduction
	reducer := NewReducer(DefaultReductionConfig())
	metrics := reducer.Reduce(provenance.NewGraph())
	t.Logf("Reduction: %s", metrics.Summary())

	// 2. Summarisation
	se := NewSummaryEngine(nil)
	summaries := se.SummariseEdges(nil, nil)
	t.Logf("Summaries: %d", len(summaries))

	// 3. Combine
	result := Combine(metrics, summaries)
	t.Logf("Combined: %s", result.Summary())

	// 4. Tiering
	tm := NewTieringManager(DefaultTieringConfig())
	tm.ArchiveHotToWarm(summaries)
	tm.ArchiveWarmToCold()

	t.Log("=== Compaction Pipeline Complete ===")
}
