// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package alert

import (
	"strings"
	"testing"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ── Pattern matcher tests ───────────────────────────────────

func TestDefaultPatterns(t *testing.T) {
	patterns := DefaultPatterns()
	if len(patterns) == 0 {
		t.Fatal("no default patterns")
	}
	t.Logf("Default patterns: %d", len(patterns))
	for _, p := range patterns {
		t.Logf("  %s (%s) — %d steps", p.ID, p.Severity, len(p.Steps))
	}
}

func TestMatchAll(t *testing.T) {
	g := testGraph(t)
	pm := NewPatternMatcher()
	matches := pm.MatchAll(g)
	t.Logf("Matches found: %d", len(matches))
	for _, m := range matches {
		t.Logf("  %s (path: %v)", m.Pattern.Name, m.Nodes)
	}
}

func TestPatternMatch(t *testing.T) {
	if !patternMatch("nginx|apache|httpd", "nginx") {
		t.Error("nginx should match")
	}
	if patternMatch("bash|sh", "curl") {
		t.Error("curl should not match bash pattern")
	}
	if !patternMatch("", "anything") {
		t.Error("empty pattern should match everything")
	}
}

func TestRelMatch(t *testing.T) {
	if !relMatch("used", "prov:used") {
		t.Error("used should match")
	}
	if relMatch("used", "prov:wasGeneratedBy") {
		t.Error("should not match different relation")
	}
}

// ── Incident tests ──────────────────────────────────────────

func TestNewIncidentManager(t *testing.T) {
	im := NewIncidentManager()
	if im == nil {
		t.Fatal("NewIncidentManager returned nil")
	}
}

func TestIngestCreatesIncident(t *testing.T) {
	im := NewIncidentManager()
	match := &MatchResult{
		Pattern: AttackPattern{ID: "APT-TEST", Name: "Test Pattern", Severity: "HIGH"},
		Nodes:   []string{"p:1", "p:2"},
	}
	inc := im.Ingest(match)
	if inc == nil {
		t.Fatal("Ingest returned nil")
	}
	if inc.PatternID != "APT-TEST" {
		t.Errorf("PatternID = %s", inc.PatternID)
	}
	if inc.Count != 1 {
		t.Errorf("Count = %d", inc.Count)
	}
}

func TestIngestMergesDuplicate(t *testing.T) {
	im := NewIncidentManager()
	im.window = time.Hour // long window for testing

	match := &MatchResult{
		Pattern: AttackPattern{ID: "APT-MERGE", Name: "Merge Test", Severity: "MEDIUM"},
		Nodes:   []string{"p:1", "p:2"},
	}
	im.Ingest(match)
	second := im.Ingest(match)
	if second != nil {
		t.Error("duplicate should be merged (return nil)")
	}

	incidents := im.ActiveIncidents()
	if len(incidents) != 1 {
		t.Errorf("active = %d, want 1", len(incidents))
	}
	if incidents[0].Count != 2 {
		t.Errorf("count = %d, want 2", incidents[0].Count)
	}
}

func TestResolveOld(t *testing.T) {
	im := NewIncidentManager()
	im.resolveAfter = time.Millisecond
	match := &MatchResult{
		Pattern: AttackPattern{ID: "APT-RESOLVE", Name: "Resolve Test"},
		Nodes:   []string{"p:1"},
	}
	im.Ingest(match)
	time.Sleep(2 * time.Millisecond)
	n := im.ResolveOld()
	if n != 1 {
		t.Errorf("resolved = %d", n)
	}
}

func TestResolveIncident(t *testing.T) {
	im := NewIncidentManager()
	match := &MatchResult{
		Pattern: AttackPattern{ID: "APT-RESOLVE-ID"},
		Nodes:   []string{"p:1"},
	}
	inc := im.Ingest(match)
	if im.ResolveIncident(inc.ID) != true {
		t.Error("should resolve existing incident")
	}
	if im.ResolveIncident("NONEXISTENT") != false {
		t.Error("should not resolve non-existent")
	}
}

// ── Summary tests ───────────────────────────────────────────

func TestSummaryGenerator(t *testing.T) {
	g := testGraph(t)
	sg := NewSummaryGenerator(g)

	inc := &Incident{
		ID: "test-1", PatternName: "Web Shell Attack",
		Severity: "CRITICAL", Nodes: []string{"p:100", "p:101"},
	}
	summary := sg.Generate(inc)
	if summary == nil {
		t.Fatal("Generate returned nil")
	}
	if !strings.Contains(summary.Title, "Web Shell") {
		t.Errorf("title = %s", summary.Title)
	}
	t.Logf("Summary: %s", summary.Text())
}

func TestSummaryFromMatch(t *testing.T) {
	g := testGraph(t)
	sg := NewSummaryGenerator(g)

	match := &MatchResult{
		Pattern: AttackPattern{Name: "Test Pattern", Severity: "HIGH", Description: "test"},
		Nodes:   []string{"p:100", "f:5001"},
	}
	summary := sg.GenerateFromMatch(match)
	if summary.NodeCount == 0 {
		t.Error("expected entities")
	}
}

func TestSummaryMarkdown(t *testing.T) {
	as := &AlertSummary{
		Title: "Test Alert", Severity: "CRITICAL",
		AttackPath: "p:1 → p:2",
		KeyEntities: []string{"bash (process)"},
	}
	md := as.Markdown()
	if !strings.Contains(md, "ProvidAPT Alert") {
		t.Errorf("markdown = %s", md)
	}
}

// ── Webhook tests ──────────────────────────────────────────

func TestNewWebhookSender(t *testing.T) {
	ws := NewWebhookSender(nil)
	if ws == nil {
		t.Fatal("NewWebhookSender returned nil")
	}
}

func TestSendNoURL(t *testing.T) {
	ws := NewWebhookSender(nil)
	err := ws.Send(&AlertSummary{Title: "test"})
	if err != nil {
		t.Errorf("send without URL: %v", err)
	}
}

// ── Helpers ─────────────────────────────────────────────────

func testGraph(t *testing.T) *provenance.Graph {
	t.Helper()
	g := provenance.NewGraph()
	// Web server (nginx) forks bash
	g.AddEvent(&collector.Event{
		Type: syscall.EventProcessFork, TimestampNS: 1000,
		PID: 100, ChildPID: 101, Comm: "nginx",
	})
	// Bash executes
	g.AddEvent(&collector.Event{
		Type: syscall.EventProcessExec, TimestampNS: 2000,
		PID: 101, Comm: "bash", Pathname: "/tmp/evil.sh",
		Inode: 5000, DevMajor: 8, DevMinor: 3,
	})
	// Bash writes to /etc/passwd
	g.AddEvent(&collector.Event{
		Type: syscall.EventFileModify, TimestampNS: 3000,
		PID: 101, Comm: "bash", Pathname: "/etc/passwd",
		Inode: 5001, DevMajor: 8, DevMinor: 3,
	})
	return g
}

func TestAlertPipeline(t *testing.T) {
	g := testGraph(t)
	pipe := NewAlertPipeline(g, "")
	if pipe == nil {
		t.Fatal("NewAlertPipeline returned nil")
	}
	pipe.Tick(g)
	t.Log("Pipeline tick completed")
}

func TestPatternMatchingIntegration(t *testing.T) {
	g := testGraph(t)
	pm := NewPatternMatcher()
	matches := pm.MatchAll(g)

	for _, m := range matches {
		t.Logf("Pattern: %s, path: %s", m.Pattern.Name, strings.Join(m.Nodes, " → "))

		im := NewIncidentManager()
		inc := im.Ingest(m)
		if inc != nil {
			t.Logf("Incident: %s", inc.Summary())

			sg := NewSummaryGenerator(g)
			summary := sg.Generate(inc)
			t.Logf("Summary: %s", summary.Text())
		}
	}
}
