// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package sigma

import (
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
)

func TestName(t *testing.T) {
	p := &SigmaPlugin{}
	if n := p.Name(); n != "sigma" {
		t.Errorf("Name() = %q, want %q", n, "sigma")
	}
}

func TestDefaultRulesCount(t *testing.T) {
	rules := DefaultRules()
	if len(rules) != 5 {
		t.Errorf("DefaultRules() returned %d rules, want 5", len(rules))
	}
}

func TestDefaultRulesHaveRequiredFields(t *testing.T) {
	for _, r := range DefaultRules() {
		if r.ID == "" {
			t.Error("rule missing ID")
		}
		if r.Title == "" {
			t.Errorf("rule %q missing Title", r.ID)
		}
		if r.Severity == "" {
			t.Errorf("rule %q missing Severity", r.ID)
		}
	}
}

func TestSeverityScore(t *testing.T) {
	tests := []struct {
		sev  string
		want float64
	}{
		{"CRITICAL", 50},
		{"critical", 50},
		{"HIGH", 40},
		{"high", 40},
		{"MEDIUM", 30},
		{"medium", 30},
		{"LOW", 20},
		{"low", 20},
		{"UNKNOWN", 10},
		{"", 10},
	}
	for _, tt := range tests {
		got := severityScore(tt.sev)
		if got != tt.want {
			t.Errorf("severityScore(%q) = %v, want %v", tt.sev, got, tt.want)
		}
	}
}

func TestRuleFromMap(t *testing.T) {
	m := map[string]interface{}{
		"id":       "test-001",
		"title":    "Test Rule",
		"severity": "HIGH",
		"detection": map[string]interface{}{
			"node_label":    "httpd",
			"node_type":     "prov:Activity",
			"edge_relation": "used",
		},
	}
	r := ruleFromMap(m)
	if r.ID != "test-001" {
		t.Errorf("id = %q", r.ID)
	}
	if r.Title != "Test Rule" {
		t.Errorf("title = %q", r.Title)
	}
	if r.Severity != "HIGH" {
		t.Errorf("severity = %q", r.Severity)
	}
	if r.Detection.NodeLabel != "httpd" {
		t.Errorf("node_label = %q", r.Detection.NodeLabel)
	}
}

func TestRuleFromMapEmpty(t *testing.T) {
	r := ruleFromMap(nil)
	if r.ID != "" {
		t.Error("expected empty rule from nil map")
	}
	r = ruleFromMap(map[string]interface{}{})
	if r.ID != "" {
		t.Error("expected empty rule from empty map")
	}
}

func TestRuleFromMapPartial(t *testing.T) {
	m := map[string]interface{}{
		"id":    "partial-001",
		"title": "Partial Rule",
	}
	r := ruleFromMap(m)
	if r.ID != "partial-001" {
		t.Errorf("id = %q", r.ID)
	}
	if r.Detection.NodeLabel != "" {
		t.Error("expected empty detection for partial map")
	}
}

func TestInitNilConfig(t *testing.T) {
	p := &SigmaPlugin{}
	if err := p.Init(nil); err != nil {
		t.Fatalf("Init(nil) failed: %v", err)
	}
	if len(p.rules) != 5 {
		t.Errorf("expected 5 default rules, got %d", len(p.rules))
	}
}

func TestInitCustomRules(t *testing.T) {
	p := &SigmaPlugin{}
	cfg := map[string]interface{}{
		"rules": []interface{}{
			map[string]interface{}{
				"id":       "custom-001",
				"title":    "Custom Rule",
				"severity": "CRITICAL",
				"detection": map[string]interface{}{
					"node_label": "evil",
				},
			},
		},
	}
	if err := p.Init(cfg); err != nil {
		t.Fatalf("Init(custom) failed: %v", err)
	}
	if len(p.rules) != 6 {
		t.Errorf("expected 6 rules (5 default + 1 custom), got %d", len(p.rules))
	}
	found := false
	for _, r := range p.rules {
		if r.ID == "custom-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("custom rule not found in rules list")
	}
}

func TestShutdown(t *testing.T) {
	p := &SigmaPlugin{}
	p.Init(nil)
	if err := p.Shutdown(); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
	if p.rules != nil {
		t.Error("rules not nil after shutdown")
	}
}

func TestAnalyseReturnsFindings(t *testing.T) {
	p := &SigmaPlugin{}
	p.Init(nil)

	snap := provenance.NewGraph()
	snap.AddEvent(fakeExecEvent(100, "httpd"))
	snap.AddEvent(fakeExecEvent(200, "bash"))
	snap.AddEvent(fakeForkEvent(200, 201, "bash"))

	findings := p.Analyse(snap)
	t.Logf("Found %d findings", len(findings))
	for _, f := range findings {
		if f.PluginName != "sigma" {
			t.Errorf("finding plugin = %q", f.PluginName)
		}
		if f.Title == "" {
			t.Error("finding missing title")
		}
		if f.Severity == "" {
			t.Error("finding missing severity")
		}
		if f.Score <= 0 {
			t.Errorf("finding score = %v", f.Score)
		}
	}
}

func TestAnalyseEmptyGraph(t *testing.T) {
	p := &SigmaPlugin{}
	p.Init(nil)

	snap := provenance.NewGraph()
	findings := p.Analyse(snap)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on empty graph, got %d", len(findings))
	}
}

func TestAnalyseAfterShutdown(t *testing.T) {
	p := &SigmaPlugin{}
	p.Init(nil)
	p.Shutdown()

	snap := provenance.NewGraph()
	snap.AddEvent(fakeExecEvent(100, "httpd"))
	findings := p.Analyse(snap)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings after shutdown, got %d", len(findings))
	}
}

// ─── Helpers ────────────────────────────────────────────

func fakeExecEvent(pid uint32, comm string) *collector.Event {
	return &collector.Event{
		Type:        syscall.EventProcessExec,
		PID:         pid,
		Comm:        comm,
		Pathname:    "/usr/bin/" + comm,
		UID:         1000,
		TimestampNS: uint64(pid) * 1000,
	}
}

func fakeForkEvent(parentPID, childPID uint32, comm string) *collector.Event {
	return &collector.Event{
		Type:        syscall.EventProcessFork,
		PID:         parentPID,
		ChildPID:    childPID,
		Comm:        comm,
		UID:         1000,
		TimestampNS: uint64(parentPID)*1000 + 500,
	}
}
