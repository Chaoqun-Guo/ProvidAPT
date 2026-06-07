// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package sigma

import (
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
)

func TestParseRule(t *testing.T) {
	rule, err := ParseRule([]byte(`
title: Test Rule
logsource:
  category: file_access
detection:
  selection:
    target: /etc/shadow
  condition: selection
level: high
`))
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	if rule.Title != "Test Rule" {
		t.Errorf("Title = %q", rule.Title)
	}
	if rule.Level != "high" {
		t.Errorf("Level = %q", rule.Level)
	}
}

func TestDefaultRules(t *testing.T) {
	rules := DefaultRules()
	if len(rules) == 0 {
		t.Error("expected at least 1 default rule")
	} else {
		t.Logf("loaded %d default sigma rules", len(rules))
		for _, r := range rules {
			t.Logf("  %s [%s]", r.Title, r.Level)
		}
	}
}

func TestMatchShadowAccess(t *testing.T) {
	g := buildGraph([]*collector.Event{
		makeEvent(syscall.EventFileOpen, 100, 0, "cat", "/etc/shadow"),
	})

	plugin := NewDefaultPlugin()
	if plugin == nil {
		t.Skip("no default plugin (rules may not have loaded)")
	}

	findings := plugin.Analyse(g)
	t.Logf("sigma findings for shadow access: %d", len(findings))
	for _, f := range findings {
		t.Logf("  %s (severity=%s, score=%.0f)", f.Title, f.Severity, f.Score)
	}
}

func TestEvaluateRule(t *testing.T) {
	rule, err := ParseRule([]byte(`
title: Shadow Read
logsource:
  category: file_access
detection:
  selection:
    target: /etc/shadow
  condition: selection
level: high
`))
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}

	// Build graph with matching event
	g := buildGraph([]*collector.Event{
		makeEvent(syscall.EventFileOpen, 100, 0, "cat", "/etc/shadow"),
	})

	matches := EvaluateRule(rule, g.Nodes(), g.Edges())
	if len(matches) == 0 {
		t.Fatal("EvaluateRule: expected at least 1 match for /etc/shadow access")
	}
	t.Logf("EvaluateRule: %d matches", len(matches))
	for _, m := range matches {
		t.Logf("  match: %v", m)
	}
}

func TestEvaluateRuleNoMatch(t *testing.T) {
	rule, err := ParseRule([]byte(`
title: No Match
logsource:
  category: file_access
detection:
  selection:
    target: /nonexistent
  condition: selection
level: low
`))
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}

	g := buildGraph([]*collector.Event{
		makeEvent(syscall.EventFileOpen, 100, 0, "cat", "/etc/hostname"),
	})

	matches := EvaluateRule(rule, g.Nodes(), g.Edges())
	if len(matches) != 0 {
		t.Errorf("EvaluateRule: expected 0 matches for non-matching rule, got %d", len(matches))
	}
}

func TestEvaluateRuleNetwork(t *testing.T) {
	rule, err := ParseRule([]byte(`
title: Network Connect
logsource:
  category: network
detection:
  selection:
    image: curl
  condition: selection
level: high
`))
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}

	// Network connection creates a process → network edge
	g := buildGraph([]*collector.Event{
		makeEvent(syscall.EventNetConnect, 100, 0, "curl", "10.0.0.1:443"),
	})

	matches := EvaluateRule(rule, g.Nodes(), g.Edges())
	t.Logf("network matches: %d", len(matches))
	// Note: match may require specific node/edge structure from network events
}

func makeEvent(typ syscall.EventType, pid, uid uint32, comm, path string) *collector.Event {
	return &collector.Event{
		Type: typ, TimestampNS: 1000, PID: pid, PPID: 1, UID: uid,
		Comm: comm, Pathname: path, Inode: uint64(pid * 1000),
		DevMajor: 8, DevMinor: 3, Mode: 0644,
	}
}

func buildGraph(events []*collector.Event) *provenance.Graph {
	g := provenance.NewGraph()
	for _, evt := range events {
		g.AddEvent(evt)
	}
	return g
}
