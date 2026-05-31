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

// ── Helpers ──────────────────────────────────────────────────

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
