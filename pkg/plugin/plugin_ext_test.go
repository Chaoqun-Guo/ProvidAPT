package plugin

import (
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ─── Get, List, Manager ───────────────────────────────────────

func TestGetNilForUnknown(t *testing.T) {
	if got := Get("nonexistent-plugin"); got != nil {
		t.Error("expected nil for unknown plugin")
	}
}

func TestPluginManagerRunAll(t *testing.T) {
	Register(&dummyPlugin{name: "mgr-test-a"})
	Register(&dummyPlugin{name: "mgr-test-b"})

	pm := NewManager([]string{"mgr-test-a", "mgr-test-b"})
	findings := pm.RunAll(&provenance.Graph{}) // dummy returns nil
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestPluginManagerRunAllSkipsNil(t *testing.T) {
	pm := NewManager([]string{"not-registered"})
	findings := pm.RunAll(&provenance.Graph{})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil plugin, got %d", len(findings))
	}
}

// ─── Finding ──────────────────────────────────────────────────

func TestFindingString(t *testing.T) {
	f := &Finding{
		PluginName: "test-plugin",
		Title:      "suspicious activity",
		Severity:   "HIGH",
		Score:      8.5,
		NodeIDs:    []string{"p:100", "f:200"},
	}
	s := f.String()
	if s == "" {
		t.Error("empty string")
	}
	t.Logf("Finding: %s", s)
}

// ─── Node helpers ─────────────────────────────────────────────

func TestNodeLabelMatch(t *testing.T) {
	n := &provenance.Node{Label: "/etc/shadow"}
	if !NodeLabelMatch(n, "SHADOW") {
		t.Error("expected case-insensitive match")
	}
	if NodeLabelMatch(n, "passwd") {
		t.Error("expected no match")
	}
}

func TestNodeLabelMatchEmptyLabel(t *testing.T) {
	n := &provenance.Node{Label: ""}
	if NodeLabelMatch(n, "anything") {
		t.Error("empty label should not match")
	}
}

func TestNodeAttrString(t *testing.T) {
	n := &provenance.Node{
		Attributes: map[string]interface{}{
			"uid":   "1000",
			"count": 42,
		},
	}
	if v := NodeAttrString(n, "uid"); v != "1000" {
		t.Errorf("uid = %q", v)
	}
	if v := NodeAttrString(n, "count"); v != "42" {
		t.Errorf("count = %q", v)
	}
	if v := NodeAttrString(n, "missing"); v != "" {
		t.Errorf("missing = %q", v)
	}
}

func TestNodeAttrStringNilNode(t *testing.T) {
	if v := NodeAttrString(nil, "anything"); v != "" {
		t.Errorf("expected empty for nil node, got %q", v)
	}
}
