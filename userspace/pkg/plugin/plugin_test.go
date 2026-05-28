package plugin

import (
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/plugin/scoring"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/plugin/sigma"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/plugin/threatintel"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/internal/syscall"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/provenance"
)

// ── Plugin registry tests ───────────────────────────────────

func TestRegisterAndGet(t *testing.T) {
	p := &dummyPlugin{name: "test"}
	err := Register(p)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	got := Get("test")
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if got.Name() != "test" {
		t.Errorf("Name = %q", got.Name())
	}
}

func TestRegisterDuplicate(t *testing.T) {
	p := &dummyPlugin{name: "dup"}
	err := Register(p)
	if err != nil {
		t.Fatalf("first register: %v", err)
	}
	err = Register(p)
	if err == nil {
		t.Error("expected error for duplicate registration")
	}
}

func TestList(t *testing.T) {
	names := List()
	if len(names) == 0 {
		t.Log("no plugins registered (expected in isolation)")
	}
}

type dummyPlugin struct {
	name string
}

func (d *dummyPlugin) Name() string { return d.name }
func (d *dummyPlugin) Analyse(snap *provenance.Graph) []*Finding {
	return nil
}

// ── Sigma rule tests ────────────────────────────────────────

func TestSigmaParseRule(t *testing.T) {
	rule, err := sigma.ParseRule([]byte(`
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

func TestSigmaRulesDefault(t *testing.T) {
	rules := sigma.DefaultRules()
	if len(rules) == 0 {
		t.Error("expected at least 1 default rule")
	} else {
		t.Logf("loaded %d default sigma rules", len(rules))
		for _, r := range rules {
			t.Logf("  %s [%s]", r.Title, r.Level)
		}
	}
}

func TestSigmaMatchShadowAccess(t *testing.T) {
	// Build graph: cat reads /etc/shadow
	g := buildGraph([]*collector.Event{
		makeEvent(syscall.EventFileOpen, 100, 0, "cat", "/etc/shadow"),
	})

	plugin := sigma.NewDefaultPlugin()
	if plugin == nil {
		t.Skip("no default plugin (rules may not have loaded)")
	}

	findings := plugin.Analyse(g)
	t.Logf("sigma findings for shadow access: %d", len(findings))
	for _, f := range findings {
		t.Logf("  %s (severity=%s, score=%.0f)", f.Title, f.Severity, f.Score)
	}
}

// ── Threat intel tests ──────────────────────────────────────

func TestThreatIntelAddMatch(t *testing.T) {
	cache := threatintel.NewCache()
	cache.Add(threatintel.IOC{
		Type:   threatintel.IOCIP,
		Value:  "5.6.7.8",
		Label:  "known C2 server",
		Source: "test",
	})

	iocs := cache.MatchIP("5.6.7.8")
	if len(iocs) != 1 {
		t.Fatalf("expected 1 match, got %d", len(iocs))
	}
	if iocs[0].Label != "known C2 server" {
		t.Errorf("Label = %q", iocs[0].Label)
	}
}

func TestThreatIntelCIDRMatch(t *testing.T) {
	cache := threatintel.NewCache()
	cache.Add(threatintel.IOC{
		Type:  threatintel.IOCIP,
		Value: "10.0.0.0/8",
		Label: "internal RFC1918 (for testing)",
	})

	iocs := cache.MatchIP("10.1.2.3")
	if len(iocs) == 0 {
		t.Error("expected CIDR match")
	}
}

func TestThreatIntelNoMatch(t *testing.T) {
	cache := threatintel.NewCache()
	cache.Add(threatintel.IOC{Type: threatintel.IOCIP, Value: "1.2.3.4"})
	iocs := cache.MatchIP("9.9.9.9")
	if len(iocs) != 0 {
		t.Error("expected no match")
	}
}

func TestThreatIntelDomain(t *testing.T) {
	cache := threatintel.NewCache()
	cache.Add(threatintel.IOC{
		Type:  threatintel.IOCDomain,
		Value: "evil.com",
	})
	iocs := cache.MatchDomain("evil.com")
	if len(iocs) != 1 {
		t.Errorf("expected 1 domain match, got %d", len(iocs))
	}
}

func TestThreatIntelLoadCSV(t *testing.T) {
	cache := threatintel.NewCache()
	// Without a real CSV file, this is a no-op test
	_ = cache
}

// ── Scoring tests ───────────────────────────────────────────

func TestScoringEmpty(t *testing.T) {
	engine := scoring.New()
	result := engine.Score(nil, provenance.NewGraph())
	if result.RiskLevel != "NONE" {
		t.Errorf("expected NONE, got %s", result.RiskLevel)
	}
}

func TestScoringSingleDimension(t *testing.T) {
	engine := scoring.New()
	findings := []*Finding{
		{Title: "Suspicious Network Connection", Score: 8, PluginName: "sigma"},
	}
	result := engine.Score(findings, provenance.NewGraph())
	if result.HitCount != 1 {
		t.Errorf("HitCount = %d, want 1", result.HitCount)
	}
	if result.Multiplier != 1.0 {
		t.Errorf("Multiplier = %.1f, want 1.0", result.Multiplier)
	}
}

func TestScoringMultiDimension(t *testing.T) {
	engine := scoring.New()
	findings := []*Finding{
		{Title: "Suspicious Network Connection", Score: 8, PluginName: "sigma"},
		{Title: "Suspicious Shadow File Access", Score: 8, PluginName: "sigma"},
		{Title: "Privilege Escalation via setuid", Score: 7, PluginName: "sigma"},
	}
	result := engine.Score(findings, provenance.NewGraph())
	t.Logf("Multi-dim score: total=%.1f, hits=%d, mult=%.1f, level=%s",
		result.TotalScore, result.HitCount, result.Multiplier, result.RiskLevel)

	if result.HitCount < 2 {
		t.Error("expected at least 2 dimension hits")
	}
	// Multiplier should be > 1 for multiple dimensions
	if result.Multiplier <= 1.0 {
		t.Error("expected multiplier > 1 for multiple dimensions")
	}
}

func TestScoringThresholds(t *testing.T) {
	engine := scoring.New()
	tests := []struct {
		score float64
		level string
	}{
		{3, "NONE"},
		{8, "LOW"},
		{18, "MEDIUM"},
		{28, "HIGH"},
		{45, "CRITICAL"},
	}
	for _, tt := range tests {
		result := engine.Score([]*Finding{
			{Title: "test", Score: tt.score, PluginName: "test"},
		}, provenance.NewGraph())
		if result.RiskLevel != tt.level {
			t.Errorf("score %.0f: expected %s, got %s", tt.score, tt.level, result.RiskLevel)
		}
	}
}

func TestScoringCeiling(t *testing.T) {
	engine := scoring.New()
	result := engine.Score([]*Finding{
		{Title: "C2 Connection", Score: 10, PluginName: "sigma"},
		{Title: "Sensitive Exfil", Score: 10, PluginName: "sigma"},
		{Title: "Privilege Escalation", Score: 10, PluginName: "sigma"},
		{Title: "Persistence via Cron", Score: 10, PluginName: "sigma"},
	}, provenance.NewGraph())
	if result.TotalScore > 100 {
		t.Errorf("score %.0f exceeds ceiling 100", result.TotalScore)
	}
	t.Logf("Ceiling test: score=%.1f, level=%s, dims=%v",
		result.TotalScore, result.RiskLevel, result.ActiveDims)
}

// ── Helpers ─────────────────────────────────────────────────

func buildGraph(events []*collector.Event) *provenance.Graph {
	g := provenance.NewGraph()
	for _, evt := range events {
		g.AddEvent(evt)
	}
	return g
}

func makeEvent(typ syscall.EventType, pid, uid uint32, comm, path string) *collector.Event {
	return &collector.Event{
		Type: typ, TimestampNS: 1000, PID: pid, PPID: 1, UID: uid,
		Comm: comm, Pathname: path, Inode: uint64(pid * 1000),
		DevMajor: 8, DevMinor: 3, Mode: 0644,
	}
}
