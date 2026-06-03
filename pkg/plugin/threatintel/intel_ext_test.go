package threatintel

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ─── Add/Match edge cases ────────────────────────────────────

func TestAddIPAndMatchDirect(t *testing.T) {
	c := NewCache()
	c.Add(IOC{Type: IOCIP, Value: "192.168.1.1", Label: "test-ip"})
	iocs := c.MatchIP("192.168.1.1")
	if len(iocs) != 1 {
		t.Fatalf("expected 1 match, got %d", len(iocs))
	}
	if iocs[0].Label != "test-ip" {
		t.Errorf("label = %q", iocs[0].Label)
	}
}

func TestAddDomainAndMatch(t *testing.T) {
	c := NewCache()
	c.Add(IOC{Type: IOCDomain, Value: "malware.example.com"})
	iocs := c.MatchDomain("malware.example.com")
	if len(iocs) != 1 {
		t.Fatalf("expected 1 match, got %d", len(iocs))
	}
}

func TestMatchDomainNotFound(t *testing.T) {
	c := NewCache()
	c.Add(IOC{Type: IOCDomain, Value: "evil.com"})
	iocs := c.MatchDomain("benign.com")
	if len(iocs) != 0 {
		t.Error("expected no match")
	}
}

func TestMatchDomainCaseInsensitive(t *testing.T) {
	c := NewCache()
	// MatchDomain lowercases the query key; entries are stored with original casing.
	c.Add(IOC{Type: IOCDomain, Value: "evil.com"})
	iocs := c.MatchDomain("EVIL.COM")
	if len(iocs) == 0 {
		t.Error("expected case-insensitive domain match")
	}
}

func TestMatchIPNoMatch(t *testing.T) {
	c := NewCache()
	c.Add(IOC{Type: IOCIP, Value: "10.0.0.1"})
	iocs := c.MatchIP("10.0.0.2")
	if len(iocs) != 0 {
		t.Error("expected no match for different IP")
	}
}

func TestMatchIPInvalid(t *testing.T) {
	c := NewCache()
	iocs := c.MatchIP("not-an-ip")
	if len(iocs) != 0 {
		t.Error("expected no match for invalid IP")
	}
}

// ─── Stats ───────────────────────────────────────────────────

func TestStatsWithFileHash(t *testing.T) {
	c := NewCache()
	c.Add(IOC{Type: IOCIP, Value: "1.2.3.4"})
	c.Add(IOC{Type: IOCDomain, Value: "evil.com"})
	c.Add(IOC{Type: IOCFileHash, Value: "deadbeef"})
	stats := c.Stats()
	if stats["total"] != 3 {
		t.Errorf("total = %d, want 3", stats["total"])
	}
	if stats["hash"] != 1 {
		t.Errorf("hash = %d, want 1", stats["hash"])
	}
}

func TestStatsEmpty(t *testing.T) {
	c := NewCache()
	stats := c.Stats()
	if stats["total"] != 0 {
		t.Errorf("total = %d, want 0", stats["total"])
	}
}

// ─── LoadCSV ─────────────────────────────────────────────────

func TestLoadCSVFromFile(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "iocs.csv")
	csvContent := "ip,10.0.0.1,test ip,csv,0.9\ndomain,evil.com,test domain,csv,0.8\nhash,abc123,test hash,csv,0.7\n"
	if err := os.WriteFile(csvPath, []byte(csvContent), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCache()
	if err := c.LoadCSV(csvPath); err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}

	stats := c.Stats()
	if stats["total"] != 3 {
		t.Errorf("total = %d, want 3", stats["total"])
	}
	if stats["ip"] != 1 {
		t.Errorf("ip = %d", stats["ip"])
	}
	if stats["domain"] != 1 {
		t.Errorf("domain = %d", stats["domain"])
	}
	if stats["hash"] != 1 {
		t.Errorf("hash = %d", stats["hash"])
	}
}

func TestLoadCSVSkippableLines(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "iocs.csv")
	csvContent := "ip,1.2.3.4,good\nunknown,whatever,skip\n"
	if err := os.WriteFile(csvPath, []byte(csvContent), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCache()
	if err := c.LoadCSV(csvPath); err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}

	stats := c.Stats()
	if stats["total"] != 1 {
		t.Errorf("total = %d, want 1", stats["total"])
	}
}

func TestLoadCSVShortLine(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "short.csv")
	csvContent := "ip\n"
	if err := os.WriteFile(csvPath, []byte(csvContent), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCache()
	if err := c.LoadCSV(csvPath); err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}

	stats := c.Stats()
	if stats["total"] != 0 {
		t.Errorf("total = %d, want 0", stats["total"])
	}
}

func TestLoadCSVFileNotFound(t *testing.T) {
	c := NewCache()
	err := c.LoadCSV("/nonexistent/file.csv")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// ─── LoadList ────────────────────────────────────────────────

func TestLoadList(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "blocklist.txt")
	content := "5.6.7.8\n10.0.0.1\n# this is a comment\n\n192.168.1.1\n"
	if err := os.WriteFile(listPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCache()
	if err := c.LoadList(listPath, IOCIP, "test-list"); err != nil {
		t.Fatalf("LoadList: %v", err)
	}

	stats := c.Stats()
	if stats["total"] != 3 {
		t.Errorf("total = %d, want 3", stats["total"])
	}

	iocs := c.MatchIP("5.6.7.8")
	if len(iocs) == 0 {
		t.Error("expected match for loaded IP")
	}
}

func TestLoadListFileNotFound(t *testing.T) {
	c := NewCache()
	err := c.LoadList("/nonexistent/list.txt", IOCIP, "test")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// ─── extractIP ───────────────────────────────────────────────

func TestExtractIP(t *testing.T) {
	tests := []struct {
		label string
		want  string
	}{
		{"192.168.1.1", "192.168.1.1"},
		{"10.0.0.1:443", "10.0.0.1"},
		{"[::1]:80", "::1"},
		{"not-an-ip", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractIP(tt.label)
		if got != tt.want {
			t.Errorf("extractIP(%q) = %q, want %q", tt.label, got, tt.want)
		}
	}
}

// ─── ThreatIntelPlugin ───────────────────────────────────────

func TestThreatIntelPluginName(t *testing.T) {
	p := &ThreatIntelPlugin{Name_: "threat-intel"}
	if p.Name() != "threat-intel" {
		t.Errorf("Name = %q", p.Name())
	}
}

func TestThreatIntelPluginAnalyseNoCache(t *testing.T) {
	p := &ThreatIntelPlugin{Name_: "test"}
	findings := p.Analyse(&provenance.Graph{})
	if len(findings) != 0 {
		t.Error("expected no findings with nil cache")
	}
}

func TestThreatIntelPluginAnalyseWithCache(t *testing.T) {
	c := NewCache()
	c.Add(IOC{Type: IOCIP, Value: "5.6.7.8", Label: "C2", Source: "test", Confidence: 0.95})
	p := &ThreatIntelPlugin{Name_: "threat-intel", Cache: c}
	// Empty graph, no nodes to scan — Analyse returns nil directly.
	findings := p.Analyse(&provenance.Graph{})
	if len(findings) != 0 {
		t.Error("expected no findings for empty graph")
	}
}

// ─── safeGet ─────────────────────────────────────────────────

func TestSafeGet(t *testing.T) {
	rec := []string{"a", "b", "c"}
	if v := safeGet(rec, 0); v != "a" {
		t.Errorf("got %q", v)
	}
	if v := safeGet(rec, 5); v != "" {
		t.Errorf("got %q", v)
	}
	if v := safeGet(rec, 5, "default"); v != "default" {
		t.Errorf("got %q", v)
	}
}
