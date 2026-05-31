package threatintel

import (
	"testing"
)

func TestNewCache(t *testing.T) {
	cache := NewCache()
	if cache == nil {
		t.Fatal("NewCache returned nil")
	}
}

func TestAddMatch(t *testing.T) {
	cache := NewCache()
	cache.Add(IOC{
		Type:   IOCIP,
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

func TestCIDRMatch(t *testing.T) {
	cache := NewCache()
	cache.Add(IOC{
		Type:  IOCIP,
		Value: "10.0.0.0/8",
		Label: "internal RFC1918 (for testing)",
	})

	iocs := cache.MatchIP("10.1.2.3")
	if len(iocs) == 0 {
		t.Error("expected CIDR match")
	}
}

func TestNoMatch(t *testing.T) {
	cache := NewCache()
	cache.Add(IOC{Type: IOCIP, Value: "1.2.3.4"})
	iocs := cache.MatchIP("9.9.9.9")
	if len(iocs) != 0 {
		t.Error("expected no match")
	}
}

func TestDomain(t *testing.T) {
	cache := NewCache()
	cache.Add(IOC{
		Type:  IOCDomain,
		Value: "evil.com",
	})
	iocs := cache.MatchDomain("evil.com")
	if len(iocs) != 1 {
		t.Errorf("expected 1 domain match, got %d", len(iocs))
	}
}

func TestLoadCSV(t *testing.T) {
	cache := NewCache()
	_ = cache
}

func TestStats(t *testing.T) {
	cache := NewCache()
	cache.Add(IOC{Type: IOCIP, Value: "1.2.3.4"})
	cache.Add(IOC{Type: IOCDomain, Value: "evil.com"})
	stats := cache.Stats()
	if stats["total"] != 2 {
		t.Errorf("total = %d, want 2", stats["total"])
	}
	if stats["ip"] != 1 {
		t.Errorf("ip = %d, want 1", stats["ip"])
	}
	if stats["domain"] != 1 {
		t.Errorf("domain = %d, want 1", stats["domain"])
	}
}
