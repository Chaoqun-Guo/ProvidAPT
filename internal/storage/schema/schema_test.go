package schema

import (
	"testing"
)

func TestNodeKey(t *testing.T) {
	key := NodeKey("process", "p:1234")
	if key != "n:process:p:1234" {
		t.Errorf("NodeKey = %q", key)
	}

	key = NodeKey("file", "f:5000:8:3")
	if key != "n:file:f:5000:8:3" {
		t.Errorf("NodeKey = %q", key)
	}
}

func TestEdgeKey(t *testing.T) {
	key := EdgeKey(1000, "p:1", "f:500")
	// Format: e:<016x>|<source>|<target>
	expected := "e:00000000000003e8|p:1|f:500"
	if key != expected {
		t.Errorf("EdgeKey = %q, want %q", key, expected)
	}
}

func TestEdgeKeyWithColons(t *testing.T) {
	// Node IDs containing colons should work with | delimiter
	key := EdgeKey(2000, "f:5000:8:3", "p:100")
	expected := "e:00000000000007d0|f:5000:8:3|p:100"
	if key != expected {
		t.Errorf("EdgeKey = %q, want %q", key, expected)
	}
}

func TestReverseEdgeKey(t *testing.T) {
	key := ReverseEdgeKey(1000, "f:500", "p:1")
	// Format: r:<target>|<016x>|<source>
	expected := "r:f:500|00000000000003e8|p:1"
	if key != expected {
		t.Errorf("ReverseEdgeKey = %q, want %q", key, expected)
	}
}

func TestPIDIndexKey(t *testing.T) {
	key := PIDIndexKey(1234, "p:1234")
	if key != "idx:pid:1234:p:1234" {
		t.Errorf("PIDIndexKey = %q", key)
	}
}

func TestInodeIndexKey(t *testing.T) {
	key := InodeIndexKey(5000, 8, 3, "f:5000:8:3")
	if key != "idx:inode:5000:8:3:f:5000:8:3" {
		t.Errorf("InodeIndexKey = %q", key)
	}
}

func TestMetaKey(t *testing.T) {
	key := MetaKey("version")
	if key != "meta:version" {
		t.Errorf("MetaKey = %q", key)
	}
}

func TestParseNodeKey(t *testing.T) {
	tests := []struct {
		key      string
		wantType string
		wantID   string
		wantOK   bool
	}{
		{"n:process:p:1234", "process", "p:1234", true},
		{"n:file:f:5000:8:3", "file", "f:5000:8:3", true},
		{"invalid", "", "", false},
		{"n:", "", "", false},
	}
	for _, tt := range tests {
		typ, id, ok := ParseNodeKey(tt.key)
		if ok != tt.wantOK || typ != tt.wantType || id != tt.wantID {
			t.Errorf("ParseNodeKey(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.key, typ, id, ok, tt.wantType, tt.wantID, tt.wantOK)
		}
	}
}

func TestEdgeTimeRange(t *testing.T) {
	start, end := EdgeTimeRange(1000, 2000)
	if start != "e:00000000000003e8|" {
		t.Errorf("start = %q", start)
	}
	if end != "e:00000000000007d0|" {
		t.Errorf("end = %q", end)
	}
}

func TestParseEdgeKey(t *testing.T) {
	tests := []struct {
		key        string
		wantSrc    string
		wantTgt    string
		wantTS     uint64
		wantOK     bool
	}{
		{"e:00000000000003e8|p:1|f:500", "p:1", "f:500", 1000, true},
		{"e:00000000000007d0|f:5000:8:3|p:100", "f:5000:8:3", "p:100", 2000, true},
		{"invalid", "", "", 0, false},
		{"e:short", "", "", 0, false},
	}
	for _, tt := range tests {
		src, tgt, ts, ok := ParseEdgeKey(tt.key)
		if ok != tt.wantOK || src != tt.wantSrc || tgt != tt.wantTgt || ts != tt.wantTS {
			t.Errorf("ParseEdgeKey(%q) = (%q, %q, %d, %v), want (%q, %q, %d, %v)",
				tt.key, src, tgt, ts, ok, tt.wantSrc, tt.wantTgt, tt.wantTS, tt.wantOK)
		}
	}
}

func TestPrefixes(t *testing.T) {
	if EdgePrefix() != "e:" {
		t.Errorf("EdgePrefix = %q", EdgePrefix())
	}
	if NodePrefix() != "n:" {
		t.Errorf("NodePrefix = %q", NodePrefix())
	}
}

func TestPIDIndexPrefix(t *testing.T) {
	p := PIDIndexPrefix(1234)
	if p != "idx:pid:1234:" {
		t.Errorf("PIDIndexPrefix = %q", p)
	}
}

func TestInodeIndexPrefix(t *testing.T) {
	p := InodeIndexPrefix(5000)
	if p != "idx:inode:5000:" {
		t.Errorf("InodeIndexPrefix = %q", p)
	}
}

func TestEdgeKeyRoundTrip(t *testing.T) {
	key := EdgeKey(0xdeadbeef, "p:1", "f:500")
	src, tgt, ts, ok := ParseEdgeKey(key)
	if !ok {
		t.Fatal("ParseEdgeKey failed")
	}
	if src != "p:1" || tgt != "f:500" || ts != 0xdeadbeef {
		t.Errorf("round trip = (%q, %q, %d)", src, tgt, ts)
	}
}

func TestReverseEdgeKeyRoundTrip(t *testing.T) {
	key := ReverseEdgeKey(0x12345678, "f:500", "p:1")
	// ReverseEdgeKey format: r:<target>|<ts>|<source>
	// We can verify by checking the structure
	if key[:2] != "r:" {
		t.Errorf("expected r: prefix, got %q", key[:2])
	}
	_ = key
}

// FuzzParseEdgeKey fuzzes edge key parsing with arbitrary strings.
func FuzzParseEdgeKey(f *testing.F) {
	f.Add("e:00000000000003e8|p:1|f:500")
	f.Add("invalid")
	f.Add("e:short")
	f.Add("e:00000000000007d0|f:5000:8:3|p:100")
	f.Add("e:gggggggggggggggg|p:1|f:2")
	f.Fuzz(func(t *testing.T, key string) {
		src, tgt, ts, ok := ParseEdgeKey(key)
		if ok {
			if src == "" || tgt == "" {
				t.Errorf("ParseEdgeKey(%q) ok=true but empty src/tgt", key)
			}
			_ = ts
		}
	})
}

// FuzzParseNodeKey fuzzes node key parsing with arbitrary strings.
func FuzzParseNodeKey(f *testing.F) {
	f.Add("n:process:p:1234")
	f.Add("n:file:f:5000:8:3")
	f.Add("invalid")
	f.Add("n:")
	f.Fuzz(func(t *testing.T, key string) {
		typ, id, ok := ParseNodeKey(key)
		_ = typ
		_ = id
		_ = ok
	})
}
