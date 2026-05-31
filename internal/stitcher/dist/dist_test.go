package dist

import (
	"testing"
)

func TestNewGlobalIDStore(t *testing.T) {
	g := NewGlobalIDStore()
	if g == nil {
		t.Fatal("NewGlobalIDStore returned nil")
	}
	if g.HostID() == "" {
		t.Error("empty host ID")
	}
}

func TestGlobalIDStoreGetOrCreate(t *testing.T) {
	g := NewGlobalIDStore()
	guid1 := g.GetOrCreate("local-1")
	if guid1 == nil {
		t.Fatal("nil GUID")
	}
	if guid1.FullID == "" {
		t.Error("empty FullID")
	}
	if guid1.LocalID != "local-1" {
		t.Errorf("local = %s", guid1.LocalID)
	}

	guid2 := g.GetOrCreate("local-1")
	if guid2.FullID != guid1.FullID {
		t.Error("expected same FullID for same local ID")
	}
}

func TestGlobalIDStoreMultiple(t *testing.T) {
	g := NewGlobalIDStore()
	g1 := g.GetOrCreate("local-a")
	g2 := g.GetOrCreate("local-b")
	if g1.FullID == g2.FullID {
		t.Error("expected different FullIDs for different local IDs")
	}
}

func TestResolve(t *testing.T) {
	g := NewGlobalIDStore()
	guid := g.GetOrCreate("resolve-test")

	resolved, ok := Resolve(guid.FullID)
	if !ok {
		t.Error("expected resolution to succeed")
	}
	// Resolve only returns the FullID (one-way hash)
	if resolved.FullID != guid.FullID {
		t.Errorf("full = %s", resolved.FullID)
	}
}

func TestResolveInvalid(t *testing.T) {
	_, ok := Resolve("invalid-format")
	if ok {
		t.Error("expected resolution to fail for short input")
	}

	_, ok = Resolve("")
	if ok {
		t.Error("expected resolution to fail for empty input")
	}
}

func TestNewCompressor(t *testing.T) {
	c := NewCompressor()
	if c == nil {
		t.Fatal("NewCompressor returned nil")
	}
}

func TestCompressorRoundTrip(t *testing.T) {
	c := NewCompressor()
	original := &GUID{
		FullID:  "host1-boot1-local1",
		HostID:  "host1",
		BootID:  "boot1",
		LocalID: "local1",
	}

	compressed := c.Compress(original)
	if compressed == nil {
		t.Fatal("nil compressed")
	}

	decompressed := c.Decompress(compressed)
	if decompressed == nil {
		t.Fatal("nil decompressed")
	}
	// FullID is recomputed from HostID+BootID+LocalID
	if decompressed.HostID != original.HostID {
		t.Errorf("host = %s", decompressed.HostID)
	}
	if decompressed.LocalID != original.LocalID {
		t.Errorf("local = %s", decompressed.LocalID)
	}
}

func TestCompressorStringRoundTrip(t *testing.T) {
	c := NewCompressor()
	// SHA256 hex string = 64 chars
	fullID := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	compressed := c.CompressGUIDString(fullID)
	if len(compressed) != 32 {
		t.Fatalf("expected 32 bytes compressed, got %d", len(compressed))
	}

	decompressed := c.DecompressGUIDString(compressed)
	if decompressed != fullID {
		t.Errorf("round trip: got %s", decompressed)
	}
}

func TestCompressorNonHexString(t *testing.T) {
	c := NewCompressor()
	short := "short-id"
	compressed := c.CompressGUIDString(short)
	// Non-64-char strings pass through unchanged
	decompressed := c.DecompressGUIDString(compressed)
	if decompressed != short {
		t.Errorf("pass through: %s", decompressed)
	}
}

func TestCompressorRatio(t *testing.T) {
	c := NewCompressor()
	// First compress = miss, second = hit
	guid1 := &GUID{HostID: "host1", BootID: "boot1", LocalID: "local1"}
	guid2 := &GUID{HostID: "host1", BootID: "boot1", LocalID: "local2"}

	c.Compress(guid1)
	c.Compress(guid2) // host1 already in dictionary → hit

	ratio := c.CompressionRatio()
	if ratio <= 0 || ratio > 100 {
		t.Errorf("ratio = %.1f%%", ratio)
	}
}

func TestCompressorStats(t *testing.T) {
	c := NewCompressor()
	c.Compress(&GUID{HostID: "host1", BootID: "boot1", LocalID: "local1"})
	stats := c.Stats()
	if stats["dictionary_size"].(int) != 1 {
		t.Errorf("dict size = %d", stats["dictionary_size"])
	}
}

func TestBootID(t *testing.T) {
	g := NewGlobalIDStore()
	// BootID should be non-empty (falls back to time-based)
	bootID := g.BootID()
	if bootID == "" {
		t.Error("expected non-empty boot ID")
	}
}
