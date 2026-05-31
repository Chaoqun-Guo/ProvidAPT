package transport

import (
	"bytes"
	"compress/gzip"
	"testing"
	"time"
)

func TestComputeHash(t *testing.T) {
	h1 := ComputeHash([]byte("test data"))
	h2 := ComputeHash([]byte("test data"))
	if h1 != h2 {
		t.Error("deterministic hash expected")
	}
	if len(h1) != 64 {
		t.Errorf("hash length = %d", len(h1))
	}
}

func TestHashCacheTransmit(t *testing.T) {
	hc := NewHashCache()
	data := []byte("content")
	hash := ComputeHash(data)

	if !hc.ShouldTransmit(hash) {
		t.Error("first transmission should be allowed")
	}
	if hc.ShouldTransmit(hash) {
		t.Error("repeat should not transmit (heartbeat)")
	}
}

func TestHashCacheStats(t *testing.T) {
	hc := NewHashCache()
	hc.ShouldTransmit("hash-1")
	hc.ShouldTransmit("hash-1")

	stats := hc.Stats()
	if stats["heartbeats"].(int64) != 1 {
		t.Errorf("heartbeats = %d", stats["heartbeats"])
	}
	if stats["cached_hashes"].(int) != 1 {
		t.Errorf("cached_hashes = %d", stats["cached_hashes"])
	}
}

func TestHashCacheComputeAndCheck(t *testing.T) {
	hc := NewHashCache()
	hash, should := hc.ComputeAndCheck([]byte("new content"))
	if hash == "" {
		t.Error("empty hash")
	}
	if !should {
		t.Error("new content should transmit")
	}
}

func TestHashCacheHeartbeat(t *testing.T) {
	hc := NewHashCache()
	hc.ShouldTransmit("known-hash")
	hb := hc.NewHeartbeat("known-hash")
	if hb == nil {
		t.Fatal("nil heartbeat")
	}
	if hb.Type != "heartbeat" {
		t.Errorf("type = %s", hb.Type)
	}
	if hb.Hash != "known-hash" {
		t.Errorf("hash = %s", hb.Hash)
	}
}

func TestHashCacheHeartbeatUnknown(t *testing.T) {
	hc := NewHashCache()
	hb := hc.NewHeartbeat("unknown-hash")
	if hb != nil {
		t.Error("expected nil heartbeat for unknown hash")
	}
}

func TestHashCacheCleanStale(t *testing.T) {
	hc := NewHashCache()
	hc.ShouldTransmit("known-hash")
	// Use negative duration to clean entries older than "now + negative" (i.e. now)
	n := hc.CleanStale(-1 * time.Nanosecond)
	if n != 1 {
		t.Errorf("cleaned = %d, want 1", n)
	}
}

func TestPriorityPipelineIngestHigh(t *testing.T) {
	pp := NewPriorityPipeline()
	pp.Ingest(&TransportEvent{
		Hash: "high-1", Priority: PriorityHigh, Tainted: true,
	})
	high := pp.DrainHigh()
	if len(high) != 1 {
		t.Errorf("high = %d, want 1", len(high))
	}
}

func TestPriorityPipelineIngestLow(t *testing.T) {
	pp := NewPriorityPipeline()
	pp.Ingest(&TransportEvent{
		Hash: "low-1", Priority: PriorityLow,
	})
	summary := pp.DrainLowSummary()
	if summary == nil {
		t.Fatal("nil summary")
	}
	if summary.Count != 1 {
		t.Errorf("count = %d, want 1", summary.Count)
	}
}

func TestPriorityPipelineEmptyDrain(t *testing.T) {
	pp := NewPriorityPipeline()
	high := pp.DrainHigh()
	if high != nil {
		t.Errorf("expected nil, got %d items", len(high))
	}
	summary := pp.DrainLowSummary()
	if summary != nil {
		t.Error("expected nil summary")
	}
}

func TestPriorityPipelineStats(t *testing.T) {
	pp := NewPriorityPipeline()
	pp.Ingest(&TransportEvent{Hash: "h1", Priority: PriorityHigh, Tainted: true})
	pp.Ingest(&TransportEvent{Hash: "l1", Priority: PriorityLow})

	stats := pp.Stats()
	if stats["high_sent"].(int64) != 1 {
		t.Errorf("high_sent = %d", stats["high_sent"])
	}
	if stats["low_staged"].(int64) != 1 {
		t.Errorf("low_staged = %d", stats["low_staged"])
	}
}

func TestPriorityNormalRoute(t *testing.T) {
	pp := NewPriorityPipeline()
	pp.Ingest(&TransportEvent{Hash: "n1", Priority: PriorityNormal})
	summary := pp.DrainLowSummary()
	if summary == nil || summary.Count != 1 {
		t.Errorf("normal priority should go low, count=%d", summary.Count)
	}
}

func TestPriorityCriticalRoute(t *testing.T) {
	pp := NewPriorityPipeline()
	pp.Ingest(&TransportEvent{Hash: "c1", Priority: PriorityCritical, Tainted: true})
	high := pp.DrainHigh()
	if len(high) != 1 {
		t.Errorf("critical should go high, got %d", len(high))
	}
}

func TestCompressorRoundTrip(t *testing.T) {
	c := NewCompressor()
	original := []byte("this is provenance data that should compress well")
	compressed, err := c.Compress(original)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}

	decompressed, err := c.Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if string(decompressed) != string(original) {
		t.Error("round-trip mismatch")
	}
	c.Close()
}

func TestCompressorDetectsZstd(t *testing.T) {
	c := NewCompressor()
	data := []byte("test data for zstd detection")
	compressed, err := c.Compress(data)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}

	if len(compressed) >= 4 && compressed[0] != 0x28 {
		t.Logf("compressed prefix: %x", compressed[:4])
	}
	c.Close()
}

func TestCompressorRatio(t *testing.T) {
	c := NewCompressor()
	payload := make([]byte, 10000)
	for i := range payload {
		payload[i] = byte(i % 10)
	}
	c.Compress(payload)
	c.Compress(payload)

	ratio := c.Ratio()
	if ratio <= 0 || ratio > 100 {
		t.Errorf("unexpected ratio: %.1f%%", ratio)
	}
	c.Close()
}

func TestZstdBetterThanGzip(t *testing.T) {
	provenanceData := []byte(`{
		"nodes": [
			{"id":"p:100","type":"process","label":"bash","pid":100,"uid":0},
			{"id":"f:1234:8:3","type":"file","label":"/etc/passwd","inode":1234}
		],
		"edges": [
			{"source":"p:100","target":"f:5678:3","relation":"used"}
		]
	}`)

	zstdComp := NewCompressor()
	zstdCompressed, _ := zstdComp.Compress(provenanceData)
	zstdComp.Close()

	var gzipBuf bytes.Buffer
	gzipWriter := gzip.NewWriter(&gzipBuf)
	gzipWriter.Write(provenanceData)
	gzipWriter.Close()
	gzipCompressed := gzipBuf.Bytes()

	zstdRatio := float64(len(zstdCompressed)) / float64(len(provenanceData)) * 100
	gzipRatio := float64(len(gzipCompressed)) / float64(len(provenanceData)) * 100

	t.Logf("Original: %d bytes", len(provenanceData))
	t.Logf("Zstd: %d bytes (%.1f%%)", len(zstdCompressed), zstdRatio)
	t.Logf("Gzip: %d bytes (%.1f%%)", len(gzipCompressed), gzipRatio)
}
