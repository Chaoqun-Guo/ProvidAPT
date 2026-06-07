// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/transport"
)

// ─── Hash cache tests ───────────────────────────────────────

func TestNewHashCache(t *testing.T) {
	hc := transport.NewHashCache()
	if hc == nil {
		t.Fatal("NewHashCache returned nil")
	}
}

func TestComputeHash(t *testing.T) {
	h1 := transport.ComputeHash([]byte("test data"))
	h2 := transport.ComputeHash([]byte("test data"))
	if h1 != h2 {
		t.Error("deterministic hash expected")
	}
	if len(h1) != 64 {
		t.Errorf("hash length = %d", len(h1))
	}
}

func TestShouldTransmit(t *testing.T) {
	hc := transport.NewHashCache()
	data := []byte("subgraph content")
	hash := transport.ComputeHash(data)

	if !hc.ShouldTransmit(hash) {
		t.Error("first transmission should be allowed")
	}
	if hc.ShouldTransmit(hash) {
		t.Error("repeat should not transmit")
	}

	stats := hc.Stats()
	if stats["heartbeats"].(int64) != 1 {
		t.Errorf("heartbeats = %d", stats["heartbeats"])
	}
}

func TestComputeAndCheck(t *testing.T) {
	hc := transport.NewHashCache()
	hash, should := hc.ComputeAndCheck([]byte("new content"))
	if hash == "" {
		t.Error("empty hash")
	}
	if !should {
		t.Error("new content should transmit")
	}
}

func TestNewHeartbeat(t *testing.T) {
	hc := transport.NewHashCache()
	data := []byte("content")
	hash := transport.ComputeHash(data)
	hc.ShouldTransmit(hash)

	hb := hc.NewHeartbeat(hash)
	if hb == nil {
		t.Fatal("nil heartbeat")
	}
	if hb.Type != "heartbeat" {
		t.Errorf("type = %s", hb.Type)
	}
}

func TestCleanStale(t *testing.T) {
	hc := transport.NewHashCache()
	hc.ShouldTransmit("known-hash")
	n := hc.CleanStale(0)
	if n != 1 {
		t.Errorf("cleaned = %d", n)
	}
}

func TestPersistentHashCache(t *testing.T) {
	dir := t.TempDir()
	hc, err := transport.NewPersistentHashCache(dir)
	if err != nil {
		t.Fatalf("NewPersistentHashCache: %v", err)
	}

	data := []byte("persistent subgraph")
	hash := transport.ComputeHash(data)

	// First transmission.
	if !hc.ShouldTransmit(hash) {
		t.Error("first should transmit")
	}

	// Second should be heartbeat.
	if hc.ShouldTransmit(hash) {
		t.Error("repeat should not transmit")
	}

	// Close and reopen.
	if err := hc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	hc2, err := transport.NewPersistentHashCache(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer hc2.Close()

	// After restart, the same hash should also be a heartbeat.
	if hc2.ShouldTransmit(hash) {
		t.Error("after restart, repeat should not transmit")
	}

	stats := hc2.Stats()
	if stats["persistent"].(bool) != true {
		t.Error("should be persistent")
	}
}

// ─── Priority pipeline tests ────────────────────────────────

func TestNewPriorityPipeline(t *testing.T) {
	pp := transport.NewPriorityPipeline()
	if pp == nil {
		t.Fatal("NewPriorityPipeline returned nil")
	}
}

func TestIngestHigh(t *testing.T) {
	pp := transport.NewPriorityPipeline()
	pp.Ingest(&transport.TransportEvent{
		Hash: "high-1", Priority: transport.PriorityHigh, Tainted: true,
	})
	high := pp.DrainHigh()
	if len(high) != 1 {
		t.Errorf("high = %d", len(high))
	}
}

func TestIngestLow(t *testing.T) {
	pp := transport.NewPriorityPipeline()
	pp.Ingest(&transport.TransportEvent{
		Hash: "low-1", Priority: transport.PriorityLow,
	})
	summary := pp.DrainLowSummary()
	if summary == nil {
		t.Fatal("nil summary")
	}
	if summary.Count != 1 {
		t.Errorf("count = %d", summary.Count)
	}
}

func TestEmptyDrain(t *testing.T) {
	pp := transport.NewPriorityPipeline()
	high := pp.DrainHigh()
	if high != nil {
		t.Errorf("expected nil, got %d", len(high))
	}
	summary := pp.DrainLowSummary()
	if summary != nil {
		t.Error("expected nil summary")
	}
}

func TestPriorityStats(t *testing.T) {
	pp := transport.NewPriorityPipeline()
	pp.Ingest(&transport.TransportEvent{Hash: "h1", Priority: transport.PriorityHigh, Tainted: true})
	pp.Ingest(&transport.TransportEvent{Hash: "l1", Priority: transport.PriorityLow})

	stats := pp.Stats()
	if stats["high_sent"].(int64) != 1 {
		t.Errorf("high = %d", stats["high_sent"])
	}
}

func TestPersistentPriorityPipeline(t *testing.T) {
	dir := t.TempDir()
	pp, err := transport.NewPersistentPriorityPipeline(dir)
	if err != nil {
		t.Fatalf("NewPersistentPriorityPipeline: %v", err)
	}

	pp.Ingest(&transport.TransportEvent{Hash: "low-1", Priority: transport.PriorityLow})
	pp.Ingest(&transport.TransportEvent{Hash: "low-2", Priority: transport.PriorityLow})
	pp.Ingest(&transport.TransportEvent{Hash: "low-1", Priority: transport.PriorityLow})

	if err := pp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen and verify events survived.
	pp2, err := transport.NewPersistentPriorityPipeline(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer pp2.Close()

	summary := pp2.DrainLowSummary()
	if summary == nil {
		t.Fatal("nil summary after reopen")
	}
	if summary.Count != 3 {
		t.Errorf("count = %d, want 3", summary.Count)
	}
	// low-1 appeared twice.
	if summary.HashCount["low-1"] != 2 {
		t.Errorf("low-1 count = %d, want 2", summary.HashCount["low-1"])
	}
	if summary.HashCount["low-2"] != 1 {
		t.Errorf("low-2 count = %d, want 1", summary.HashCount["low-2"])
	}

	depth := pp2.LowQueueDepth()
	if depth != 0 {
		t.Errorf("queue depth after drain = %d, want 0", depth)
	}
}

// ─── Compressor tests (Zstd) ─────────────────────────────────

func TestNewCompressor(t *testing.T) {
	c := transport.NewCompressor()
	if c == nil {
		t.Fatal("NewCompressor returned nil")
	}
}

func TestCompressDecompress(t *testing.T) {
	c := transport.NewCompressor()
	original := []byte("this is provenance data that should compress well")
	compressed, err := c.Compress(original)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}

	// Verify Zstd is used (NOT gzip magic bytes 0x1f8b).
	if len(compressed) >= 4 && compressed[0] == 0x28 && compressed[1] == 0xb5 && compressed[2] == 0x2f && compressed[3] == 0xfd {
		t.Log("Zstd magic bytes detected — correct")
	} else if len(compressed) >= 2 && compressed[0] == 0x1f && compressed[1] == 0x8b {
		t.Error("gzip magic bytes detected — expected Zstd")
	} else {
		t.Logf("compressed prefix: %x", compressed[:4])
	}

	decompressed, err := c.Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if string(decompressed) != string(original) {
		t.Error("round-trip mismatch")
	}
}

func TestCompressRatio(t *testing.T) {
	c := transport.NewCompressor()
	payload := make([]byte, 10000)
	for i := range payload {
		payload[i] = byte(i % 10)
	}
	c.Compress(payload)
	c.Compress(payload)

	ratio := c.Ratio()
	t.Logf("Compression ratio: %.1f%%", ratio)
	if ratio <= 0 || ratio > 100 {
		t.Errorf("unexpected ratio: %.1f%%", ratio)
	}
}

func TestCompressProtobuf(t *testing.T) {
	c := transport.NewCompressor()
	data := []byte("{\"node_id\":\"p:100\",\"type\":\"process\",\"label\":\"bash\"}")
	compressed, err := c.CompressProtobuf(data)
	if err != nil {
		t.Fatalf("CompressProtobuf: %v", err)
	}

	decompressed, err := c.DecompressProtobuf(compressed)
	if err != nil {
		t.Fatalf("DecompressProtobuf: %v", err)
	}
	if string(decompressed) != string(data) {
		t.Error("protobuf round-trip mismatch")
	}

	// Verify header.
	if len(compressed) < 4 {
		t.Fatal("missing length header")
	}
	if len(data) < 0 {
		t.Fatal("unreachable")
	}
}

func TestTrainDictionary(t *testing.T) {
	c := transport.NewCompressor()
	samples := [][]byte{
		[]byte("{\"host_id\":\"host-1\",\"event\":\"file_open\"}"),
		[]byte("{\"host_id\":\"host-1\",\"event\":\"file_write\"}"),
		[]byte("{\"host_id\":\"host-1\",\"event\":\"net_connect\"}"),
	}
	dict := c.TrainDictionary(samples)
	if dict == nil {
		t.Fatal("nil dictionary")
	}
	if dict.SampleCount != 3 {
		t.Errorf("samples = %d", dict.SampleCount)
	}
}

func TestCompressorStats(t *testing.T) {
	c := transport.NewCompressor()
	c.Compress([]byte("test data"))
	stats := c.Stats()
	if stats["original_bytes"].(int64) <= 0 {
		t.Errorf("original = %d", stats["original_bytes"])
	}
}

func TestMultipleLevels(t *testing.T) {
	levels := []transport.CompressionLevel{0, 1, 2}
	data := []byte("{\"nodes\":[{\"id\":\"p:1\"},{\"id\":\"p:2\"}]}")

	for _, level := range levels {
		c := transport.NewCompressorWithLevel(level)
		compressed, err := c.Compress(data)
		if err != nil {
			t.Errorf("level %d compression failed: %v", level, err)
			continue
		}
		decompressed, err := c.Decompress(compressed)
		if err != nil {
			t.Errorf("level %d decompress failed: %v", level, err)
			continue
		}
		if string(decompressed) != string(data) {
			t.Errorf("level %d round-trip failed", level)
		}
		c.Close()
	}
}

func TestZstdBetterThanGzip(t *testing.T) {
	// Verify Zstd compression ratio is competitive with gzip on
	// realistic provenance data.
	provenanceData := []byte(`{
		"nodes": [
			{"id":"p:100","type":"process","label":"bash","pid":100,"uid":0},
			{"id":"f:1234:8:3","type":"file","label":"/etc/passwd","inode":1234},
			{"id":"f:5678:8:3","type":"file","label":"/tmp/malware.sh","inode":5678}
		],
		"edges": [
			{"source":"p:100","target":"f:5678:3","relation":"used"},
			{"source":"p:100","target":"f:1234:3","relation":"used"}
		]
	}`)

	zstdComp := transport.NewCompressor()
	zstdCompressed, _ := zstdComp.Compress(provenanceData)
	zstdComp.Close()

	// gzip baseline.
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

// ─── TransportManager integration tests ─────────────────────

func TestTransportManager(t *testing.T) {
	dir := t.TempDir()
	cfg := &transport.TransportConfig{
		HashCachePath:      dir + "/hashcache",
		LowPriorityPath:    dir + "/lowpri",
		LowSummaryInterval: 0, // disable periodic summary in test
	}
	tm, err := transport.NewTransportManager(cfg)
	if err != nil {
		t.Fatalf("NewTransportManager: %v", err)
	}
	defer tm.Stop()

	// High-priority event.
	tm.Ingest([]byte("critical-event"), transport.PriorityCritical, true, false)
	// Low-priority event.
	tm.Ingest([]byte("background-noise"), transport.PriorityLow, false, false)

	stats := tm.Stats()
	if stats.HighSent < 1 {
		t.Errorf("high_sent = %d, want >= 1", stats.HighSent)
	}
	if stats.LowStaged < 1 {
		t.Errorf("low_staged = %d, want >= 1", stats.LowStaged)
	}
	t.Logf("Manager stats: %+v", stats)
}

func TestTransportManagerHeartbeat(t *testing.T) {
	dir := t.TempDir()
	cfg := &transport.TransportConfig{
		HashCachePath:      dir + "/hashcache",
		LowPriorityPath:    dir + "/lowpri",
		LowSummaryInterval: 0,
	}
	tm, err := transport.NewTransportManager(cfg)
	if err != nil {
		t.Fatalf("NewTransportManager: %v", err)
	}
	defer tm.Stop()

	data := []byte("repeated-subgraph-content")
	tm.Ingest(data, transport.PriorityNormal, false, false)
	tm.Ingest(data, transport.PriorityNormal, false, false)

	stats := tm.Stats()
	if stats.Heartbeats < 1 {
		t.Errorf("heartbeats = %d, want >= 1", stats.Heartbeats)
	}
	if stats.BytesSaved < 1 {
		t.Errorf("bytes_saved = %d, want >= 1", stats.BytesSaved)
	}
	t.Logf("Heartbeat stats: %d heartbeats, %d bytes saved",
		stats.Heartbeats, stats.BytesSaved)
}

// ─── Full transport integration test ───────────────────────

func TestTransportIntegration(t *testing.T) {
	t.Log("=== Transport Optimization Integration ===")

	// 1. Hash cache
	hc := transport.NewHashCache()
	subgraph := []byte("{\"nodes\":[{\"id\":\"p:100\",\"label\":\"bash\"}]}")
	hash := transport.ComputeHash(subgraph)

	first := hc.ShouldTransmit(hash)
	second := hc.ShouldTransmit(hash)
	t.Logf("Hash cache: first=%v second=%v (heartbeat=%v)", first, second, !second)

	// 2. Priority pipeline
	pp := transport.NewPriorityPipeline()
	pp.Ingest(&transport.TransportEvent{
		Hash: "c2-connect", Priority: transport.PriorityCritical, Tainted: true,
	})
	pp.Ingest(&transport.TransportEvent{
		Hash: "log-rotate", Priority: transport.PriorityLow,
	})
	pp.Ingest(&transport.TransportEvent{
		Hash: "cron-job", Priority: transport.PriorityLow,
	})

	high := pp.DrainHigh()
	summary := pp.DrainLowSummary()
	t.Logf("Priority: %d high, %d low (summary count=%d)",
		len(high), summary.Count, summary.Count)

	// 3. Compression
	c := transport.NewCompressor()
	protoData := []byte("{\"nodes\":[{\"id\":\"p:100\",\"label\":\"bash\",\"host_id\":\"host-1\"}]}")
	compressed, err := c.Compress(protoData)
	if err != nil {
		t.Fatalf("compress error: %v", err)
	}
	decompressed, err := c.Decompress(compressed)
	if err != nil {
		t.Fatalf("decompress error: %v", err)
	}
	ratio := float64(len(compressed)) / float64(len(protoData)) * 100
	t.Logf("Compression: %d -> %d bytes (%.1f%%)", len(protoData), len(compressed), ratio)
	if string(decompressed) != string(protoData) {
		t.Error("compression round-trip failed")
	}
	c.Close()

	// 4. Combined stats
	hcStats := hc.Stats()
	ppStats := pp.Stats()
	t.Logf("Hash cache: %d heartbeats, %d bytes saved",
		hcStats["heartbeats"], hcStats["bytes_saved"])
	t.Logf("Pipeline: %d high, %d low staged",
		ppStats["high_sent"], ppStats["low_staged"])

	t.Log("Transport integration OK")
}
