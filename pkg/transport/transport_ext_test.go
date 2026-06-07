// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"path/filepath"
	"testing"
	"time"
)

// ─── Compressor extended tests ───────────────────────────────

func TestCompressorProtobufRoundTrip(t *testing.T) {
	c := NewCompressor()
	defer c.Close()

	original := []byte("protobuf-encoded-provenance-data")
	compressed, err := c.CompressProtobuf(original)
	if err != nil {
		t.Fatalf("CompressProtobuf: %v", err)
	}

	// Header should be 4 bytes + compressed data
	if len(compressed) < 4 {
		t.Fatal("compressed too short, missing length header")
	}

	decompressed, err := c.DecompressProtobuf(compressed)
	if err != nil {
		t.Fatalf("DecompressProtobuf: %v", err)
	}
	if string(decompressed) != string(original) {
		t.Error("protobuf round-trip mismatch")
	}
}

func TestCompressorProtobufShortInput(t *testing.T) {
	c := NewCompressor()
	defer c.Close()

	// Less than 4 bytes — should fall back to plain decompress
	data := []byte{0x28, 0xb5, 0x2f}
	_, err := c.DecompressProtobuf(data)
	if err == nil {
		// Accept either success or failure — just should not panic
	}
}

func TestCompressorWithLevels(t *testing.T) {
	levels := []CompressionLevel{CompressSpeed, CompressBalance, CompressSize}
	payload := make([]byte, 5000)
	for i := range payload {
		payload[i] = byte(i % 15)
	}

	for _, l := range levels {
		c := NewCompressorWithLevel(l)
		compressed, err := c.Compress(payload)
		if err != nil {
			t.Fatalf("level %d compress: %v", l, err)
		}
		decompressed, err := c.Decompress(compressed)
		if err != nil {
			t.Fatalf("level %d decompress: %v", l, err)
		}
		if string(decompressed) != string(payload) {
			t.Errorf("level %d round-trip mismatch", l)
		}
		c.Close()
	}
}

func TestCompressorStats(t *testing.T) {
	c := NewCompressor()
	defer c.Close()

	payload := []byte("statistics-test-payload")
	c.Compress(payload)

	stats := c.Stats()
	if stats["original_bytes"].(int64) == 0 {
		t.Error("original_bytes should be > 0")
	}
	if stats["compressed_bytes"].(int64) == 0 {
		t.Error("compressed_bytes should be > 0")
	}
	if _, ok := stats["ratio"]; !ok {
		t.Error("ratio missing from stats")
	}
	if _, ok := stats["dict_trained"]; !ok {
		t.Error("dict_trained missing from stats")
	}
}

func TestCompressorDictBytes(t *testing.T) {
	c := NewCompressor()
	defer c.Close()

	if b := c.DictBytes(); b != nil {
		t.Error("expected nil dict bytes without training")
	}
}

func TestCompressorRatioNoData(t *testing.T) {
	c := NewCompressor()
	defer c.Close()

	if r := c.Ratio(); r != 0 {
		t.Errorf("expected 0 ratio with no data, got %.1f%%", r)
	}
}

func TestCompressorCloseIdempotent(t *testing.T) {
	c := NewCompressor()
	c.Close()
	c.Close() // should not panic
}

// ─── Persistent HashCache tests ───────────────────────────────

func TestPersistentHashCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hashcache")

	hc, err := NewPersistentHashCache(path)
	if err != nil {
		t.Fatalf("NewPersistentHashCache: %v", err)
	}

	// Should transmit new content
	if !hc.ShouldTransmit("hash-1") {
		t.Error("first transmission should be allowed")
	}
	// Should not transmit duplicate
	if hc.ShouldTransmit("hash-1") {
		t.Error("duplicate should not transmit")
	}

	stats := hc.Stats()
	if stats["cached_hashes"].(int) != 1 {
		t.Errorf("cached_hashes = %d, want 1", stats["cached_hashes"])
	}

	hc.Close()
}

func TestPersistentHashCacheFlushSuccess(t *testing.T) {
	dir := t.TempDir()
	hc, err := NewPersistentHashCache(filepath.Join(dir, "hc"))
	if err != nil {
		t.Fatalf("NewPersistentHashCache: %v", err)
	}

	hc.ShouldTransmit("persistent-hash")
	if err := hc.FlushToDisk(); err != nil {
		t.Errorf("FlushToDisk: %v", err)
	}

	stats := hc.Stats()
	if stats["cached_hashes"].(int) != 1 {
		t.Errorf("cached_hashes = %d, want 1", stats["cached_hashes"])
	}

	hc.Close()
}

func TestPersistentHashCacheComputeAndCheck(t *testing.T) {
	dir := t.TempDir()
	hc, err := NewPersistentHashCache(filepath.Join(dir, "hc"))
	if err != nil {
		t.Fatalf("NewPersistentHashCache: %v", err)
	}
	defer hc.Close()

	hash, should := hc.ComputeAndCheck([]byte("new-data"))
	if hash == "" {
		t.Error("empty hash")
	}
	if !should {
		t.Error("new content should transmit")
	}

	// Same data again — should not transmit
	_, should = hc.ComputeAndCheck([]byte("new-data"))
	if should {
		t.Error("duplicate should not transmit")
	}
}

func TestPersistentHashCacheHeartbeat(t *testing.T) {
	dir := t.TempDir()
	hc, err := NewPersistentHashCache(filepath.Join(dir, "hc"))
	if err != nil {
		t.Fatalf("NewPersistentHashCache: %v", err)
	}
	defer hc.Close()

	hc.ShouldTransmit("beat-hash")
	hb := hc.NewHeartbeat("beat-hash")
	if hb == nil {
		t.Fatal("expected heartbeat")
	}
	if hb.Type != "heartbeat" {
		t.Errorf("type = %q", hb.Type)
	}
}

func TestPersistentHashCacheCleanStale(t *testing.T) {
	dir := t.TempDir()
	hc, err := NewPersistentHashCache(filepath.Join(dir, "hc"))
	if err != nil {
		t.Fatalf("NewPersistentHashCache: %v", err)
	}
	defer hc.Close()

	hc.ShouldTransmit("stale-hash")
	n := hc.CleanStale(-1 * time.Nanosecond)
	if n != 1 {
		t.Errorf("cleaned %d, want 1", n)
	}
}

// ─── Persistent PriorityPipeline tests ───────────────────────

func TestPersistentPriorityPipeline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lowpri")

	pp, err := NewPersistentPriorityPipeline(path)
	if err != nil {
		t.Fatalf("NewPersistentPriorityPipeline: %v", err)
	}
	defer pp.Close()

	pp.Ingest(&TransportEvent{Hash: "persist-low", Priority: PriorityLow})
	summary := pp.DrainLowSummary()
	if summary == nil || summary.Count != 1 {
		t.Fatalf("expected 1 event, got %v", summary)
	}
}

func TestPersistentPriorityPipelineLowQueueDepth(t *testing.T) {
	dir := t.TempDir()
	pp, err := NewPersistentPriorityPipeline(filepath.Join(dir, "lowpri"))
	if err != nil {
		t.Fatalf("NewPersistentPriorityPipeline: %v", err)
	}
	defer pp.Close()

	if d := pp.LowQueueDepth(); d != 0 {
		t.Errorf("expected empty queue, depth=%d", d)
	}

	pp.Ingest(&TransportEvent{Hash: "q1", Priority: PriorityLow})
	pp.Ingest(&TransportEvent{Hash: "q2", Priority: PriorityLow})

	// Depth includes event keys + the "lp:seq" metadata key.
	if d := pp.LowQueueDepth(); d < 2 {
		t.Errorf("expected at least 2 entries in queue, got %d", d)
	}
}

func TestPersistentPriorityPipelineDrainPreservesFIFO(t *testing.T) {
	dir := t.TempDir()
	pp, err := NewPersistentPriorityPipeline(filepath.Join(dir, "lowpri"))
	if err != nil {
		t.Fatalf("NewPersistentPriorityPipeline: %v", err)
	}
	defer pp.Close()

	pp.Ingest(&TransportEvent{Hash: "first", Priority: PriorityLow})
	pp.Ingest(&TransportEvent{Hash: "second", Priority: PriorityLow})

	summary := pp.DrainLowSummary()
	if summary == nil || summary.Count != 2 {
		t.Fatalf("expected 2 events, got %d", summary.Count)
	}
}

// ─── TransportManager tests ───────────────────────────────────

func TestDefaultTransportConfig(t *testing.T) {
	cfg := DefaultTransportConfig()
	if cfg == nil {
		t.Fatal("nil config")
	}
	if cfg.ServerAddr != "localhost:50051" {
		t.Errorf("ServerAddr = %q", cfg.ServerAddr)
	}
	if cfg.CompressionLevel != CompressBalance {
		t.Errorf("CompressionLevel = %d", cfg.CompressionLevel)
	}
}

func TestNewTransportManagerNilConfig(t *testing.T) {
	tm, err := NewTransportManager(nil)
	if err != nil {
		t.Fatalf("NewTransportManager(nil): %v", err)
	}
	if tm == nil {
		t.Fatal("nil manager")
	}
	tm.Stop()
}

func TestNewTransportManagerInMemory(t *testing.T) {
	cfg := DefaultTransportConfig()
	tm, err := NewTransportManager(cfg)
	if err != nil {
		t.Fatalf("NewTransportManager: %v", err)
	}
	defer tm.Stop()

	if tm.HashCache() == nil {
		t.Error("nil HashCache")
	}
	if tm.Pipeline() == nil {
		t.Error("nil Pipeline")
	}
	if tm.Compressor() == nil {
		t.Error("nil Compressor")
	}
}

func TestTransportManagerIngestLow(t *testing.T) {
	cfg := DefaultTransportConfig()
	tm, err := NewTransportManager(cfg)
	if err != nil {
		t.Fatalf("NewTransportManager: %v", err)
	}
	defer tm.Stop()

	tm.Ingest([]byte("low-priority-event"), PriorityLow, false, false)
	stats := tm.Stats()
	if stats.LowStaged != 1 {
		t.Errorf("LowStaged = %d, want 1", stats.LowStaged)
	}
}

func TestTransportManagerIngestHigh(t *testing.T) {
	cfg := DefaultTransportConfig()
	tm, err := NewTransportManager(cfg)
	if err != nil {
		t.Fatalf("NewTransportManager: %v", err)
	}
	defer tm.Stop()

	tm.Ingest([]byte("critical-event"), PriorityCritical, true, true)
	stats := tm.Stats()
	if stats.HighSent != 1 {
		t.Errorf("HighSent = %d, want 1", stats.HighSent)
	}
}

func TestTransportManagerIngestDedup(t *testing.T) {
	cfg := DefaultTransportConfig()
	tm, err := NewTransportManager(cfg)
	if err != nil {
		t.Fatalf("NewTransportManager: %v", err)
	}
	defer tm.Stop()

	payload := []byte("dedup-payload")
	tm.Ingest(payload, PriorityLow, false, false)
	tm.Ingest(payload, PriorityLow, false, false)

	stats := tm.Stats()
	// First → low staged; second → heartbeat (low staged again)
	if stats.LowStaged != 2 {
		t.Errorf("LowStaged = %d, want 2", stats.LowStaged)
	}
	if stats.Heartbeats != 1 {
		t.Errorf("Heartbeats = %d, want 1", stats.Heartbeats)
	}
}

func TestTransportManagerStartStop(t *testing.T) {
	tm, err := NewTransportManager(nil)
	if err != nil {
		t.Fatalf("NewTransportManager: %v", err)
	}

	tm.Start()
	tm.Stop() // should not deadlock or panic
}

func TestTransportManagerStatsAfterIngest(t *testing.T) {
	cfg := DefaultTransportConfig()
	tm, err := NewTransportManager(cfg)
	if err != nil {
		t.Fatalf("NewTransportManager: %v", err)
	}
	defer tm.Stop()

	tm.Ingest([]byte("data-1"), PriorityNormal, false, false)
	tm.Ingest([]byte("data-2"), PriorityCritical, true, false)
	tm.Ingest([]byte("data-3"), PriorityLow, false, true)

	stats := tm.Stats()
	if stats.Processed != 2 {
		t.Errorf("Processed = %d, want 2 (low events aren't drained until summary flush)", stats.Processed)
	}
	if stats.HighSent == 0 {
		t.Error("expected high sent > 0")
	}
}

// ─── TransportManager persistent test ─────────────────────────

func TestNewTransportManagerPersistent(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultTransportConfig()
	cfg.HashCachePath = filepath.Join(dir, "hashcache")
	cfg.LowPriorityPath = filepath.Join(dir, "lowpri")

	tm, err := NewTransportManager(cfg)
	if err != nil {
		t.Fatalf("NewTransportManager persistent: %v", err)
	}
	defer tm.Stop()

	if tm.HashCache() == nil {
		t.Error("nil HashCache")
	}
	if tm.Pipeline() == nil {
		t.Error("nil Pipeline")
	}
}

// ─── File-close edge cases ───────────────────────────────────

func TestPersistentHashCacheClose(t *testing.T) {
	dir := t.TempDir()
	hc, err := NewPersistentHashCache(filepath.Join(dir, "hc"))
	if err != nil {
		t.Fatalf("NewPersistentHashCache: %v", err)
	}
	hc.Close() // should not panic
}

func TestPriorityPipelineCloseNotPanics(t *testing.T) {
	pp := NewPriorityPipeline()
	if err := pp.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Close on in-memory pipeline should be safe
}

func TestPriorityPipelinePersistentCloseError(t *testing.T) {
	dir := t.TempDir()
	pp, err := NewPersistentPriorityPipeline(filepath.Join(dir, "lowpri"))
	if err != nil {
		t.Fatalf("NewPersistentPriorityPipeline: %v", err)
	}
	if err := pp.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// ─── GrpcClient config tests (unit-safe, no gRPC server) ────

func TestGrpcClientConfig(t *testing.T) {
	cfg := &GrpcClientConfig{
		ServerAddr: "example.com:50051",
		CertFile:   "/nonexistent/cert.pem",
		KeyFile:    "/nonexistent/key.pem",
		CAFile:     "/nonexistent/ca.pem",
		EnableTLS:  true,
	}

	// Should not panic with non-existent files
	client := NewGrpcClientWithTLS(cfg)
	if client == nil {
		t.Fatal("nil client")
	}

	// Verify addr
	if client.addr != "example.com:50051" {
		t.Errorf("addr = %q", client.addr)
	}

	client.Close()
}

func TestGrpcClientConfigNoTLS(t *testing.T) {
	cfg := &GrpcClientConfig{
		ServerAddr: "localhost:50051",
		EnableTLS:  false,
	}
	client := NewGrpcClientWithTLS(cfg)
	if client == nil {
		t.Fatal("nil client")
	}
	client.Close()
}

func TestLoadTLSClientConfig(t *testing.T) {
	// Test with missing files — should not panic and return config
	cfg := &GrpcClientConfig{
		ServerName: "test-server",
		CertFile:   "/tmp/nonexistent-cert.pem",
		KeyFile:    "/tmp/nonexistent-key.pem",
		CAFile:     "/tmp/nonexistent-ca.pem",
	}
	tlsCfg := loadTLSClientConfig(cfg)
	if tlsCfg == nil {
		t.Fatal("nil tls config")
	}
	if tlsCfg.MinVersion != 0x0303 {
		t.Errorf("MinVersion = %x, want 0x0303 (TLS 1.2)", tlsCfg.MinVersion)
	}
	if tlsCfg.ServerName != "test-server" {
		t.Errorf("ServerName = %q", tlsCfg.ServerName)
	}
}

// ─── Platform-specific: /proc/self/fd is Linux-only ──────────

func TestHashCacheOpenMissingDir(t *testing.T) {
	// Opening in a non-existent dir should fail gracefully
	_, err := NewPersistentHashCache("/nonexistent/providapt/hc")
	if err == nil {
		t.Log("persistent hash cache opened in nonexistent dir (pebble may create it)")
	}
}

func TestPriorityPipelineOpenMissingDir(t *testing.T) {
	_, err := NewPersistentPriorityPipeline("/nonexistent/providapt/lowpri")
	if err == nil {
		t.Log("persistent pipeline opened in nonexistent dir (pebble may create it)")
	}
}

// ─── Compressor dictionary tests ─────────────────────────────

func TestCompressorTrainDictionary(t *testing.T) {
	c := NewCompressor()
	defer c.Close()

	samples := [][]byte{
		[]byte(`{"node":{"id":"p:1","type":"process","label":"bash"}}`),
		[]byte(`{"node":{"id":"f:1","type":"file","label":"/etc/passwd"}}`),
		[]byte(`{"edge":{"source":"p:1","target":"f:1","relation":"used"}}`),
		[]byte(`{"node":{"id":"p:2","type":"process","label":"sshd"}}`),
	}

	dict := c.TrainDictionary(samples)
	if dict == nil {
		t.Skip("dictionary training may fail on small samples")
	}
	if len(dict.Data) == 0 {
		t.Error("empty dictionary data")
	}
	if dict.SampleCount != 4 {
		t.Errorf("SampleCount = %d, want 4", dict.SampleCount)
	}

	// DictBytes should return the trained data
	if b := c.DictBytes(); b == nil {
		t.Error("DictBytes should return trained data")
	}
}

func TestCompressorTrainDictionaryNoSamples(t *testing.T) {
	c := NewCompressor()
	defer c.Close()

	dict := c.TrainDictionary(nil)
	if dict != nil {
		t.Error("expected nil with no samples")
	}
}

func TestCompressorSetDict(t *testing.T) {
	c := NewCompressor()
	defer c.Close()

	if err := c.SetDict([]byte("fake-dict-data")); err != nil {
		t.Errorf("SetDict: %v", err)
	}
	if b := c.DictBytes(); b == nil {
		t.Error("expected dict bytes after SetDict")
	}
}

// ─── Compressor level conversion ─────────────────────────────

func TestCompressionLevelZstd(t *testing.T) {
	if CompressSpeed.zstd().String() != "fastest" {
		t.Errorf("CompressSpeed = %s", CompressSpeed.zstd())
	}
	if CompressBalance.zstd().String() != "default" {
		t.Errorf("CompressBalance = %s", CompressBalance.zstd())
	}
	if CompressSize.zstd().String() != "best" {
		t.Errorf("CompressSize = %s", CompressSize.zstd())
	}
}
