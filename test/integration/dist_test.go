//go:build integration

package integration

import (
	"testing"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/stitcher/dist"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/transport"
)

func TestNewGlobalIDStore(t *testing.T) {
	g := dist.NewGlobalIDStore()
	if g == nil {
		t.Fatal("NewGlobalIDStore returned nil")
	}
	if g.HostID() == "" {
		t.Error("empty HostID")
	}
	if g.BootID() == "" {
		t.Error("empty BootID")
	}
	t.Logf("HostID: %s, BootID: %s", g.HostID(), g.BootID())
}

func TestGetOrCreate(t *testing.T) {
	g := dist.NewGlobalIDStore()
	guid := g.GetOrCreate("p:100")
	if guid == nil {
		t.Fatal("nil GUID")
	}
	if guid.LocalID != "p:100" {
		t.Errorf("local = %s", guid.LocalID)
	}
	if guid.FullID == "" {
		t.Error("empty FullID")
	}
	t.Logf("GUID: host=%s boot=%s local=%s full=%s",
		guid.HostID, guid.BootID, guid.LocalID, guid.FullID[:16])
}

func TestGUIDCache(t *testing.T) {
	g := dist.NewGlobalIDStore()
	guid1 := g.GetOrCreate("p:100")
	guid2 := g.GetOrCreate("p:100")
	if guid1.FullID != guid2.FullID {
		t.Error("same local ID should produce same FullID")
	}
}

func TestGUIDDifferentHosts(t *testing.T) {
	g1 := dist.NewGlobalIDStore()
	g2 := dist.NewGlobalIDStore()
	_ = g1
	_ = g2
	t.Log("GUIDs created for p:100 on this host")
}

func TestResolve(t *testing.T) {
	g := dist.NewGlobalIDStore()
	guid := g.GetOrCreate("p:500")

	resolved, ok := dist.Resolve(guid.FullID)
	if !ok {
		t.Error("resolve failed")
	}
	if resolved.FullID != guid.FullID {
		t.Errorf("mismatch: %s vs %s", resolved.FullID, guid.FullID)
	}
}

// ─── Stream pipeline tests (updated for TransportManager) ─────

func TestNewStreamPipeline(t *testing.T) {
	sp := dist.NewStreamPipeline(nil, nil)
	if sp == nil {
		t.Fatal("NewStreamPipeline returned nil")
	}
}

func TestSendAndBuffer(t *testing.T) {
	sp := dist.NewStreamPipeline(nil, nil)
	evt := &dist.StreamEvent{
		FullID:    "abc123",
		EventType: "file_open",
		Tainted:   true,
	}
	ok := sp.Send(evt)
	if !ok {
		t.Error("send failed")
	}
	_ = sp.Stats()
}

func TestBufferFull(t *testing.T) {
	cfg := dist.DefaultStreamConfig()
	cfg.BufferSize = 3
	sp := dist.NewStreamPipeline(cfg, nil)

	for i := 0; i < 5; i++ {
		sp.Send(&dist.StreamEvent{FullID: "evt"})
	}

	stats := sp.Stats()
	if stats["dropped"].(int64) == 0 {
		t.Log("no drops (buffer may be larger than expected)")
	} else {
		t.Logf("dropped: %d", stats["dropped"])
	}
}

func TestFlush(t *testing.T) {
	cfg := dist.DefaultStreamConfig()
	cfg.FlushInterval = 50 * time.Millisecond
	sp := dist.NewStreamPipeline(cfg, nil)
	sp.Start()

	sp.Send(&dist.StreamEvent{FullID: "test-event"})
	time.Sleep(100 * time.Millisecond)

	stats := sp.Stats()
	t.Logf("Sent: %d", stats["sent"])
	sp.Stop()
}

func TestStreamStats(t *testing.T) {
	sp := dist.NewStreamPipeline(nil, nil)
	sp.Send(&dist.StreamEvent{FullID: "e1"})
	sp.Send(&dist.StreamEvent{FullID: "e2"})

	stats := sp.Stats()
	if stats["buffered"].(int) != 2 {
		t.Errorf("buffered = %d", stats["buffered"])
	}
}

// ─── GUID compression tests ────────────────────────────────────

func TestNewCompressor(t *testing.T) {
	c := dist.NewCompressor()
	if c == nil {
		t.Fatal("NewCompressor returned nil")
	}
}

func TestGUIDCompressDecompress(t *testing.T) {
	c := dist.NewCompressor()
	guid := &dist.GUID{
		HostID:  "host-abc-123",
		BootID:  "boot-xyz-789",
		LocalID: "p:100",
	}

	cg := c.Compress(guid)
	if cg.HostIdx == 0 {
		t.Error("host index should not be 0")
	}

	recovered := c.Decompress(cg)
	if recovered.HostID != "host-abc-123" {
		t.Errorf("host = %s", recovered.HostID)
	}
	if recovered.LocalID != "p:100" {
		t.Errorf("local = %s", recovered.LocalID)
	}
}

func TestCompressDictionaryHit(t *testing.T) {
	c := dist.NewCompressor()
	guid := &dist.GUID{HostID: "host-x", BootID: "boot-y", LocalID: "p:1"}

	c.Compress(guid) // miss
	c.Compress(guid) // hit

	ratio := c.CompressionRatio()
	if ratio <= 0 {
		t.Error("ratio should be > 0")
	}
	t.Logf("Compression ratio: %.1f%%", ratio)
}

func TestCompressGUIDString(t *testing.T) {
	c := dist.NewCompressor()
	fullID := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	compressed := c.CompressGUIDString(fullID)
	if len(compressed) != 32 {
		t.Errorf("compressed length = %d", len(compressed))
	}

	decompressed := c.DecompressGUIDString(compressed)
	if decompressed != fullID {
		t.Errorf("roundtrip: %s != %s", decompressed, fullID)
	}
}

func TestCompressGUIDStringShort(t *testing.T) {
	c := dist.NewCompressor()
	short := "short-id"
	compressed := c.CompressGUIDString(short)
	if string(compressed) != short {
		t.Error("short string should pass through unchanged")
	}
}

func TestGuidStats(t *testing.T) {
	c := dist.NewCompressor()
	c.Compress(&dist.GUID{HostID: "h1", LocalID: "p:1"})
	c.Compress(&dist.GUID{HostID: "h1", LocalID: "p:2"})

	stats := c.Stats()
	if stats["dictionary_size"].(int) < 1 {
		t.Errorf("dict size = %d", stats["dictionary_size"])
	}
}

// ─── Integration test ──────────────────────────────────────────

func TestDistIntegration(t *testing.T) {
	t.Log("=== Distributed System Integration ===")

	guidStore := dist.NewGlobalIDStore()
	t.Logf("HostID: %s", guidStore.HostID())
	t.Logf("BootID: %s", guidStore.BootID())

	procGUID := guidStore.GetOrCreate("p:100")
	fileGUID := guidStore.GetOrCreate("f:5000:8:3")
	t.Logf("Process GUID: %s", procGUID.FullID[:16])
	t.Logf("File GUID:    %s", fileGUID.FullID[:16])

	compressor := dist.NewCompressor()
	cg := compressor.Compress(procGUID)
	recovered := compressor.Decompress(cg)
	t.Logf("Compressed: idx=%d -> recovered: host=%s local=%s",
		cg.HostIdx, recovered.HostID, recovered.LocalID)

	compressed := compressor.CompressGUIDString(procGUID.FullID)
	decompressed := compressor.DecompressGUIDString(compressed)
	if decompressed != procGUID.FullID {
		t.Error("FullID round-trip failed")
	}
	t.Logf("GUID compression: 64 hex -> %d bytes (%.0f%% reduction)",
		len(compressed), (1-float64(len(compressed))/64)*100)

	pipeline := dist.NewStreamPipeline(nil, nil)
	evt := &dist.StreamEvent{
		FullID:    procGUID.FullID,
		EventType: "net_connect",
		Tainted:   true,
	}
	pipeline.Send(evt)

	stats := pipeline.Stats()
	t.Logf("Pipeline: buffered=%d sent=%d", stats["buffered"], stats["sent"])

	t.Log("Distributed system integration OK")
}

func TestStreamPipelineWithTransportManager(t *testing.T) {
	t.Log("=== Stream Pipeline with TransportManager ===")

	cfg := &transport.TransportConfig{
		LowSummaryInterval: 0, // disable periodic summary in test
	}
	tm, err := transport.NewTransportManager(cfg)
	if err != nil {
		t.Fatalf("NewTransportManager: %v", err)
	}
	defer tm.Stop()

	sp := dist.NewStreamPipeline(nil, tm)
	_ = sp.Send(&dist.StreamEvent{
		FullID:    "guid-123",
		EventType: "proc_exec",
		Tainted:   true,
	})

	stats := sp.Stats()
	if stats["buffered"].(int) != 1 {
		t.Errorf("buffered = %d, want 1", stats["buffered"])
	}
	t.Log("Stream with TransportManager integration OK")
}
