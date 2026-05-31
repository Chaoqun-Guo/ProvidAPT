package benchmark

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/pipeline"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ─── Setup ───────────────────────────────────────────────────

func benchPipeline(b *testing.B) (*pipeline.Pipeline, *provenance.Graph, func()) {
	graph := provenance.NewGraph()
	dir, err := os.MkdirTemp("", "providapt-bench-*")
	if err != nil {
		b.Fatalf("temp dir: %v", err)
	}

	cfg := pipeline.DefaultConfig()
	cfg.StorePath = dir + "/pebble"
	cfg.MaxCacheSize = 8192
	cfg.MergeWindow = 5 * time.Second

	pipe, err := pipeline.New(graph, cfg)
	if err != nil {
		b.Fatalf("pipeline: %v", err)
	}
	pipe.Start()

	cleanup := func() {
		pipe.Stop()
		os.RemoveAll(dir)
	}

	return pipe, graph, cleanup
}

// ─── Benchmarks ─────────────────────────────────────────────

// BenchmarkPipelineThroughput measures end-to-end event processing
// rate: raw event → pipeline → cache → merge → RocksDB.
func BenchmarkPipelineThroughput(b *testing.B) {
	pipe, _, cleanup := benchPipeline(b)
	defer cleanup()

	gen := NewGenerator()
	events := gen.Generate(b.N)

	b.ResetTimer()
	start := time.Now()

	for _, evt := range events {
		pipe.AddEvent(evt)
	}

	elapsed := time.Since(start)
	pipe.Stop()

	rate := float64(b.N) / elapsed.Seconds()
	b.ReportMetric(rate, "events/sec")
	b.ReportMetric(float64(elapsed.Microseconds())/float64(b.N), "ns/event")
}

// BenchmarkPipelineBurst measures burst throughput (pre-generate all
// events, then feed as fast as possible).
func BenchmarkPipelineBurst(b *testing.B) {
	pipe, _, cleanup := benchPipeline(b)
	defer cleanup()

	// Pre-generate
	gen := NewGenerator()
	events := gen.Generate(b.N)

	b.ResetTimer()
	start := time.Now()

	// Feed without any pacing
	for _, evt := range events {
		pipe.AddEvent(evt)
	}

	elapsed := time.Since(start)
	rate := float64(b.N) / elapsed.Seconds()
	b.ReportMetric(rate, "burst_events/sec")
	b.ReportMetric(float64(elapsed.Microseconds())/float64(b.N), "ns/event")
}

// BenchmarkPipeline50K simulates 50,000 events/sec for 10 seconds
// to measure sustained throughput under realistic load.
func BenchmarkPipeline50K(b *testing.B) {
	pipe, graph, cleanup := benchPipeline(b)
	defer cleanup()

	gen := NewGenerator()
	targetRate := 50000 // events per second
	duration := 10 * time.Second
	totalEvents := targetRate * int(duration.Seconds())
	b.Logf("Target: %d events/sec for %v = %d events",
		targetRate, duration, totalEvents)

	// Generate a batch at a time
	batchSize := 5000
	events := gen.Generate(batchSize)
	eventIdx := 0

	b.ResetTimer()
	start := time.Now()
	ticker := time.NewTicker(time.Second / time.Duration(targetRate/batchSize))
	defer ticker.Stop()

	processed := 0
	for time.Since(start) < duration {
		<-ticker.C
		for i := 0; i < batchSize && processed < totalEvents; i++ {
			pipe.AddEvent(events[eventIdx])
			eventIdx++
			processed++
			if eventIdx >= len(events) {
				events = gen.Generate(batchSize)
				eventIdx = 0
			}
		}
	}

	elapsed := time.Since(start)
	actualRate := float64(processed) / elapsed.Seconds()
	b.ReportMetric(actualRate, "50k_events/sec")
	b.ReportMetric(float64(runtime.NumGoroutine()), "goroutines")

	// Report graph and cache stats
	stats := graph.Stats()
	pipeStats := pipe.Stats()
	b.Logf("Graph: %d nodes, %d edges", stats.Nodes, stats.Edges)
	b.Logf("Cache size: %v", pipeStats["cache"].(map[string]interface{})["size"])
	b.Logf("Merge pending: %v", pipeStats["merger"].(map[string]interface{})["pending"])
	b.Logf("RocksDB disk: %v bytes", pipeStats["store"].(map[string]interface{})["disk_bytes"])
}

// BenchmarkMemoryAlloc measures allocation behaviour of the pipeline.
func BenchmarkMemoryAlloc(b *testing.B) {
	pipe, _, cleanup := benchPipeline(b)
	defer cleanup()

	gen := NewGenerator()
	events := gen.Generate(50000)

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	b.ResetTimer()
	for _, evt := range events {
		pipe.AddEvent(evt)
	}
	b.StopTimer()

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	alloced := memAfter.TotalAlloc - memBefore.TotalAlloc
	b.ReportMetric(float64(alloced)/float64(len(events)), "B/event")
	b.ReportMetric(float64(memAfter.Mallocs-memBefore.Mallocs)/float64(len(events)), "allocs/event")
	b.ReportMetric(float64(memAfter.NumGC-memBefore.NumGC), "GC_cycles")
}

// ─── CPU profile ─────────────────────────────────────────────

func BenchmarkCPUProfile(b *testing.B) {
	f, err := os.Create("cpu.prof")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()

	pipe, _, cleanup := benchPipeline(b)
	defer cleanup()

	gen := NewGenerator()
	events := gen.Generate(b.N)
	for _, evt := range events {
		pipe.AddEvent(evt)
	}
}

// ─── Heap profile ────────────────────────────────────────────

func BenchmarkHeapProfile(b *testing.B) {
	pipe, _, cleanup := benchPipeline(b)
	defer cleanup()

	gen := NewGenerator()
	events := gen.Generate(b.N)
	for _, evt := range events {
		pipe.AddEvent(evt)
	}

	f, err := os.Create("heap.prof")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	runtime.GC()
	if err := pprof.WriteHeapProfile(f); err != nil {
		b.Fatal(err)
	}
	b.Logf("heap profile written to heap.prof")
}

// ─── Memory stability over time ──────────────────────────────

func BenchmarkMemoryStability(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping 24h stability test in short mode")
	}

	pipe, graph, cleanup := benchPipeline(b)
	defer cleanup()

	gen := NewGenerator()
	targetRate := 50000
	duration := 24 * time.Hour

	b.Logf("=== 24h Memory Stability Test ===")
	b.Logf("Rate: %d events/sec", targetRate)
	b.Logf("Duration: %v", duration)

	batchSize := 10000
	events := gen.Generate(batchSize)
	eventIdx := 0

	sampleInterval := 5 * time.Minute
	sampleTicker := time.NewTicker(sampleInterval)
	defer sampleTicker.Stop()

	b.ResetTimer()

	processed := int64(0)
	start := time.Now()
	samples := make([]runtime.MemStats, 0)
	ticker := time.NewTicker(time.Second / time.Duration(targetRate/batchSize))
	defer ticker.Stop()

loop:
	for {
		select {
		case <-ticker.C:
			for i := 0; i < batchSize && time.Since(start) < duration; i++ {
				pipe.AddEvent(events[eventIdx])
				eventIdx++
				processed++
				if eventIdx >= len(events) {
					events = gen.Generate(batchSize)
					eventIdx = 0
				}
			}
			if time.Since(start) >= duration {
				break loop
			}

		case <-sampleTicker.C:
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			samples = append(samples, mem)
			b.Logf("[sample %d] alloc=%d MB sys=%d MB goroutines=%d",
				len(samples), mem.Alloc/1024/1024,
				mem.Sys/1024/1024, runtime.NumGoroutine())
		}
	}

	pipe.Stop()
	elapsed := time.Since(start)
	rate := float64(processed) / elapsed.Seconds()

	// Analyse memory growth
	if len(samples) >= 2 {
		firstAlloc := samples[0].Alloc
		lastAlloc := samples[len(samples)-1].Alloc
		growth := int64(lastAlloc) - int64(firstAlloc)
		growthMB := float64(growth) / 1024 / 1024
		hours := elapsed.Hours()

		b.ReportMetric(rate, "avg_events/sec")
		b.ReportMetric(float64(processed), "total_events")
		b.ReportMetric(growthMB/hours, "mem_growth_MB/hour")
		b.ReportMetric(float64(samples[len(samples)-1].NumGC-samples[0].NumGC)/hours, "GC_cycles/hour")

		b.Logf("Memory growth: %.2f MB over %.1f hours (%.3f MB/hr)",
			growthMB, hours, growthMB/hours)
		if growthMB/hours > 10 {
			b.Logf("WARNING: Memory growing at %.2f MB/hr — possible leak", growthMB/hours)
		} else {
			b.Logf("Memory stable — growth rate %.3f MB/hr is acceptable", growthMB/hours)
		}
	}

	// Final stats
	stats := graph.Stats()
	pipeStats := pipe.Stats()
	b.Logf("Final — Graph: %d nodes, %d edges", stats.Nodes, stats.Edges)
	b.Logf("Cache: %v", pipeStats["cache"])
	b.Logf("Store: %v", pipeStats["store"])
}

// ─── Short sanity test (always runs) ─────────────────────────

func BenchmarkPipelineSanity(b *testing.B) {
	pipe, _, cleanup := benchPipeline(b)
	defer cleanup()

	gen := NewGenerator()
	events := gen.Generate(1000)

	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	for _, evt := range events {
		pipe.AddEvent(evt)
	}
	pipe.Stop()

	runtime.ReadMemStats(&memAfter)
	b.Logf("Processed %d events", len(events))
	b.Logf("Alloc before: %d KB, after: %d KB",
		memBefore.Alloc/1024, memAfter.Alloc/1024)
	b.Logf("GC cycles: %d", memAfter.NumGC-memBefore.NumGC)
}

func init() {
	fmt.Println("ProvidAPT Benchmark Suite")
	fmt.Println("=========================")
	fmt.Println("Run: go test -bench=. -benchtime=10s ./test/benchmark/")
	fmt.Println("Profile: go test -bench=BenchmarkCPUProfile -benchtime=30s ./test/benchmark/")
	fmt.Println("24h test: go test -bench=BenchmarkMemoryStability -benchtime=86400s ./test/benchmark/")
	fmt.Println()
}
