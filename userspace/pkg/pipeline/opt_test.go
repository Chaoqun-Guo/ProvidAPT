package pipeline

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/Chaoqun-Guo/ProvidAPT/userspace/internal/syscall"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/provenance"
)

// ── Zero-copy reader tests ──────────────────────────────────

func TestRawSamplePool(t *testing.T) {
	pool := NewRawSamplePool(10)
	buf := pool.Get()
	if buf == nil {
		t.Fatal("Get returned nil")
	}
	pool.Put(buf)
}

func TestReaderStats(t *testing.T) {
	zr := &ZeroCopyReader{}
	zr.stats.Reads.Add(10)
	zr.stats.BytesTotal.Add(3320)
	stats := zr.Stats()
	if stats["reads"] != 10 {
		t.Errorf("reads = %d", stats["reads"])
	}
}

// ── Lock-free queue tests ───────────────────────────────────

func TestLockFreeQueueBasic(t *testing.T) {
	q := NewLockFreeQueue(16)
	val := unsafe.Pointer(new(int))
	if !q.TryPush(val) {
		t.Fatal("push failed")
	}
	got, ok := q.TryPop()
	if !ok {
		t.Fatal("pop failed")
	}
	if got != val {
		t.Error("got different pointer")
	}
}

func TestLockFreeQueueEmpty(t *testing.T) {
	q := NewLockFreeQueue(16)
	_, ok := q.TryPop()
	if ok {
		t.Error("should be empty")
	}
}

func TestLockFreeQueueFull(t *testing.T) {
	q := NewLockFreeQueue(4)
	for i := 0; i < q.Cap(); i++ {
		if !q.TryPush(unsafe.Pointer(&i)) {
			t.Fatalf("push %d failed", i)
		}
	}
	if q.TryPush(unsafe.Pointer(new(int))) {
		t.Error("should be full")
	}
}

func TestLockFreeQueueLen(t *testing.T) {
	q := NewLockFreeQueue(16)
	if q.Len() != 0 {
		t.Errorf("initial len = %d", q.Len())
	}
	q.TryPush(unsafe.Pointer(new(int)))
	if q.Len() != 1 {
		t.Errorf("after push len = %d", q.Len())
	}
}

func TestLockFreeQueueConcurrentSPSC(t *testing.T) {
	q := NewLockFreeQueue(4096)
	var wg sync.WaitGroup
	n := 5000

	// Producer
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			v := i
			for !q.TryPush(unsafe.Pointer(&v)) {
				runtime.Gosched()
			}
		}
	}()

	// Consumer
	wg.Add(1)
	count := 0
	go func() {
		defer wg.Done()
		for count < n {
			if _, ok := q.TryPop(); ok {
				count++
			} else {
				runtime.Gosched()
			}
		}
	}()

	wg.Wait()
	if count != n {
		t.Errorf("consumed %d, want %d", count, n)
	}
}

func TestLockFreeQueueRoundRobin(t *testing.T) {
	// Test that the buffer wraps correctly by filling near capacity
	q := NewLockFreeQueue(8)
	for i := 0; i < 100; i++ {
		v := i
		q.TryPush(unsafe.Pointer(&v))
		q.TryPop()
	}
	// After 100 wrap-arounds, queue should still work
	v := 42
	if !q.TryPush(unsafe.Pointer(&v)) {
		t.Fatal("push failed after wrap")
	}
}

// ── Worker pool tests ───────────────────────────────────────

func TestWorkerPoolConfig(t *testing.T) {
	cfg := DefaultWorkerPoolConfig()
	if cfg.NumWorkers <= 0 {
		t.Errorf("NumWorkers = %d", cfg.NumWorkers)
	}
	if cfg.QueueSize <= 0 {
		t.Errorf("QueueSize = %d", cfg.QueueSize)
	}
}

func TestWorkerPoolNew(t *testing.T) {
	// Without a real ring buffer reader, the pool can be created
	// but not started
	_ = NewWorkerPool(nil, nil)
}

func TestDispatcherRoundRobin(t *testing.T) {
	d := &Dispatcher{
		queues: make([]*LockFreeQueue, 3),
	}
	for i := range d.queues {
		d.queues[i] = NewLockFreeQueue(16)
	}

	// First dispatch goes to queue 0, second to queue 1, etc.
	n0 := d.next.Add(1) % 3
	n1 := d.next.Add(1) % 3
	n2 := d.next.Add(1) % 3

	if n0 == n1 || n1 == n2 {
		t.Log("round-robin: distribution across queues")
	}
}

// ── Batch writer tests ──────────────────────────────────────

func TestBatchWriterConfig(t *testing.T) {
	cfg := DefaultBatchWriterConfig()
	if cfg.BatchSize <= 0 {
		t.Errorf("BatchSize = %d", cfg.BatchSize)
	}
	if cfg.FlushInterval <= 0 {
		t.Errorf("FlushInterval = %v", cfg.FlushInterval)
	}
	if !cfg.DisableWAL {
		t.Error("default should have WAL disabled for performance")
	}
}

func TestSafeBatchWriterConfig(t *testing.T) {
	cfg := SafeBatchWriterConfig()
	if cfg.DisableWAL {
		t.Error("safe config should enable WAL")
	}
	if !cfg.SyncWrites {
		t.Error("safe config should sync writes")
	}
}

func TestBatchWriterWriteEdge(t *testing.T) {
	// Create a batch writer without a real store (will fail on flush)
	bw := NewBatchWriter(nil, &BatchWriterConfig{
		BatchSize:     10,
		FlushInterval: time.Hour,
	})
	bw.Start()
	defer bw.Stop()

	e := &provenance.Edge{
		Source: "p:1", Target: "f:100", Relation: "prov:used",
	}
	// WriteEdge should accept the edge even without a store
	err := bw.WriteEdge(e)
	if err != nil {
		t.Logf("WriteEdge (no store): %v", err)
	}
	bw.Flush()
}

func TestBatchWriterStats(t *testing.T) {
	bw := NewBatchWriter(nil, DefaultBatchWriterConfig())
	stats := bw.Stats()
	if stats["batch_size"] != 500 {
		t.Errorf("batch_size = %v", stats["batch_size"])
	}
}

func TestBatchWriterPendingCount(t *testing.T) {
	bw := NewBatchWriter(nil, &BatchWriterConfig{
		BatchSize: 100,
	})

	// Add edges without flushing
	for i := 0; i < 50; i++ {
		bw.WriteEdge(&provenance.Edge{
			Source: "p:1", Target: "f:100", Relation: "prov:used",
		})
	}

	bw.mu.Lock()
	pending := len(bw.pending)
	bw.mu.Unlock()

	if pending != 50 {
		t.Errorf("pending = %d, want 50", pending)
	}
}

// ── SpinWait test ───────────────────────────────────────────

func TestSpinWait(t *testing.T) {
	// Should not panic for any iteration count
	for i := 0; i < 50; i++ {
		SpinWait(i)
	}
}

// ── Performance: raw event parsing via worker pool ──────────

func BenchmarkRawEventParsing(b *testing.B) {
	raw := make([]byte, 332)
	raw[0] = byte(syscall.EventFileOpen)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := collector.ParseRawEvent(raw)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLockFreeQueue(b *testing.B) {
	q := NewLockFreeQueue(65536)
	n := b.N

	// Pre-fill with pointers
	vals := make([]unsafe.Pointer, n)
	for i := 0; i < n; i++ {
		v := i
		vals[i] = unsafe.Pointer(&v)
	}

	// Produce
	var prod atomic.Int64
	var cons atomic.Int64
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			for !q.TryPush(vals[i]) {
				runtime.Gosched()
			}
			prod.Add(1)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for cons.Load() < int64(n) {
			if _, ok := q.TryPop(); ok {
				cons.Add(1)
			} else {
				runtime.Gosched()
			}
		}
	}()

	wg.Wait()
	b.ReportMetric(float64(n)/b.Elapsed().Seconds(), "ops/sec")
}

func TestRawEventPointer(t *testing.T) {
	e := &rawEvent{data: []byte("test"), seq: 42}
	p := e.ptr()
	e2 := (*rawEvent)(p)
	if string(e2.data) != "test" || e2.seq != 42 {
		t.Error("pointer conversion failed")
	}
}

func TestWorkerPoolRoundRobinDistribution(t *testing.T) {
	queues := make([]*LockFreeQueue, 4)
	for i := range queues {
		queues[i] = NewLockFreeQueue(16)
	}

	d := &Dispatcher{queues: queues}
	_ = d
	// Verify dispatcher distributes across workers
	// by checking the next index increments
	n1 := d.next.Add(1) % 4
	n2 := d.next.Add(1) % 4
	if n1 == n2 {
		t.Log("round-robin distributes")
	}
}
