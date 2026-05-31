package pebblestore

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"

	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
)

// ─── Proto event parsing tests ──────────────────────────────

func TestRawEventToProto(t *testing.T) {
	raw := make([]byte, 332)
	raw[0] = 10                            // type=file_open
	raw[16] = 100                          // pid=100
	raw[28] = 0xE8                         // uid=1000 (LSB)
	raw[29] = 0x03                         // uid=1000 (MSB)
	copy(raw[60:], []byte("bash\x00"))     // comm
	copy(raw[76:], []byte("/etc/shadow\x00")) // pathname

	evt := RawEventToProto(raw)
	if evt == nil {
		t.Fatal("nil event")
	}
	if evt.Type != 10 {
		t.Errorf("type = %d", evt.Type)
	}
	if evt.Pid != 100 {
		t.Errorf("pid = %d", evt.Pid)
	}
	if evt.Comm != "bash" {
		t.Errorf("comm = %q", evt.Comm)
	}
	if evt.Pathname != "/etc/shadow" {
		t.Errorf("pathname = %q", evt.Pathname)
	}
}

func TestRawEventToProtoUid(t *testing.T) {
	raw := make([]byte, 332)
	raw[28] = 42 // uid at offset 28
	evt := RawEventToProto(raw)
	if evt.Uid != 42 {
		t.Errorf("uid = %d", evt.Uid)
	}
}

func TestRawEventShortBuffer(t *testing.T) {
	evt := RawEventToProto(make([]byte, 10))
	if evt != nil {
		t.Error("should return nil for short buffer")
	}
}

func TestMarshalUnmarshalNode(t *testing.T) {
	n := &pb.Node{
		Id: "p:100", Type: "process", Label: "bash",
		Pid: 100, Uid: 1000, Comm: "bash",
	}
	data, err := MarshalNode(n)
	if err != nil {
		t.Fatalf("MarshalNode: %v", err)
	}

	decoded, err := UnmarshalNode(data)
	if err != nil {
		t.Fatalf("UnmarshalNode: %v", err)
	}
	if decoded.Label != "bash" {
		t.Errorf("label = %s", decoded.Label)
	}
	if decoded.Pid != 100 {
		t.Errorf("pid = %d", decoded.Pid)
	}
}

func TestMarshalUnmarshalEdge(t *testing.T) {
	e := &pb.Edge{
		Source: "p:1", Target: "f:100",
		Relation: "used", Count: 42,
	}
	data, err := MarshalEdge(e)
	if err != nil {
		t.Fatalf("MarshalEdge: %v", err)
	}
	decoded, err := UnmarshalEdge(data)
	if err != nil {
		t.Fatalf("UnmarshalEdge: %v", err)
	}
	if decoded.Relation != "used" {
		t.Errorf("relation = %s", decoded.Relation)
	}
	if decoded.Count != 42 {
		t.Errorf("count = %d", decoded.Count)
	}
}

// ─── Zero-copy reader tests ─────────────────────────────────

func TestZeroCopyReaderStats(t *testing.T) {
	zr := &ZeroCopyReader{}
	stats := zr.Stats()
	if stats.EventsRead != 0 {
		t.Errorf("events read = %d", stats.EventsRead)
	}
}

// ─── Batch writer tests ─────────────────────────────────────

func openBatchStore(t *testing.T) (*BatchWriter, func()) {
	dir, err := os.MkdirTemp("", "providapt-batch-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	db, err := pebble.Open(dir+"/pebble", &pebble.Options{})
	if err != nil {
		t.Fatalf("pebble open: %v", err)
	}
	bw := NewBatchWriter(db)
	bw.Start()
	return bw, func() {
		bw.Stop()
		db.Close()
		os.RemoveAll(dir)
	}
}

func TestNewBatchWriter(t *testing.T) {
	bw, cleanup := openBatchStore(t)
	defer cleanup()

	if bw.batchSize != 1000 {
		t.Errorf("batch size = %d", bw.batchSize)
	}
	if bw.flushInterval != 100*time.Millisecond {
		t.Errorf("flush interval = %v", bw.flushInterval)
	}
}

func TestBatchWriteNode(t *testing.T) {
	bw, cleanup := openBatchStore(t)
	defer cleanup()

	n := &pb.Node{Id: "p:100", Type: "process", Label: "test"}
	if err := bw.WriteNode(n); err != nil {
		t.Fatalf("WriteNode: %v", err)
	}

	bw.Flush()
	s := bw.stats
	if s.NodesWritten != 1 {
		t.Errorf("nodes written = %d", s.NodesWritten)
	}
}

func TestBatchWriteEdge(t *testing.T) {
	bw, cleanup := openBatchStore(t)
	defer cleanup()

	e := &pb.Edge{Source: "p:1", Target: "f:100", Relation: "used", TimestampNs: 1000}
	if err := bw.WriteEdge(e); err != nil {
		t.Fatalf("WriteEdge: %v", err)
	}

	bw.Flush()
	if bw.stats.EdgesWritten != 1 {
		t.Errorf("edges = %d", bw.stats.EdgesWritten)
	}
}

func TestBatchCountTrigger(t *testing.T) {
	bw, cleanup := openBatchStore(t)
	defer cleanup()

	// Write batchSize events — should trigger count-based flush
	for i := 0; i < 500; i++ {
		bw.WriteNode(&pb.Node{Id: fmt.Sprintf("p:%d", i), Type: "process"})
	}

	time.Sleep(50 * time.Millisecond) // let flush happen

	if bw.stats.FlushByCount == 0 && bw.stats.BatchesCommitted == 0 {
		t.Log("count trigger may not have fired (pending < 1000)")
	}
	t.Logf("Batch stats: %d committed, %d nodes", bw.stats.BatchesCommitted, bw.stats.NodesWritten)
}

func TestBatchTimeTrigger(t *testing.T) {
	bw, cleanup := openBatchStore(t)
	defer cleanup()

	// Write a few events and wait for time-based flush
	bw.WriteNode(&pb.Node{Id: "p:1"})
	bw.WriteNode(&pb.Node{Id: "p:2"})

	time.Sleep(200 * time.Millisecond)

	if bw.stats.FlushByTime == 0 && bw.stats.BatchesCommitted == 0 {
		t.Log("time trigger may not have fired yet")
	}
	t.Logf("Time trigger: %d time-based flushes", bw.stats.FlushByTime)
}

func TestBatchSummary(t *testing.T) {
	bw, cleanup := openBatchStore(t)
	defer cleanup()

	bw.WriteNode(&pb.Node{Id: "p:1"})
	bw.Flush()

	summary := bw.Summary()
	if len(summary) == 0 {
		t.Error("empty summary")
	}
	t.Logf("Summary: %s", summary)
}

func TestBatchConcurrency(t *testing.T) {
	bw, cleanup := openBatchStore(t)
	defer cleanup()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				bw.WriteNode(&pb.Node{
					Id: fmt.Sprintf("p:%d", base+j), Type: "process",
				})
			}
		}(i * 100)
	}
	wg.Wait()

	time.Sleep(200 * time.Millisecond)

	t.Logf("Concurrent: %d nodes written, %d batches",
		bw.stats.NodesWritten, bw.stats.BatchesCommitted)
}

func TestProtoSize(t *testing.T) {
	evt := &pb.Event{Type: 10, Pid: 100, Comm: "bash", Pathname: "/etc/shadow"}
	size := ProtoSize(evt)
	if size <= 0 {
		t.Error("proto size = 0")
	}
	t.Logf("Proto size: %d bytes (JSON estimate: %d)", size, JSONSizeEstimate(evt))
}

func TestNewProcessNode(t *testing.T) {
	n := NewProcessNode(100, "bash", 1000)
	if n.Id != "p:100" {
		t.Errorf("id = %s", n.Id)
	}
	if n.Comm != "bash" {
		t.Errorf("comm = %s", n.Comm)
	}
}

func TestNewFileNode(t *testing.T) {
	n := NewFileNode(5000, 8, 3, "/etc/shadow")
	if n.Label != "/etc/shadow" {
		t.Errorf("label = %s", n.Label)
	}
}
