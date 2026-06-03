package store

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

func tempDir(t *testing.T) string {
	dir, err := os.MkdirTemp("", "providapt-store-test-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func openStore(t *testing.T) *Store {
	s, err := Open(tempDir(t)+"/pebble", nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func TestOpenClose(t *testing.T) {
	s := openStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestPutGetNode(t *testing.T) {
	s := openStore(t)
	defer s.Close()

	n := &provenance.Node{
		ID:       "p:1234",
		ProvType: "prov:Activity",
		Subtype:  "process",
		Label:    "nginx",
	}

	if err := s.PutNode(n); err != nil {
		t.Fatalf("PutNode: %v", err)
	}

	got, err := s.GetNode("p:1234")
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got == nil {
		t.Fatal("GetNode returned nil")
	}
	if got.ID != "p:1234" || got.Label != "nginx" {
		t.Errorf("got %+v, want {ID:p:1234 Label:nginx}", got)
	}
}

func TestGetNodeNotFound(t *testing.T) {
	s := openStore(t)
	defer s.Close()

	n, err := s.GetNode("nonexistent")
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if n != nil {
		t.Error("expected nil for nonexistent node")
	}
}

func TestDeleteNode(t *testing.T) {
	s := openStore(t)
	defer s.Close()

	s.PutNode(&provenance.Node{ID: "p:1", Label: "test"})
	s.DeleteNode("p:1")

	n, _ := s.GetNode("p:1")
	if n != nil {
		t.Error("node should be deleted")
	}
}

func TestPutEdge(t *testing.T) {
	s := openStore(t)
	defer s.Close()

	e := &provenance.Edge{
		Source:   "p:1",
		Target:   "f:100",
		Relation: "prov:used",
		Count:    1,
	}
	if err := s.PutEdge(e); err != nil {
		t.Fatalf("PutEdge: %v", err)
	}
}

func TestGetEdgesByTimeRange(t *testing.T) {
	s := openStore(t)
	defer s.Close()

	base := time.Now()

	for i := 0; i < 5; i++ {
		e := &provenance.Edge{
			Source:    "p:1",
			Target:    "f:100",
			Relation:  "prov:used",
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Count:     1,
		}
		s.PutEdge(e)
	}

	// Flush all writes
	s.Flush()

	// Query range [base+1s, base+4s) → should return edges with ts 1,2,3
	start := uint64(base.Add(1 * time.Second).UnixNano())
	end := uint64(base.Add(4 * time.Second).UnixNano())

	edges, err := s.GetEdgesByTimeRange(start, end)
	if err != nil {
		t.Fatalf("GetEdgesByTimeRange: %v", err)
	}
	if len(edges) != 3 {
		t.Errorf("expected 3 edges in range, got %d", len(edges))
	}
}

func TestEdgeCount(t *testing.T) {
	s := openStore(t)
	defer s.Close()

	for i := 0; i < 3; i++ {
		s.PutEdge(&provenance.Edge{
			Source:   "p:1",
			Target:   fmt.Sprintf("f:%d", 100+i),
			Relation: "prov:used",
		})
	}
	s.Flush()

	count, err := s.EdgeCount()
	if err != nil {
		t.Fatalf("EdgeCount: %v", err)
	}
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
}

func TestBatchFlush(t *testing.T) {
	s := openStore(t)
	defer s.Close()

	// Put many edges to trigger auto-flush
	for i := 0; i < 500; i++ {
		s.PutEdge(&provenance.Edge{
			Source:   "p:1",
			Target:   fmt.Sprintf("f:%d", i),
			Relation: "prov:used",
		})
	}
	// Auto-flush should have triggered at least once
	count, _ := s.EdgeCount()
	if count < 500 {
		t.Errorf("expected >= 500 edges after batch, got %d", count)
	}
}

func TestStats(t *testing.T) {
	s := openStore(t)
	defer s.Close()

	stats := s.Stats()
	if stats == nil {
		t.Error("Stats returned nil")
	}
	if _, ok := stats["disk_bytes"]; !ok {
		t.Error("Stats missing disk_bytes")
	}
}
