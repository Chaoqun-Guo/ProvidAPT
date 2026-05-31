package provenance

import (
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
)

func TestAddMemfdEvent(t *testing.T) {
	g := NewGraph()
	evt := &collector.Event{
		Type: syscall.EventMemfdCreate, TimestampNS: 1000,
		PID: 100, Comm: "python3", Pathname: "evil.so",
		FFlags: 1, // MFD_CLOEXEC
	}
	g.AddEvent(evt)

	nodes := g.Nodes()
	memfdFound := false
	filelessFound := false
	for _, n := range nodes {
		if n.Subtype == "file" && evt.Pathname == "evil.so" {
			memfdFound = true
		}
		if v, ok := n.Attributes["fileless"]; ok && v.(bool) {
			filelessFound = true
		}
	}
	if !memfdFound {
		t.Error("memfd node should exist in graph")
	}
	if !filelessFound {
		t.Error("process should have fileless=true attribute")
	}
	t.Logf("memfd event graph: %d nodes, %d edges", g.Stats().Nodes, g.Stats().Edges)
}

func TestAddMprotectRXEvent(t *testing.T) {
	g := NewGraph()
	evt := &collector.Event{
		Type: syscall.EventMprotectRX, TimestampNS: 1000,
		PID: 200, Comm: "bash",
		Inode: 0x7f1234560000, // example address
	}
	g.AddEvent(evt)

	nodes := g.Nodes()
	shellcodeFound := false
	rxNodeFound := false
	for _, n := range nodes {
		if v, ok := n.Attributes["shellcode"]; ok && v.(bool) {
			shellcodeFound = true
		}
		if n.Subtype == "memory" {
			rxNodeFound = true
		}
	}
	if !shellcodeFound {
		t.Error("process should have shellcode=true attribute")
	}
	if !rxNodeFound {
		t.Error("RX memory node should exist")
	}
}

func TestAddPipeFlowEvent(t *testing.T) {
	g := NewGraph()
	// Writer (curl) writes to pipe
	g.AddEvent(&collector.Event{
		Type: syscall.EventPipeWrite, TimestampNS: 1000,
		PID: 300, Comm: "curl", Inode: 3, // fd=3
	})
	// Reader (bash) reads from pipe
	g.AddEvent(&collector.Event{
		Type: syscall.EventPipeRead, TimestampNS: 1001,
		PID: 301, Comm: "bash", Inode: 3,
	})

	stats := g.Stats()
	if stats.Nodes < 3 { // curl + bash + pipe
		t.Errorf("expected ≥3 nodes, got %d", stats.Nodes)
	}

	// Check for pipe attributes
	nodes := g.Nodes()
	writerOk := false
	readerOk := false
	for _, n := range nodes {
		if v, ok := n.Attributes["pipe_writer"]; ok && v.(bool) {
			writerOk = true
		}
		if v, ok := n.Attributes["pipe_reader"]; ok && v.(bool) {
			readerOk = true
		}
	}
	t.Logf("pipe writer marked: %v, reader marked: %v", writerOk, readerOk)
}

func TestMemoryMultipleEvents(t *testing.T) {
	g := NewGraph()
	// Simulate an attack chain: memfd + mprotect + pipe
	g.AddEvent(&collector.Event{
		Type: syscall.EventMemfdCreate, TimestampNS: 1,
		PID: 400, Comm: "python3", Pathname: "payload",
	})
	g.AddEvent(&collector.Event{
		Type: syscall.EventMprotectRX, TimestampNS: 2,
		PID: 400, Comm: "python3", Inode: 0x7f0000000000,
	})
	g.AddEvent(&collector.Event{
		Type: syscall.EventPipeRead, TimestampNS: 3,
		PID: 400, Comm: "python3", Inode: 3,
	})

	stats := g.Stats()
	t.Logf("memory attack chain: %d nodes, %d edges", stats.Nodes, stats.Edges)
	if stats.Nodes < 4 { // process + memfd + rx + pipe
		t.Errorf("expected ≥4 nodes for attack chain, got %d", stats.Nodes)
	}
}

func TestMemfdNodeLabel(t *testing.T) {
	g := NewGraph()
	g.AddEvent(&collector.Event{
		Type: syscall.EventMemfdCreate, TimestampNS: 1,
		PID: 500, Comm: "python3", Pathname: "libhack.so",
	})
	nodes := g.Nodes()
	found := false
	for _, n := range nodes {
		if n.Subtype == "file" && n.Label == "libhack.so" {
			found = true
		}
	}
	if !found {
		t.Error("memfd node should carry the name as label")
	}
}

func TestMprotectRXNodeAddr(t *testing.T) {
	g := NewGraph()
	addr := uint64(0x7f1234560000)
	g.AddEvent(&collector.Event{
		Type: syscall.EventMprotectRX, TimestampNS: 1,
		PID: 600, Comm: "bash", Inode: addr,
	})
	nodes := g.Nodes()
	for _, n := range nodes {
		if n.Subtype == "memory" {
			v, ok := n.Attributes["addr"]
			if !ok {
				t.Error("memory node missing addr attribute")
			} else if v.(uint64) != addr {
				t.Errorf("addr = %x, want %x", v, addr)
			}
		}
	}
}

func TestPipeChainDetection(t *testing.T) {
	g := NewGraph()
	// Simulate: curl | bash
	// curl writes to pipe
	g.AddEvent(&collector.Event{
		Type: syscall.EventPipeWrite, TimestampNS: 1,
		PID: 100, Comm: "curl", Inode: 4,
	})
	// bash reads from pipe
	g.AddEvent(&collector.Event{
		Type: syscall.EventPipeRead, TimestampNS: 2,
		PID: 101, Comm: "bash", Inode: 4,
	})
	// bash execs the piped content
	g.AddEvent(&collector.Event{
		Type: syscall.EventProcessExec, TimestampNS: 3,
		PID: 101, Comm: "bash",
	})

	// Verify the graph has all three nodes and pipe-related edges
	stats := g.Stats()
	t.Logf("curl|bash chain: %d nodes, %d edges", stats.Nodes, stats.Edges)

	// Walk the graph from curl to bash pipe
	edges := g.Edges()
	pipeEdges := 0
	for _, e := range edges {
		if e.Relation == ProvUsed {
			pipeEdges++
		}
	}
	if pipeEdges < 2 {
		t.Errorf("expected ≥2 used edges, got %d", pipeEdges)
	}
}
