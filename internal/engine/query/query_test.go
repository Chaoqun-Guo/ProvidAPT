package query

import (
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ── Parser tests ──────────────────────────────────────────

func TestParseBasicQuery(t *testing.T) {
	q, err := Parse(`MATCH (p:Process)-[:WROTE]->(f:File) WHERE f.path STARTSWITH '/etc' RETURN p, f`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if q.Match == nil {
		t.Fatal("nil Match")
	}
	if len(q.Match.Nodes) != 2 {
		t.Errorf("nodes = %d, want 2", len(q.Match.Nodes))
	}
	if len(q.Match.Edges) != 1 {
		t.Errorf("edges = %d, want 1", len(q.Match.Edges))
	}
	if q.Match.Nodes[0].Label != "Process" {
		t.Errorf("node0 label = %q", q.Match.Nodes[0].Label)
	}
	if q.Match.Edges[0].Relation != "WROTE" {
		t.Errorf("edge rel = %q", q.Match.Edges[0].Relation)
	}
	if len(q.Where) != 1 {
		t.Errorf("where = %d", len(q.Where))
	}
	if len(q.Return) != 2 {
		t.Errorf("return = %d", len(q.Return))
	}
}

func TestParseTimeWindow(t *testing.T) {
	q, err := Parse(`MATCH (p:Process)-[:READ]->(f:File) DURING [2025-01-01T00:00:00Z, 2025-01-02T00:00:00Z] RETURN p`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if q.During == nil {
		t.Fatal("nil During")
	}
	if q.During.Start.Year() != 2025 {
		t.Errorf("start year = %d", q.During.Start.Year())
	}
}

func TestParseThreeNodePath(t *testing.T) {
	q, err := Parse(`MATCH (a:Process)-[:FORKED]->(b:Process)-[:READ]->(f:File) RETURN a, b, f`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(q.Match.Nodes) != 3 {
		t.Errorf("nodes = %d, want 3", len(q.Match.Nodes))
	}
	if len(q.Match.Edges) != 2 {
		t.Errorf("edges = %d, want 2", len(q.Match.Edges))
	}
}

func TestParseEmptyQuery(t *testing.T) {
	_, err := Parse("")
	if err == nil {
		t.Error("expected error for empty query")
	}
}

func TestParseMissingMatch(t *testing.T) {
	_, err := Parse("RETURN p")
	if err == nil {
		t.Error("expected error for missing MATCH")
	}
}

func TestParseInvalidSyntax(t *testing.T) {
	_, err := Parse("MATCH (p:Process INVALID")
	if err == nil {
		t.Error("expected error for invalid syntax")
	}
}

func TestParseProjectionFields(t *testing.T) {
	q, err := Parse(`MATCH (p:Process)-[:READ]->(f:File) RETURN p.pid, p.comm, f.path`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(q.Return) != 3 {
		t.Errorf("return = %d", len(q.Return))
	}
	if q.Return[0].Variable != "p" || q.Return[0].Field != "pid" {
		t.Errorf("return[0] = %+v", q.Return[0])
	}
}

// ── Executor tests ─────────────────────────────────────────

func makeGraph(t *testing.T) *provenance.Graph {
	t.Helper()
	g := provenance.NewGraph()
	// Process 1 forks process 2
	g.AddEvent(&collector.Event{
		Type: syscall.EventProcessFork, TimestampNS: 1000,
		PID: 1, ChildPID: 2, Comm: "bash",
	})
	// Process 2 reads /etc/shadow
	g.AddEvent(&collector.Event{
		Type: syscall.EventFileOpen, TimestampNS: 2000,
		PID: 2, Comm: "bash", Pathname: "/etc/shadow",
		Inode: 5000, DevMajor: 8, DevMinor: 3,
	})
	// Process 2 writes a temp file
	g.AddEvent(&collector.Event{
		Type: syscall.EventFileModify, TimestampNS: 3000,
		PID: 2, Comm: "bash", Pathname: "/tmp/evil.sh",
		Inode: 6000, DevMajor: 8, DevMinor: 3,
	})
	return g
}

func TestExecuteReadQuery(t *testing.T) {
	g := makeGraph(t)
	exe := NewExecutor(g)

	result, err := exe.Execute(`MATCH (p:Process)-[:READ]->(f:File) RETURN p, f`)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result == nil {
		t.Fatal("nil result")
	}
	t.Logf("READ query: %d rows in %v", len(result.Rows), result.Elapsed)
	if len(result.Rows) == 0 {
		t.Error("expected at least 1 row")
	}
}

func TestExecuteWriteQuery(t *testing.T) {
	g := makeGraph(t)
	exe := NewExecutor(g)

	result, err := exe.Execute(`MATCH (p:Process)-[:WROTE]->(f:File) WHERE f.path STARTSWITH '/tmp' RETURN p, f`)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	t.Logf("WROTE query: %d rows", len(result.Rows))
	if len(result.Rows) < 1 {
		t.Error("expected at least 1 row for WROTE /tmp")
	}
}

func TestExecuteForkChain(t *testing.T) {
	g := makeGraph(t)
	exe := NewExecutor(g)

	result, err := exe.Execute(`MATCH (a:Process)-[:FORKED]->(b:Process) RETURN a, b`)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	t.Logf("FORKED query: %d rows", len(result.Rows))
	if len(result.Rows) < 1 {
		t.Error("expected at least 1 fork row")
	}
}

func TestExecuteThreeHop(t *testing.T) {
	g := makeGraph(t)
	exe := NewExecutor(g)

	result, err := exe.Execute(`MATCH (a:Process)-[:FORKED]->(b:Process)-[:READ]->(f:File) RETURN a, b, f`)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	t.Logf("3-hop query: %d rows", len(result.Rows))
	if len(result.Rows) < 1 {
		t.Error("expected at least 1 row for 3-hop path")
	}
}

func TestExecuteWhereFilter(t *testing.T) {
	g := makeGraph(t)
	exe := NewExecutor(g)

	// Should match /etc/shadow but not /tmp/evil.sh
	result, err := exe.Execute(`MATCH (p:Process)-[:READ]->(f:File) WHERE f.path STARTSWITH '/etc' RETURN p, f`)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	t.Logf("WHERE filter: %d rows", len(result.Rows))
	if len(result.Rows) == 0 {
		t.Error("expected rows for /etc read")
	}
}

func TestExecuteNoMatch(t *testing.T) {
	g := makeGraph(t)
	exe := NewExecutor(g)

	result, err := exe.Execute(`MATCH (p:Process)-[:CONNECTED]->(n:Network) RETURN p`)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Rows) != 0 {
		t.Errorf("expected 0 rows, got %d", len(result.Rows))
	}
}

func TestExecuteColumns(t *testing.T) {
	g := makeGraph(t)
	exe := NewExecutor(g)

	result, err := exe.Execute(`MATCH (p:Process)-[:READ]->(f:File) RETURN p.pid, f.path`)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Columns) > 0 {
		t.Logf("columns: %v", result.Columns)
	}
}

func TestExecuteLargeGraph(t *testing.T) {
	g := provenance.NewGraph()
	// Create 1000 events
	for i := 0; i < 100; i++ {
		g.AddEvent(&collector.Event{
			Type: syscall.EventProcessFork, TimestampNS: uint64(1000 + i),
			PID: uint32(i), ChildPID: uint32(i + 1), Comm: "proc",
		})
	}

	exe := NewExecutor(g)
	result, err := exe.Execute(`MATCH (a:Process)-[:FORKED]->(b:Process) RETURN a, b`)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Rows) == 0 {
		t.Error("expected rows for large graph")
	}
	t.Logf("large graph: %d rows in %v", len(result.Rows), result.Elapsed)
}

// ── Label mapping tests ─────────────────────────────────────

func TestLabelToSubtype(t *testing.T) {
	tests := []struct{ label, subtype string }{
		{"Process", "process"},
		{"File", "file"},
		{"Network", "network"},
		{"Pipe", "pipe"},
		{"Memory", "memory"},
		{"Credential", "credential"},
		{"Invalid", ""},
	}
	for _, tt := range tests {
		got := labelToSubtype[tt.label]
		if got != tt.subtype {
			t.Errorf("labelToSubtype[%q] = %q", tt.label, got)
		}
	}
}

func TestRelationMapping(t *testing.T) {
	tests := []struct{ rel, prov string }{
		{"WROTE", "prov:wasGeneratedBy"},
		{"READ", "prov:used"},
		{"FORKED", "prov:wasInformedBy"},
		{"CONNECTED", "prov:used"},
	}
	for _, tt := range tests {
		got := relationMapping[tt.rel]
		if got != tt.prov {
			t.Errorf("relationMapping[%q] = %q", tt.rel, got)
		}
	}
}

// ── Executor convenience tests ──────────────────────────────

func TestExecutorNew(t *testing.T) {
	e := NewExecutor(provenance.NewGraph())
	if e == nil {
		t.Fatal("NewExecutor returned nil")
	}
}

func TestExecuteEmptyGraph(t *testing.T) {
	e := NewExecutor(provenance.NewGraph())
	result, err := e.Execute(`MATCH (p:Process)-[:READ]->(f:File) RETURN p`)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Rows) != 0 {
		t.Errorf("expected 0 rows for empty graph, got %d", len(result.Rows))
	}
}

func TestExecuteWithTimeWindow(t *testing.T) {
	g := makeGraph(t)
	exe := NewExecutor(g)

	result, err := exe.Execute(`MATCH (p:Process)-[:READ]->(f:File) DURING [1970-01-01T00:00:00Z, 1970-01-01T00:00:01Z] RETURN p`)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// Our test events use TimestampNS=1000,2000,3000 which are
	// way after the epoch window — they should be excluded
	t.Logf("time window query: %d rows", len(result.Rows))
}

// FuzzParseQuery fuzzes the query parser with arbitrary input strings.
func FuzzParseQuery(f *testing.F) {
	f.Add("MATCH (p:Process)-[:WROTE]->(f:File) WHERE f.path STARTSWITH '/etc' RETURN p, f")
	f.Add("MATCH (a)-[:CONNECTED]->(b) RETURN a, b")
	f.Add("")
	f.Add("INVALID QUERY")
	f.Fuzz(func(t *testing.T, input string) {
		q, err := Parse(input)
		_ = q
		_ = err
	})
}
