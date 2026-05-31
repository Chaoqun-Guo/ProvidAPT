package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ── Test helpers ────────────────────────────────────────────

func testGraph(t *testing.T) *provenance.Graph {
	t.Helper()
	g := provenance.NewGraph()
	g.AddEvent(&collector.Event{
		Type: syscall.EventProcessFork, TimestampNS: 1000,
		PID: 1, ChildPID: 100, Comm: "bash",
	})
	g.AddEvent(&collector.Event{
		Type: syscall.EventFileOpen, TimestampNS: 2000,
		PID: 100, Pathname: "/etc/shadow",
		Inode: 5000, DevMajor: 8, DevMinor: 3,
		Comm: "cat",
	})
	return g
}

func testServer(t *testing.T) *Server {
	t.Helper()
	return NewServer(":0", testGraph(t), nil)
}

func apiGet(ts *Server, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	return w
}

// ── Tests ───────────────────────────────────────────────────

func TestStatus(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/status")

	if w.Code != http.StatusOK {
		t.Errorf("status code = %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "running" {
		t.Errorf("status = %v", resp["status"])
	}
}

func TestExport(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/graph/export")

	if w.Code != http.StatusOK {
		t.Errorf("status code = %d", w.Code)
	}

	var resp cytoGraph
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.NodeCount < 2 {
		t.Errorf("nodes = %d, want ≥2", resp.Data.NodeCount)
	}
	if resp.Data.EdgeCount < 1 {
		t.Errorf("edges = %d, want ≥1", resp.Data.EdgeCount)
	}

	// Verify Cytoscape format
	if len(resp.Elements) == 0 {
		t.Fatal("no elements")
	}
	hasNode := false
	hasEdge := false
	for _, el := range resp.Elements {
		if el.Group == "nodes" {
			hasNode = true
			if el.Data.ID == "" {
				t.Error("node missing id")
			}
		}
		if el.Group == "edges" {
			hasEdge = true
			if el.Data.Source == "" || el.Data.Target == "" {
				t.Error("edge missing source/target")
			}
		}
	}
	if !hasNode {
		t.Error("no node elements")
	}
	if !hasEdge {
		t.Error("no edge elements")
	}
}

func TestExportFilterPID(t *testing.T) {
	ts := testServer(t)

	// Filter by PID 100
	w := apiGet(ts, "/api/v1/graph/export?pid=100")
	var resp cytoGraph
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Data.NodeCount == 0 {
		t.Error("expected nodes for PID 100")
	}
	t.Logf("PID=100 export: %d nodes, %d edges", resp.Data.NodeCount, resp.Data.EdgeCount)
}

func TestExportFilterPIDInvalid(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/graph/export?pid=99999")

	var resp cytoGraph
	json.NewDecoder(w.Body).Decode(&resp)
	t.Logf("invalid PID: %d nodes, %d edges", resp.Data.NodeCount, resp.Data.EdgeCount)
}

func TestBackwardTrace(t *testing.T) {
	ts := testServer(t)

	// Trace backward from the process that read shadow
	w := apiGet(ts, "/api/v1/graph/node/p:100/backward")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d: %s", w.Code, w.Body.String())
	}

	var resp cytoGraph
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Data.NodeCount == 0 {
		t.Error("expected nodes in backward trace")
	}
	t.Logf("backward trace from p:100: %d nodes, %d edges",
		resp.Data.NodeCount, resp.Data.EdgeCount)
}

func TestForwardTrace(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/graph/node/p:1/forward")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}

	var resp cytoGraph
	json.NewDecoder(w.Body).Decode(&resp)
	t.Logf("forward trace from p:1: %d nodes, %d edges",
		resp.Data.NodeCount, resp.Data.EdgeCount)
}

func TestBackwardDepthParam(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/graph/node/p:100/backward?depth=2")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestNodeInvalidAction(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/graph/node/p:100/invalid")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected error for invalid action, got %d", w.Code)
	}
}

func TestAlertsEndpoint(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/alerts")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	t.Logf("alerts response: %v", resp)
}

func TestCORSHeaders(t *testing.T) {
	ts := testServer(t)
	handler := corsMiddleware(ts.mux)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/status", nil)
	handler.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("missing CORS header")
	}
}

func TestNotFound(t *testing.T) {
	ts := testServer(t)
	w := apiGet(ts, "/api/v1/nonexistent")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestCytoFormat(t *testing.T) {
	// Direct test of Cytoscape format
	nodes := []*provenance.Node{
		{ID: "p:1", Label: "init", Subtype: "process"},
		{ID: "f:100", Label: "/etc/hosts", Subtype: "file"},
	}
	edges := []*provenance.Edge{
		{ID: "e1", Source: "p:1", Target: "f:100"},
	}

	w := httptest.NewRecorder()
	writeCytoscape(w, nodes, edges)

	var resp cytoGraph
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Elements) != 3 { // 2 nodes + 1 edge
		t.Errorf("elements = %d, want 3", len(resp.Elements))
	}
}

// ── SVG tests ──────────────────────────────────────────────

func TestSVGGeneration(t *testing.T) {
	g := testGraph(t)
	svg, err := generateAlertSVG("test-1", g)
	if err != nil {
		t.Fatalf("generateAlertSVG: %v", err)
	}
	if len(svg) == 0 {
		t.Error("empty SVG")
	}
	if !strings.Contains(string(svg), "<svg") {
		t.Error("SVG missing <svg> tag")
	}
	if !strings.Contains(string(svg), "node-") {
		t.Error("SVG missing node classes")
	}
	t.Logf("SVG size: %d bytes", len(svg))
}

func TestSVGEmptyGraph(t *testing.T) {
	g := provenance.NewGraph()
	svg, err := generateAlertSVG("empty", g)
	if err != nil {
		t.Fatalf("generateAlertSVG: %v", err)
	}
	if len(svg) == 0 {
		t.Error("empty SVG for empty graph")
	}
}

func TestSVGContentType(t *testing.T) {
	g := testGraph(t)
	svg, _ := generateAlertSVG("test", g)
	if !strings.HasPrefix(string(svg), "<svg") {
		t.Error("SVG should start with <svg")
	}
}

// ── Helpers tests ──────────────────────────────────────────

func TestShortRel(t *testing.T) {
	tests := []struct{ in, want string }{
		{"prov:used", "used"},
		{"prov:wasGeneratedBy", "created"},
		{"prov:wasInformedBy", "forked"},
		{"prov:wasDerivedFrom", "derived"},
		{"custom", "custom"},
	}
	for _, tt := range tests {
		got := shortRel(tt.in)
		if got != tt.want {
			t.Errorf("shortRel(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if s := truncate("hello world", 5); s != "he..." {
		t.Errorf("truncate = %q", s)
	}
	if s := truncate("hello", 10); s != "hello" {
		t.Errorf("truncate short = %q", s)
	}
}

func TestQueryInt(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/?depth=5", nil)
	if v := queryInt(r, "depth", 3); v != 5 {
		t.Errorf("queryInt = %d", v)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	if v := queryInt(r2, "depth", 3); v != 3 {
		t.Errorf("queryInt default = %d", v)
	}
}

func TestEscapeXML(t *testing.T) {
	if s := escapeXML("<hello & world>"); s != "&lt;hello &amp; world&gt;" {
		t.Errorf("escape = %q", s)
	}
}
