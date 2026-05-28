// Package api provides a lightweight HTTP API for the ProvidAPT
// provenance graph, supporting Cytoscape.js-compatible graph export,
// interactive node backtracking, and alert SVG snapshots.
//
// All endpoints return JSON (except SVG which returns image/svg+xml).
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/backtrace"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/store"
)

// ═══════════════════════════════════════════════════════════════
// Server
// ═══════════════════════════════════════════════════════════════

type Server struct {
	addr       string
	graph      *provenance.Graph
	store      *store.Store
	backtracer *backtrace.Backtracer
	mux        *http.ServeMux
}

func NewServer(addr string, graph *provenance.Graph, st *store.Store) *Server {
	s := &Server{
		addr:       addr,
		graph:      graph,
		store:      st,
		backtracer: backtrace.New(graph, st),
	}
	s.mux = s.buildMux()
	return s
}

func (s *Server) Start() error {
	log.Printf("[api] listening on %s", s.addr)
	return http.ListenAndServe(s.addr, corsMiddleware(loggingMiddleware(s.mux)))
}

func (s *Server) buildMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", s.jsonHandler(s.handleStatus))
	mux.HandleFunc("/api/v1/graph/export", s.jsonHandler(s.handleExport))
	mux.HandleFunc("/api/v1/graph/node/", s.jsonHandler(s.handleNode)) // parsed from path
	mux.HandleFunc("/api/v1/alerts", s.jsonHandler(s.handleAlerts))
	mux.HandleFunc("/api/v1/", s.notFound)
	return mux
}

// jsonHandler wraps a handler to set JSON content type and handle errors.
func (s *Server) jsonHandler(fn func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-ProvidAPT", "1.0")
		if err := fn(w, r); err != nil {
			log.Printf("[api] error: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		}
	}
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

// ═══════════════════════════════════════════════════════════════
// Handlers
// ═══════════════════════════════════════════════════════════════

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) error {
	stats := s.graph.Stats()
	return json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "running",
		"nodes":     stats.Nodes,
		"edges":     stats.Edges,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// ── Graph export: /api/v1/graph/export?pid=1234&start=...&end=... ──

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	nodes := s.graph.Nodes()
	edges := s.graph.Edges()

	if pid := q.Get("pid"); pid != "" {
		pidPrefix := "p:" + pid
		nodes, edges = filterByPID(nodes, edges, pidPrefix)
	}

	return writeCytoscape(w, nodes, edges)
}

// ── Node operations: /api/v1/graph/node/{id}/backward or /forward ──

func (s *Server) handleNode(w http.ResponseWriter, r *http.Request) error {
	// Parse path: /api/v1/graph/node/<id>/<action>
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/graph/node/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 {
		return fmt.Errorf("usage: /api/v1/graph/node/<id>/backward|forward")
	}
	nodeID := parts[0]
	action := parts[1]
	depth := queryInt(r, "depth", 5)

	switch action {
	case "backward":
		return s.backward(w, nodeID, depth)
	case "forward":
		return s.forward(w, nodeID, depth)
	default:
		return fmt.Errorf("unknown action: %s (use backward or forward)", action)
	}
}

func (s *Server) backward(w http.ResponseWriter, nodeID string, depth int) error {
	result, err := s.backtracer.Trace(&backtrace.TraceRequest{
		StartID:  nodeID,
		MaxDepth: depth,
	})
	if err != nil {
		return fmt.Errorf("trace: %w", err)
	}
	var nodes []*provenance.Node
	var edges []*provenance.Edge
	for _, seg := range result.Segments {
		nodes = append(nodes, seg.Nodes...)
		edges = append(edges, seg.Edges...)
	}
	return writeCytoscape(w, nodes, edges)
}

func (s *Server) forward(w http.ResponseWriter, nodeID string, depth int) error {
	seen := make(map[string]bool)
	var nodes []*provenance.Node
	var edges []*provenance.Edge
	queue := []string{nodeID}

	for d := 0; len(queue) > 0 && d < depth; d++ {
		var next []string
		for _, id := range queue {
			if seen[id] {
				continue
			}
			seen[id] = true
			if n, ok := s.graph.LookupNode(id); ok && n != nil {
				nodes = append(nodes, n)
			}
			for _, e := range s.graph.Edges() {
				if e.Source == id && !seen[e.Target] {
					edges = append(edges, e)
					next = append(next, e.Target)
				}
			}
		}
		queue = next
	}
	return writeCytoscape(w, nodes, edges)
}

// ── Alerts: /api/v1/alerts ──────────────────────────────────

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) error {
	alerts := loadAlerts("")
	// Check for /alerts/{id}/svg sub-path
	if rest := strings.TrimPrefix(r.URL.Path, "/api/v1/alerts"); rest != "" && rest != "/" {
		return s.handleAlertSVG(w, r, strings.TrimPrefix(rest, "/"))
	}
	return json.NewEncoder(w).Encode(map[string]interface{}{
		"alerts": alerts,
		"count":  len(alerts),
	})
}

func (s *Server) handleAlertSVG(w http.ResponseWriter, r *http.Request, path string) error {
	// Parse: <id>/svg
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 || parts[1] != "svg" {
		return fmt.Errorf("usage: /api/v1/alerts/<id>/svg")
	}
	alertID := parts[0]

	svg, err := generateAlertSVG(alertID, s.graph)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Write(svg)
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Middleware
// ═══════════════════════════════════════════════════════════════

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[api] %s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

// ═══════════════════════════════════════════════════════════════
// Cytoscape.js JSON writer
// ═══════════════════════════════════════════════════════════════

type cytoGraph struct {
	Data     cytoMeta      `json:"data"`
	Elements []cytoElement `json:"elements"`
}

type cytoMeta struct {
	Generated string `json:"generated"`
	NodeCount int    `json:"node_count"`
	EdgeCount int    `json:"edge_count"`
}

type cytoElement struct {
	Group string       `json:"group"`
	Data  cytoElemData `json:"data"`
}

type cytoElemData struct {
	ID       string `json:"id,omitempty"`
	Source   string `json:"source,omitempty"`
	Target   string `json:"target,omitempty"`
	Label    string `json:"label,omitempty"`
	NodeType string `json:"type,omitempty"`
	Class    string `json:"class,omitempty"`
}

func writeCytoscape(w http.ResponseWriter, nodes []*provenance.Node, edges []*provenance.Edge) error {
	g := cytoGraph{
		Data: cytoMeta{
			Generated: time.Now().UTC().Format(time.RFC3339Nano),
			NodeCount: len(nodes),
			EdgeCount: len(edges),
		},
	}
	for _, n := range nodes {
		l := n.Label
		if l == "" {
			l = n.ID
		}
		g.Elements = append(g.Elements, cytoElement{
			Group: "nodes",
			Data: cytoElemData{
				ID: n.ID, Label: l, NodeType: n.Subtype,
				Class: n.Subtype,
			},
		})
	}
	for _, e := range edges {
		g.Elements = append(g.Elements, cytoElement{
			Group: "edges",
			Data: cytoElemData{
				ID: e.ID, Source: e.Source, Target: e.Target,
				Label: shortRel(e.Relation),
				Class: "edge-" + shortRel(e.Relation),
			},
		})
	}
	return json.NewEncoder(w).Encode(g)
}

func shortRel(rel string) string {
	switch rel {
	case "prov:used":
		return "used"
	case "prov:wasGeneratedBy":
		return "created"
	case "prov:wasInformedBy":
		return "forked"
	case "prov:wasDerivedFrom":
		return "derived"
	case "prov:hadSecurityContext":
		return "context"
	}
	return rel
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

func queryInt(r *http.Request, key string, def int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}

func filterByPID(nodes []*provenance.Node, edges []*provenance.Edge, prefix string) ([]*provenance.Node, []*provenance.Edge) {
	keepNode := make(map[string]bool)
	for _, n := range nodes {
		if strings.HasPrefix(n.ID, prefix) || strings.HasPrefix(n.ID, prefix+"#") {
			keepNode[n.ID] = true
		}
	}
	var keptEdges []*provenance.Edge
	edgeSet := make(map[string]bool)
	for _, e := range edges {
		if keepNode[e.Source] || keepNode[e.Target] {
			edgeSet[e.ID] = true
			keepNode[e.Source] = true
			keepNode[e.Target] = true
			keptEdges = append(keptEdges, e)
		}
	}
	var keptNodes []*provenance.Node
	for _, n := range nodes {
		if keepNode[n.ID] {
			keptNodes = append(keptNodes, n)
		}
	}
	return keptNodes, keptEdges
}

func loadAlerts(path string) []map[string]interface{} {
	if path == "" {
		path = "/var/log/providapt/alerts.json"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var alerts []map[string]interface{}
	if err := json.Unmarshal(data, &alerts); err != nil {
		return nil
	}
	return alerts
}
