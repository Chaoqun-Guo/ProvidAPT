// cluster-test-harness — HTTP/JSON API wrapping all v2.2 components
// for the Python integration test script.
//
// Usage: go run . [--port 8722]
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	detect "github.com/Chaoqun-Guo/ProvidAPT/internal/policy/blastradius"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/ja3"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/stitcher/server"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/stitcher/stitch"
	store "github.com/Chaoqun-Guo/ProvidAPT/internal/storage/graphdb"
)

var (
	centralServer = stitch.NewCentralServer()
	correlator    = ja3.NewCentralCorrelator()
	graphDB       = store.NewMemGraphDB()
	globalIndex   = store.NewGlobalIndex()
	blastEngine   = detect.NewBlastRadiusEngine()
	queueMgr      = server.NewEventQueueManager()
	router        = server.NewConsistentHashRouter(nil, 100)
	perfMu        sync.Mutex
)

func main() {
	port := 8722
	if len(os.Args) > 1 && os.Args[1] == "--port" && len(os.Args) > 2 {
		if p, err := strconv.Atoi(os.Args[2]); err == nil {
			port = p
		}
	}

	mux := http.NewServeMux()

	// Stitch endpoints
	mux.HandleFunc("/ingest-outbound", handleIngestOutbound)
	mux.HandleFunc("/ingest-inbound", handleIngestInbound)
	mux.HandleFunc("/stitch/by-agent", handleStitchByAgent)
	mux.HandleFunc("/stitch/edges", handleStitchEdges)
	mux.HandleFunc("/stitch/stats", handleStitchStats)

	// JA3 endpoints
	mux.HandleFunc("/ja3/ingest", handleJA3Ingest)
	mux.HandleFunc("/ja3/clusters", handleJA3Clusters)
	mux.HandleFunc("/ja3/alerts", handleJA3Alerts)
	mux.HandleFunc("/ja3/stats", handleJA3Stats)

	// Graph endpoints
	mux.HandleFunc("/graph/node", handleGraphCreateNode)
	mux.HandleFunc("/graph/subgraph", handleGraphSubgraph)
	mux.HandleFunc("/graph/nodes", handleGraphNodes)
	mux.HandleFunc("/graph/edges", handleGraphEdges)
	mux.HandleFunc("/graph/index", handleGraphIndex)
	mux.HandleFunc("/graph/query-by-host", handleGraphQueryByHost)
	mux.HandleFunc("/graph/backtrack", handleGraphBacktrack)

	// Blast radius
	mux.HandleFunc("/blast/calculate", handleBlastCalculate)

	// Queue (performance)
	mux.HandleFunc("/queue/enqueue", handleQueueEnqueue)
	mux.HandleFunc("/queue/enqueue-batch", handleQueueEnqueueBatch)
	mux.HandleFunc("/queue/stats", handleQueueStats)

	// Router
	mux.HandleFunc("/router/route", handleRouterRoute)
	mux.HandleFunc("/router/add-collector", handleRouterAddCollector)
	mux.HandleFunc("/router/stats", handleRouterStats)

	// Combined
	mux.HandleFunc("/all-stats", handleAllStats)
	mux.HandleFunc("/health", handleHealth)

	addr := fmt.Sprintf(":%d", port)
	log.Printf("[harness] starting cluster test harness on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[harness] %v", err)
	}
}

// ─── JSON helpers ──────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func readJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

// ─── Stitch handlers ──────────────────────────────────────────

func handleIngestOutbound(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, "POST required", 405); return
	}
	var req struct {
		FlowID      string `json:"flow_id"`
		AgentID     string `json:"agent_id"`
		PID         uint32 `json:"pid"`
		Comm        string `json:"comm"`
		SrcIP       string `json:"src_ip"`
		DstIP       string `json:"dst_ip"`
		SrcPort     uint32 `json:"src_port"`
		DstPort     uint32 `json:"dst_port"`
		Tainted     bool   `json:"tainted"`
		TaintSource string `json:"taint_source,omitempty"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, err.Error(), 400); return
	}
	edge := centralServer.IngestOutbound(req.FlowID, req.AgentID, req.PID, req.Comm,
		req.SrcIP, req.DstIP, req.SrcPort, req.DstPort, req.Tainted, req.TaintSource)
	writeJSON(w, map[string]interface{}{
		"stitch_edge": edge,
		"matched":     edge != nil,
	})
}

func handleIngestInbound(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, "POST required", 405); return
	}
	var req struct {
		FlowID  string `json:"flow_id"`
		AgentID string `json:"agent_id"`
		PID     uint32 `json:"pid"`
		Comm    string `json:"comm"`
		SrcIP   string `json:"src_ip"`
		DstIP   string `json:"dst_ip"`
		SrcPort uint32 `json:"src_port"`
		DstPort uint32 `json:"dst_port"`
		Tainted bool   `json:"tainted"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, err.Error(), 400); return
	}
	edge := centralServer.IngestInbound(req.FlowID, req.AgentID, req.PID, req.Comm,
		req.SrcIP, req.DstIP, req.SrcPort, req.DstPort, req.Tainted)
	writeJSON(w, map[string]interface{}{
		"stitch_edge": edge,
		"matched":     edge != nil,
	})
}

func handleStitchByAgent(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		writeError(w, "agent_id required", 400); return
	}
	edges := centralServer.QueryStitchByAgent(agentID)
	writeJSON(w, map[string]interface{}{
		"agent_id": agentID,
		"edges":    edges,
		"count":    len(edges),
	})
}

func handleStitchEdges(w http.ResponseWriter, r *http.Request) {
	stats := centralServer.Stats()
	writeJSON(w, map[string]interface{}{
		"count": stats["stitch_edges"],
	})
}

func handleStitchStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, centralServer.Stats())
}

// ─── JA3 handlers ─────────────────────────────────────────────

func handleJA3Ingest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, "POST required", 405); return
	}
	var req struct {
		JA3        string `json:"ja3"`
		JA3Text    string `json:"ja3_text,omitempty"`
		SourceHost string `json:"source_host"`
		PID        uint32 `json:"pid"`
		Comm       string `json:"comm"`
		DestIP     string `json:"dest_ip"`
		DestPort   uint32 `json:"dest_port"`
		IsAtypical bool   `json:"is_atypical"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, err.Error(), 400); return
	}

	record := &ja3.JA3Record{
		JA3:        req.JA3,
		JA3Text:    req.JA3Text,
		SourceHost: req.SourceHost,
		PID:        req.PID,
		Comm:       req.Comm,
		DestIP:     req.DestIP,
		DestPort:   req.DestPort,
		IsAtypical: req.IsAtypical,
		Timestamp:  time.Now(),
	}
	alert := correlator.Ingest(record)
	writeJSON(w, map[string]interface{}{
		"alert": alert,
		"alerted": alert != nil,
	})
}

func handleJA3Clusters(w http.ResponseWriter, r *http.Request) {
	clusters := correlator.Clusters()
	writeJSON(w, map[string]interface{}{
		"clusters": clusters,
		"count":    len(clusters),
	})
}

func handleJA3Alerts(w http.ResponseWriter, r *http.Request) {
	alerts := correlator.Alerts()
	writeJSON(w, map[string]interface{}{
		"alerts": alerts,
		"count":  len(alerts),
	})
}

func handleJA3Stats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, correlator.Stats())
}

// ─── Graph handlers ───────────────────────────────────────────

func handleGraphCreateNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, "POST required", 405); return
	}
	var req struct {
		NodeType string                 `json:"node_type"`
		ID       string                 `json:"id"`
		Label    string                 `json:"label"`
		HostID   string                 `json:"host_id"`
		AgentID  string                 `json:"agent_id"`
		Props    map[string]interface{} `json:"props,omitempty"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, err.Error(), 400); return
	}
	if req.Props == nil {
		req.Props = make(map[string]interface{})
	}
	req.Props["host_id"] = req.HostID
	req.Props["agent_id"] = req.AgentID

	id, err := graphDB.CreateNode(req.NodeType, req.ID, req.Label, req.Props)
	if err != nil {
		writeError(w, err.Error(), 500); return
	}
	writeJSON(w, map[string]string{"id": id})
}

func handleGraphSubgraph(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, "POST required", 405); return
	}
	var req struct {
		Nodes []store.GlobalNode `json:"nodes"`
		Edges []store.GlobalEdge `json:"edges"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, err.Error(), 400); return
	}
	if err := store.InsertSubgraph(graphDB, req.Nodes, req.Edges); err != nil {
		writeError(w, err.Error(), 500); return
	}
	writeJSON(w, map[string]int{"nodes": len(req.Nodes), "edges": len(req.Edges)})
}

func handleGraphNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := graphDB.QueryNodes("", nil)
	if err != nil {
		writeError(w, err.Error(), 500); return
	}
	writeJSON(w, map[string]interface{}{
		"nodes": nodes,
		"count": len(nodes),
	})
}

func handleGraphEdges(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"edges": graphDB.Stats()["edges"],
	})
}

func handleGraphIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, "POST required", 405); return
	}
	node, err := parseGraphNode(r)
	if err != nil {
		writeError(w, err.Error(), 400); return
	}
	globalIndex.IndexNode(node)
	writeJSON(w, map[string]string{"status": "indexed"})
}

func handleGraphQueryByHost(w http.ResponseWriter, r *http.Request) {
	hostID := r.URL.Query().Get("host_id")
	if hostID == "" {
		writeError(w, "host_id required", 400); return
	}
	entries := globalIndex.QueryByHostID(hostID)
	writeJSON(w, map[string]interface{}{
		"host_id": hostID,
		"entries": entries,
		"count":   len(entries),
	})
}

func handleGraphBacktrack(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		writeError(w, "node_id required", 400); return
	}
	hosts := globalIndex.GlobalBacktrack(nodeID)
	writeJSON(w, map[string]interface{}{
		"node_id": nodeID,
		"hosts":   hosts,
		"count":   len(hosts),
	})
}

func parseGraphNode(r *http.Request) (*store.GlobalNode, error) {
	var req struct {
		ID      string                 `json:"id"`
		Type    string                 `json:"type"`
		Label   string                 `json:"label"`
		HostID  string                 `json:"host_id"`
		AgentID string                 `json:"agent_id"`
		Props   map[string]interface{} `json:"props"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if req.Props == nil {
		req.Props = make(map[string]interface{})
	}
	return &store.GlobalNode{
		ID:      req.ID,
		Type:    req.Type,
		Label:   req.Label,
		HostID:  req.HostID,
		AgentID: req.AgentID,
		Props:   req.Props,
	}, nil
}

// ─── Blast radius handler ─────────────────────────────────────

func handleBlastCalculate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, "POST required", 405); return
	}
	var req struct {
		RootNode     string                `json:"root_node"`
		RootHost     string                `json:"root_host"`
		LateralEdges []detect.LateralEdge  `json:"lateral_edges"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, err.Error(), 400); return
	}
	result := blastEngine.Calculate(req.RootNode, req.RootHost, req.LateralEdges)
	writeJSON(w, map[string]interface{}{
		"result": result,
		"summary": result.Summary(),
	})
}

// ─── Queue (performance) handlers ─────────────────────────────

func handleQueueEnqueue(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, "POST required", 405); return
	}
	var req struct {
		ID        string  `json:"id"`
		HostID    string  `json:"host_id"`
		EventType string  `json:"event_type"`
		RiskScore float64 `json:"risk_score"`
		Tainted   bool    `json:"tainted"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, err.Error(), 400); return
	}
	queueMgr.Enqueue(&server.QueueEvent{
		ID:        req.ID,
		HostID:    req.HostID,
		EventType: req.EventType,
		RiskScore: req.RiskScore,
		Tainted:   req.Tainted,
		Timestamp: time.Now(),
	})
	writeJSON(w, map[string]string{"status": "enqueued"})
}

func handleQueueEnqueueBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, "POST required", 405); return
	}
	var req struct {
		NAgents  int `json:"n_agents"`
		NPerAgent int `json:"n_per_agent"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, err.Error(), 400); return
	}
	if req.NAgents <= 0 { req.NAgents = 100 }
	if req.NPerAgent <= 0 { req.NPerAgent = 100 }

	start := time.Now()
	total := req.NAgents * req.NPerAgent
	eventTypes := []string{"file_open", "net_connect", "proc_exec", "file_write", "dns_query"}

	perfMu.Lock()
	for i := 0; i < req.NAgents; i++ {
		agentID := fmt.Sprintf("agent-%04d", i)
		for j := 0; j < req.NPerAgent; j++ {
			evtType := eventTypes[(i+j)%len(eventTypes)]
			score := float64((i + j) % 100)
			queueMgr.Enqueue(&server.QueueEvent{
				ID:        fmt.Sprintf("evt-%04d-%06d", i, j),
				HostID:    agentID,
				EventType: evtType,
				RiskScore: score,
				Tainted:   score > 80,
				Timestamp: time.Now(),
			})
		}
	}
	perfMu.Unlock()

	elapsed := time.Since(start)
	rps := float64(total) / elapsed.Seconds()

	// Sample memory
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	writeJSON(w, map[string]interface{}{
		"n_agents":     req.NAgents,
		"n_per_agent":  req.NPerAgent,
		"total_events": total,
		"elapsed_ms":   elapsed.Milliseconds(),
		"rps":          int(rps),
		"memory_mb":    memStats.Alloc / 1024 / 1024,
		"heap_mb":      memStats.HeapAlloc / 1024 / 1024,
		"stack_mb":     memStats.StackInuse / 1024 / 1024,
	})
}

func handleQueueStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, queueMgr.Stats())
}

// ─── Router handlers ──────────────────────────────────────────

func handleRouterRoute(w http.ResponseWriter, r *http.Request) {
	hostID := r.URL.Query().Get("host_id")
	if hostID == "" {
		writeError(w, "host_id required", 400); return
	}
	collector := router.Route(hostID)
	writeJSON(w, map[string]string{
		"host_id":    hostID,
		"collector":  collector,
	})
}

func handleRouterAddCollector(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, "POST required", 405); return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, err.Error(), 400); return
	}
	router.AddCollector(req.ID)
	writeJSON(w, map[string]string{"status": "added"})
}

func handleRouterStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, router.Stats())
}

// ─── Combined stats handler ───────────────────────────────────

func handleAllStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"stitch":  centralServer.Stats(),
		"ja3":     correlator.Stats(),
		"graph":   graphDB.Stats(),
		"queue":   queueMgr.Stats(),
		"router":  router.Stats(),
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"status":  "healthy",
		"uptime":  time.Now().String(),
	})
}

