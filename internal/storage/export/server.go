// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Server — central collector that receives telemetry from agents
// ═══════════════════════════════════════════════════════════════

// Server receives telemetry from multiple agents and runs the
// cross-host correlation engine.
type Server struct {
	addr string

	mu            sync.RWMutex
	socketEvents  []*SocketEvent
	recentSockets map[string][]*SocketEvent // agentID → events (last 5 min)
	stitchedEdges []*CrossHostEdge
	stitchEnabled bool

	mux    *http.ServeMux
	stopCh chan struct{}
}

// NewServer creates a central correlation server.
func NewServer(addr string) *Server {
	s := &Server{
		addr:          addr,
		recentSockets: make(map[string][]*SocketEvent),
		stitchedEdges: make([]*CrossHostEdge, 0),
		stitchEnabled: true,
		stopCh:        make(chan struct{}),
	}
	s.mux = s.router()
	return s
}

func (s *Server) router() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/socket-events", s.handleSocketEvents)
	mux.HandleFunc("GET /api/v1/stitched-graph", s.handleStitchedGraph)
	mux.HandleFunc("GET /api/v1/stats", s.handleStats)
	return mux
}

// Start begins listening.
func (s *Server) Start() error {
	log.Printf("[export/server] listening on %s (stitching=%v)", s.addr, s.stitchEnabled)
	return http.ListenAndServe(s.addr, s.mux)
}

// ── Handlers ────────────────────────────────────────────────

func (s *Server) handleSocketEvents(w http.ResponseWriter, r *http.Request) {
	var batch []*SocketEvent
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.socketEvents = append(s.socketEvents, batch...)
	for _, evt := range batch {
		key := evt.AgentID
		s.recentSockets[key] = append(s.recentSockets[key], evt)
		// Keep only last 5 minutes
		cutoff := time.Now().Add(-5 * time.Minute).UnixNano()
		for len(s.recentSockets[key]) > 0 && s.recentSockets[key][0].Timestamp < cutoff {
			s.recentSockets[key] = s.recentSockets[key][1:]
		}
	}
	s.mu.Unlock()

	// Run lateral movement stitching
	if s.stitchEnabled {
		go s.stitchEvents(batch)
	}

	if err := json.NewEncoder(w).Encode(ReportAck{
		Received: len(batch),
		Status:   "ok",
	}); err != nil {
		log.Printf("[export] encode ack: %v", err)
	}
}

func (s *Server) handleStitchedGraph(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"stitched_edges": s.stitchedEdges,
		"total_agents":   len(s.recentSockets),
	}); err != nil {
		log.Printf("[export] encode stitched graph: %v", err)
	}
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"total_events":   len(s.socketEvents),
		"active_agents":  len(s.recentSockets),
		"stitched_edges": len(s.stitchedEdges),
	}); err != nil {
		log.Printf("[export] encode stats: %v", err)
	}
}
