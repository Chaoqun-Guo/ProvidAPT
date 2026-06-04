package export

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Lateral movement stitching algorithm
//
// Detects: Machine A's Process X connected to Machine B → Machine B
// spawned a shell/process from sshd at approximately the same time.
//
// Algorithm:
//   1. For each incoming socket event from Agent A (outgoing conn):
//      Check if any agent B has an sshd/sshd-related process spawn
//      event within a ±5 second window.
//   2. If match found, create a CrossHostEdge linking:
//        p:A:pid_X ──lateral──▶ p:B:pid_sshd_child
//   3. The edge is added to the global stitched graph.
// ═══════════════════════════════════════════════════════════════

// Stitcher correlates socket events across agents.
type Stitcher struct {
	mu         sync.RWMutex
	agents     map[string]*AgentState
	edges      []*CrossHostEdge
	edgeIndex  map[string]bool // dedup key → true

	// Config
	TimeWindow time.Duration // correlation time window (default 5s)
	MinConfidence float64   // minimum confidence to emit (default 0.5)
}

// AgentState tracks the recent history of one agent.
type AgentState struct {
	AgentID       string
	Sockets       []*SocketEvent // recent socket events
	ProcessSpawns []*ProcessSpawn
}

// ProcessSpawn represents a new process creation (fork/exec).
type ProcessSpawn struct {
	AgentID    string
	PID        uint32
	Comm       string
	ParentPID  uint32
	ParentComm string
	Timestamp  int64
}

// NewStitcher creates a correlation engine.
func NewStitcher() *Stitcher {
	return &Stitcher{
		agents:        make(map[string]*AgentState),
		edges:         make([]*CrossHostEdge, 0),
		edgeIndex:     make(map[string]bool),
		TimeWindow:    5 * time.Second,
		MinConfidence: 0.5,
	}
}

// IngestSocketEvent processes a socket event for stitching.
func (st *Stitcher) IngestSocketEvent(evt *SocketEvent) {
	st.mu.Lock()
	defer st.mu.Unlock()

	state := st.getOrCreateAgent(evt.AgentID)
	state.Sockets = append(state.Sockets, evt)
	st.evictOld(state)

	// Check if this outgoing connection matches any incoming
	// process spawn across all agents
	if evt.ConnStatus == "SYN_SENT" || evt.ConnStatus == "ESTABLISHED" {
		st.matchLateral(evt)
	}
}

// IngestProcessSpawn registers a new process creation.
func (st *Stitcher) IngestProcessSpawn(spawn *ProcessSpawn) {
	st.mu.Lock()
	defer st.mu.Unlock()

	state := st.getOrCreateAgent(spawn.AgentID)
	state.ProcessSpawns = append(state.ProcessSpawns, spawn)

	// Only keep last 10 minutes
	cutoff := time.Now().Add(-10 * time.Minute).UnixNano()
	for len(state.ProcessSpawns) > 0 && state.ProcessSpawns[0].Timestamp < cutoff {
		state.ProcessSpawns = state.ProcessSpawns[1:]
	}
}

// matchLateral is the core correlation algorithm.
// It looks for: this agent's socket connects to agent B → agent B
// has an sshd spawn at approximately the same time.
func (st *Stitcher) matchLateral(evt *SocketEvent) {
	targetHost := extractHost(evt.DstIP)
	if targetHost == "" {
		return
	}

	evtTime := time.Unix(0, evt.Timestamp)
	window := st.TimeWindow

	// Check all agents for matching process spawns
	for agentID, state := range st.agents {
		if agentID == evt.AgentID {
			continue // skip self
		}
		if !strings.Contains(agentID, targetHost) {
			continue // agent ID must contain target hostname hint
		}

		for _, spawn := range state.ProcessSpawns {
			spawnTime := time.Unix(0, spawn.Timestamp)
			diff := evtTime.Sub(spawnTime)
			if diff < 0 {
				diff = -diff
			}

			if diff > window {
				continue // outside time window
			}

			// Check if parent is a known network service
			if isNetworkService(spawn.ParentComm) {
				edge := &CrossHostEdge{
					SourceAgent: evt.AgentID,
					SourceNode:  fmt.Sprintf("p:%s:%d", evt.AgentID, evt.PID),
					SourcePID:   evt.PID,
					TargetAgent: agentID,
					TargetNode:  fmt.Sprintf("p:%s:%d", agentID, spawn.PID),
					TargetPID:   spawn.PID,
					SocketKey:   evt.SocketKey(),
					SeqHash:     evt.SeqHash,
					Timestamp:   evt.Timestamp,
					Confidence:  st.calcConfidence(diff, evt),
				}

				key := fmt.Sprintf("%s→%s", edge.SourceNode, edge.TargetNode)
				if !st.edgeIndex[key] {
					st.edgeIndex[key] = true
					st.edges = append(st.edges, edge)
					log.Printf("[stitch] LATERAL: %s → %s (ssh=%s, conf=%.2f, delta=%v)",
						edge.SourceNode, edge.TargetNode,
						spawn.ParentComm, edge.Confidence, diff)
				}
			}
		}
	}
}

// calcConfidence computes correlation confidence based on time delta
// and TCP fingerprint match.
func (st *Stitcher) calcConfidence(delta time.Duration, evt *SocketEvent) float64 {
	// Time proximity: 5s window → 1.0, 0s delta → 0.5 (minimum)
	timeScore := 1.0 - (float64(delta) / float64(st.TimeWindow))
	if timeScore < 0.5 {
		timeScore = 0.5
	}

	// Seq hash provides additional confidence if non-zero
	seqScore := 0.0
	if evt.SeqHash != 0 {
		seqScore = 0.2 // small bonus for having TCP fingerprint
	}

	conf := timeScore + seqScore
	if conf > 1.0 {
		conf = 1.0
	}
	return conf
}

func (st *Stitcher) getOrCreateAgent(id string) *AgentState {
	if s, ok := st.agents[id]; ok {
		return s
	}
	s := &AgentState{AgentID: id}
	st.agents[id] = s
	return s
}

func (st *Stitcher) evictOld(state *AgentState) {
	cutoff := time.Now().Add(-5 * time.Minute).UnixNano()
	for len(state.Sockets) > 0 && state.Sockets[0].Timestamp < cutoff {
		state.Sockets = state.Sockets[1:]
	}
}

// StitchedEdges returns all detected cross-host edges.
func (st *Stitcher) StitchedEdges() []*CrossHostEdge {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]*CrossHostEdge, len(st.edges))
	copy(out, st.edges)
	return out
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

func isNetworkService(comm string) bool {
	services := []string{"sshd", "nginx", "apache2", "httpd",
		"smbd", "rpcbind", "smtpd", "dovecot", "systemd-logind"}
	for _, s := range services {
		if s == comm {
			return true
		}
	}
	return false
}

func extractHost(ip string) string {
	// In production, map IP to known hostname/agent ID
	// For now, return the last two octets as a simple identifier
	parts := strings.Split(ip, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return ""
}

// ── Integration: hook into the Server ───────────────────────

// stitchEvents is called by the server when new socket events arrive.
func (s *Server) stitchEvents(batch []*SocketEvent) {
	stitcher := NewStitcher()
	for _, evt := range batch {
		stitcher.IngestSocketEvent(evt)
	}

	s.mu.Lock()
	s.stitchedEdges = append(s.stitchedEdges, stitcher.StitchedEdges()...)
	s.mu.Unlock()
}
