// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Load-based self-healing — backpressure and agent throttling
// ═══════════════════════════════════════════════════════════════

// ServerLoad indicates the central server's current load level.
type ServerLoad int

const (
	LoadLow      ServerLoad = 0 // normal operation
	LoadMedium   ServerLoad = 1 // elevated — monitor
	LoadHigh     ServerLoad = 2 // high — request agent throttling
	LoadCritical ServerLoad = 3 // critical — force agent degradation
)

// LoadController monitors server load and notifies agents.
type LoadController struct {
	mu            sync.Mutex
	load          ServerLoad
	queue         *EventQueueManager
	agents        map[string]*AgentStats
	throttleLevel int // 0-3, broadcast to agents
	lastAdjust    time.Time

	// Thresholds
	highThreshold int // queue depth triggering high load
	critThreshold int // queue depth triggering critical load
	checkInterval time.Duration
}

// AgentStats tracks an agent's contribution to load.
type AgentStats struct {
	AgentID       string    `json:"agent_id"`
	EventsSent    int64     `json:"events_sent"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	ThrottleLevel int       `json:"throttle_level"` // 0-3
}

// NewLoadController creates a load controller.
func NewLoadController(queue *EventQueueManager) *LoadController {
	return &LoadController{
		queue:         queue,
		agents:        make(map[string]*AgentStats),
		highThreshold: 10000,
		critThreshold: 50000,
		checkInterval: 5 * time.Second,
		lastAdjust:    time.Now(),
	}
}

// Tick evaluates server load and adjusts throttle levels.
// Called periodically (every 5 seconds).
func (lc *LoadController) Tick() {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	queueDepth := 0
	if lc.queue != nil {
		queueDepth = lc.queue.Size()
	}

	oldLoad := lc.load
	oldThrottle := lc.throttleLevel

	// Determine load level
	switch {
	case queueDepth >= lc.critThreshold:
		lc.load = LoadCritical
		lc.throttleLevel = 3
	case queueDepth >= lc.highThreshold:
		lc.load = LoadHigh
		lc.throttleLevel = 2
	case queueDepth >= lc.highThreshold/2:
		lc.load = LoadMedium
		lc.throttleLevel = 1
	default:
		if lc.queue.Size() < lc.highThreshold/4 {
			lc.load = LoadLow
			lc.throttleLevel = 0
		}
	}

	// Hysteresis: don't oscillate
	if lc.load == oldLoad {
		return
	}

	// Notify agents of throttle level change
	if lc.throttleLevel != oldThrottle {
		lc.notifyAgentsLocked()
		lc.lastAdjust = time.Now()
		log.Printf("[throttle] load=%d queue=%d throttle=%d → %d",
			lc.load, queueDepth, oldThrottle, lc.throttleLevel)
	}
}

// GetThrottleLevel returns the current throttle level for agents.
func (lc *LoadController) GetThrottleLevel() int {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.throttleLevel
}

// RegisterAgent tracks an agent for throttle notifications.
func (lc *LoadController) RegisterAgent(agentID string) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.agents[agentID] = &AgentStats{
		AgentID:       agentID,
		LastHeartbeat: time.Now(),
	}
}

// Heartbeat updates an agent's last seen timestamp.
func (lc *LoadController) Heartbeat(agentID string) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if agent, ok := lc.agents[agentID]; ok {
		agent.LastHeartbeat = time.Now()
		agent.EventsSent++
	}
}

// notifyAgentsLocked broadcasts the throttle level to all agents.
// In production, this sends gRPC messages to each agent.
func (lc *LoadController) notifyAgentsLocked() {
	for agentID := range lc.agents {
		log.Printf("[throttle] notify %s: set throttle=%d", agentID, lc.throttleLevel)
		// In production: rpcClient.SendThrottle(agentID, lc.throttleLevel)
	}

	switch lc.throttleLevel {
	case 0:
		log.Println("[throttle] ALL CLEAR — normal operation")
	case 1:
		log.Println("[throttle] LIGHT — agents increase aggregation window")
	case 2:
		log.Println("[throttle] HIGH — agents filter low-risk events")
	case 3:
		log.Println("[throttle] CRITICAL — agents drop all but critical events")
	}
}

// Stats returns load controller statistics.
func (lc *LoadController) Stats() map[string]interface{} {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return map[string]interface{}{
		"load_level":     int(lc.load),
		"throttle_level": lc.throttleLevel,
		"agents":         len(lc.agents),
		"high_threshold": lc.highThreshold,
		"crit_threshold": lc.critThreshold,
	}
}
