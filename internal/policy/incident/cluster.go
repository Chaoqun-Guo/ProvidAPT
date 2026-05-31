// Package alert provides optimized alerting with incident clustering,
// topology-based risk scoring, and context-enriched reports.
package incident

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Incident — clustered alert group
// ═══════════════════════════════════════════════════════════════

// Incident clusters multiple related alerts into one group.
type Incident struct {
	ID          string       `json:"id"`
	AlertIDs    []string     `json:"alert_ids"`
	Nodes       []string     `json:"nodes"`       // all nodes in this incident
	TotalAlerts int          `json:"total_alerts"`
	FirstSeen   time.Time    `json:"first_seen"`
	LastSeen    time.Time    `json:"last_seen"`
	RiskScore   float64      `json:"risk_score"`
	EntryPoint  string       `json:"entry_point"`
	FarthestPoint string     `json:"farthest_point"`
	Briefing    string       `json:"briefing"`
	Resolved    bool         `json:"resolved"`
}

// AlertNode is a single alert with graph context.
type AlertNode struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`       // "taint", "file_write", "net_connect"
	PID       uint32    `json:"pid,omitempty"`
	Comm      string    `json:"comm,omitempty"`
	Target    string    `json:"target,omitempty"`
	Score     float64   `json:"score"`
	Timestamp time.Time `json:"timestamp"`
}

// IncidentCluster groups alerts by connected component analysis.
type IncidentCluster struct {
	mu        sync.Mutex
	alerts    []*AlertNode
	incidents []*Incident
	window    time.Duration // merge window (default 5 min)
}

// NewIncidentCluster creates an incident cluster.
func NewIncidentCluster() *IncidentCluster {
	return &IncidentCluster{
		window: 5 * time.Minute,
	}
}

// Ingest adds an alert and returns the incident it belongs to.
func (ic *IncidentCluster) Ingest(alert *AlertNode) *Incident {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	ic.alerts = append(ic.alerts, alert)
	now := time.Now()

	// Find or create incident by connected component analysis
	// First: check if this alert connects to any existing incident
	for _, inc := range ic.incidents {
		if inc.Resolved {
			continue
		}
		if now.Sub(inc.LastSeen) > ic.window {
			continue
		}
		if ic.isConnected(inc, alert) {
			inc.AlertIDs = append(inc.AlertIDs, alert.ID)
			inc.Nodes = append(inc.Nodes, fmt.Sprintf("%s:%s", alert.Type, alert.Target))
			inc.TotalAlerts++
			inc.LastSeen = now
			inc.RiskScore = ic.recalculateScore(inc)
			return inc
		}
	}

	// Create new incident
	inc := &Incident{
		ID:        fmt.Sprintf("INC-%d", len(ic.incidents)+1),
		AlertIDs:  []string{alert.ID},
		Nodes:     []string{fmt.Sprintf("%s:%s", alert.Type, alert.Target)},
		TotalAlerts: 1,
		FirstSeen: now,
		LastSeen:  now,
		RiskScore: alert.Score,
	}
	ic.incidents = append(ic.incidents, inc)
	return inc
}

// isConnected checks if an alert shares nodes with an incident.
func (ic *IncidentCluster) isConnected(inc *Incident, alert *AlertNode) bool {
	for _, node := range inc.Nodes {
		if strings.Contains(node, alert.Comm) ||
			strings.Contains(node, alert.Target) {
			return true
		}
	}
	return false
}

// recalculateScore re-evaluates the incident risk score.
func (ic *IncidentCluster) recalculateScore(inc *Incident) float64 {
	score := 0.0
	for _, a := range ic.alerts {
		for _, aid := range inc.AlertIDs {
			if a.ID == aid {
				score += a.Score
			}
		}
	}
	return score
}

// ActiveIncidents returns all unresolved incidents.
func (ic *IncidentCluster) ActiveIncidents() []*Incident {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	var out []*Incident
	for _, inc := range ic.incidents {
		if !inc.Resolved {
			out = append(out, inc)
		}
	}
	return out
}

// ResolveIncident marks an incident as resolved.
func (ic *IncidentCluster) ResolveIncident(id string) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	for _, inc := range ic.incidents {
		if inc.ID == id {
			inc.Resolved = true
			return
		}
	}
}

// Stats returns clustering statistics.
func (ic *IncidentCluster) Stats() map[string]interface{} {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	return map[string]interface{}{
		"total_alerts":     len(ic.alerts),
		"total_incidents":  len(ic.incidents),
		"active_incidents": func() int {
			n := 0
			for _, inc := range ic.incidents {
				if !inc.Resolved {
					n++
				}
			}
			return n
		}(),
	}
}
