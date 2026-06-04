package alert

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Incident aggregation
// ═══════════════════════════════════════════════════════════════

// Incident correlates multiple alerts from the same attack chain.
type Incident struct {
	ID          string    `json:"id"`
	PatternID   string    `json:"pattern_id"`
	PatternName string    `json:"pattern_name"`
	Severity    string    `json:"severity"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Count       int       `json:"count"`
	Nodes       []string  `json:"nodes"`
	Resolved    bool      `json:"resolved"`
}

// IncidentManager aggregates and deduplicates alerts.
type IncidentManager struct {
	mu         sync.Mutex
	incidents  map[string]*Incident // keyed by pattern + hash of nodes
	window     time.Duration        // merge window (default 5 min)
	resolveAfter time.Duration      // auto-resolve after (default 30 min)
}

// NewIncidentManager creates an incident manager.
func NewIncidentManager() *IncidentManager {
	return &IncidentManager{
		incidents:    make(map[string]*Incident),
		window:       5 * time.Minute,
		resolveAfter: 30 * time.Minute,
	}
}

// Ingest processes a match result and either creates a new incident
// or merges it into an existing one.
func (im *IncidentManager) Ingest(match *MatchResult) *Incident {
	// Create a dedup key: pattern ID + first/last node
	var dedupKey string
	if len(match.Nodes) >= 2 {
		dedupKey = match.Pattern.ID + "|" + match.Nodes[0] + "→" + match.Nodes[len(match.Nodes)-1]
	} else {
		dedupKey = match.Pattern.ID + "|" + strings.Join(match.Nodes, ",")
	}

	im.mu.Lock()
	defer im.mu.Unlock()

	now := time.Now()

	// Check for existing incident in the merge window
	if inc, ok := im.incidents[dedupKey]; ok {
		if now.Sub(inc.LastSeen) < im.window {
			// Merge: update count and timestamp
			inc.Count++
			inc.LastSeen = now

			// Merge unique nodes
			seen := make(map[string]bool)
			for _, n := range inc.Nodes {
				seen[n] = true
			}
			for _, n := range match.Nodes {
				if !seen[n] {
					inc.Nodes = append(inc.Nodes, n)
					seen[n] = true
				}
			}

			log.Printf("[alert] merged into incident %s (count=%d)", inc.ID, inc.Count)
			return nil // Return nil to indicate merge (no new alert needed)
		}
		// Outside merge window — resolve old, create new
		inc.Resolved = true
	}

	// Create new incident
	inc := &Incident{
		ID:          fmt.Sprintf("INC-%s-%d", match.Pattern.ID, now.Unix()),
		PatternID:   match.Pattern.ID,
		PatternName: match.Pattern.Name,
		Severity:    match.Pattern.Severity,
		FirstSeen:   now,
		LastSeen:    now,
		Count:       1,
		Nodes:       match.Nodes,
	}
	im.incidents[dedupKey] = inc

	log.Printf("[alert] NEW INCIDENT %s: %s (severity=%s, nodes=%d)",
		inc.ID, inc.PatternName, inc.Severity, len(inc.Nodes))

	return inc
}

// ResolveOld marks incidents older than resolveAfter as resolved.
func (im *IncidentManager) ResolveOld() int {
	im.mu.Lock()
	defer im.mu.Unlock()

	now := time.Now()
	resolved := 0
	for _, inc := range im.incidents {
		if !inc.Resolved && now.Sub(inc.LastSeen) > im.resolveAfter {
			inc.Resolved = true
			resolved++
			log.Printf("[alert] auto-resolved incident %s (%s)", inc.ID, inc.PatternName)
		}
	}
	return resolved
}

// ActiveIncidents returns all unresolved incidents.
func (im *IncidentManager) ActiveIncidents() []*Incident {
	im.mu.Lock()
	defer im.mu.Unlock()
	var out []*Incident
	for _, inc := range im.incidents {
		if !inc.Resolved {
			out = append(out, inc)
		}
	}
	return out
}

// ResolveIncident manually resolves an incident by ID (case-insensitive).
func (im *IncidentManager) ResolveIncident(id string) bool {
	im.mu.Lock()
	defer im.mu.Unlock()
	for _, inc := range im.incidents {
		if strings.EqualFold(inc.ID, id) {
			inc.Resolved = true
			return true
		}
	}
	return false
}

// IncidentSummary returns a human-readable incident summary.
func (inc *Incident) Summary() string {
	return fmt.Sprintf("[%s] %s — seen %d times, first=%s, path: %s",
		inc.Severity, inc.PatternName, inc.Count,
		inc.FirstSeen.Format("15:04:05"),
		strings.Join(inc.Nodes, " → "))
}
