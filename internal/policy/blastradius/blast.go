package blastradius

import (
	"fmt"
	"log"
	"strings"
)

// ═══════════════════════════════════════════════════════════════
// Global blast radius — datacenter-wide impact analysis
// ═══════════════════════════════════════════════════════════════

// BlastRadiusResult shows all affected resources across the data center.
type BlastRadiusResult struct {
	RootNode    string       `json:"root_node"`
	RootHost    string       `json:"root_host"`
	AffectedHosts []HostImpact `json:"affected_hosts"`
	TotalHosts  int          `json:"total_hosts"`
	TotalAssets int          `json:"total_assets"`
	MaxDepth    int          `json:"max_depth"`
}

// HostImpact describes the impact on a single host.
type HostImpact struct {
	HostID     string   `json:"host_id"`
	Processes  []string `json:"processes"`
	Files      []string `json:"files"`
	Networks   []string `json:"networks"`
	IsCritical bool     `json:"is_critical"`
	RiskScore  float64  `json:"risk_score"`
}

// BlastRadiusEngine calculates the datacenter-wide impact of a compromise.
//
// Algorithm:
//   1. Start from an infected host/node
//   2. BFS traverse the global graph following lateral movement edges
//   3. For each reachable host, aggregate impacted resources
//   4. Calculate cumulative risk score
//   5. Return complete blast radius report
type BlastRadiusEngine struct {
	maxDepth int
}

// NewBlastRadiusEngine creates a blast radius analyzer.
func NewBlastRadiusEngine() *BlastRadiusEngine {
	return &BlastRadiusEngine{maxDepth: 10}
}

// Calculate computes the blast radius from an initial compromised node.
//
// In production, this queries the global graph database. For the
// framework, it works on a set of declared edges.
func (bre *BlastRadiusEngine) Calculate(rootNode, rootHost string, lateralEdges []LateralEdge) *BlastRadiusResult {
	result := &BlastRadiusResult{
		RootNode:    rootNode,
		RootHost:    rootHost,
		MaxDepth:    bre.maxDepth,
	}

	// BFS traversal
	type bfsItem struct {
		host  string
		depth int
		path  []string
	}

	visited := make(map[string]bool)
	var hosts []HostImpact
	queue := []bfsItem{{host: rootHost, depth: 0, path: []string{rootHost}}}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		if visited[item.host] {
			continue
		}
		visited[item.host] = true

		impact := HostImpact{
			HostID:    item.host,
			Processes: bre.getHostProcesses(item.host, lateralEdges),
			Files:     bre.getHostFiles(item.host, lateralEdges),
			Networks:  bre.getHostNetworks(item.host, lateralEdges),
		}
		impact.RiskScore = bre.calcHostRisk(impact)
		impact.IsCritical = impact.RiskScore > 50
		hosts = append(hosts, impact)

		if item.depth >= bre.maxDepth {
			continue
		}

		// Follow lateral edges
		for _, edge := range lateralEdges {
			if edge.SourceHost == item.host && !visited[edge.TargetHost] {
				queue = append(queue, bfsItem{
					host:  edge.TargetHost,
					depth: item.depth + 1,
					path:  append(item.path, edge.TargetHost),
				})
			}
		}
	}

	result.AffectedHosts = hosts
	result.TotalHosts = len(hosts)
	for _, h := range hosts {
		result.TotalAssets += len(h.Processes) + len(h.Files) + len(h.Networks)
	}

	return result
}

// LateralEdge describes a known lateral movement path.
type LateralEdge struct {
	SourceHost string `json:"source_host"`
	TargetHost string `json:"target_host"`
	Relation   string `json:"relation"`   // "ssh", "rdp", "wmi", "scp"
	PID        uint32 `json:"pid"`
	Comm       string `json:"comm"`
	Tainted    bool   `json:"tainted"`
}

// getHostProcesses collects processes on a host.
func (bre *BlastRadiusEngine) getHostProcesses(hostID string, edges []LateralEdge) []string {
	var procs []string
	for _, e := range edges {
		if e.SourceHost == hostID && e.Comm != "" {
			procs = append(procs, fmt.Sprintf("%s(PID %d)", e.Comm, e.PID))
		}
	}
	return unique(procs)
}

func (bre *BlastRadiusEngine) getHostFiles(hostID string, edges []LateralEdge) []string {
	return nil
}

func (bre *BlastRadiusEngine) getHostNetworks(hostID string, edges []LateralEdge) []string {
	return nil
}

func (bre *BlastRadiusEngine) calcHostRisk(impact HostImpact) float64 {
	score := float64(len(impact.Processes)*10 + len(impact.Files)*5 + len(impact.Networks)*15)
	if score > 100 {
		score = 100
	}
	return score
}

func unique(s []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// Summary returns a human-readable blast radius summary.
func (br *BlastRadiusResult) Summary() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Blast Radius from %s (%s):\n", br.RootNode, br.RootHost))
	b.WriteString(fmt.Sprintf("  Affected hosts: %d\n", br.TotalHosts))
	b.WriteString(fmt.Sprintf("  Total assets:   %d\n", br.TotalAssets))
	for _, h := range br.AffectedHosts {
		critical := ""
		if h.IsCritical {
			critical = " [CRITICAL]"
		}
		b.WriteString(fmt.Sprintf("  %s: %d procs, %d files%s\n",
			h.HostID, len(h.Processes), len(h.Files), critical))
	}
	return b.String()
}

// Ensure log is used
var _ = log.Printf
