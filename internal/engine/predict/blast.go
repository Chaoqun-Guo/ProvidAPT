package predict

import (
	"fmt"
	"strings"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ═══════════════════════════════════════════════════════════════
// Blast radius calculation
// ═══════════════════════════════════════════════════════════════

// BlastRadius describes all assets reachable from a compromised process.
type BlastRadius struct {
	CompromisedNode string        `json:"compromised_node"`
	CompromisedComm string        `json:"compromised_comm"`
	Files           []Asset       `json:"files"`
	NetworkEndpoints []Asset     `json:"network_endpoints"`
	Processes       []Asset      `json:"processes"`
	Credentials     []Asset      `json:"credentials"`
	TotalImpacted   int           `json:"total_impacted"`
}

// Asset is a single reachable resource.
type Asset struct {
	ID        string `json:"id"`
	Type      string `json:"type"`      // file, network, process, credential
	Label     string `json:"label"`     // file path, IP, process name
	Critical  bool   `json:"critical"`  // is this a critical asset?
	Distance  int    `json:"distance"`  // hops from compromised node
}

// BlastCalculator computes the blast radius from a compromised node.
type BlastCalculator struct {
	criticalPaths []string
}

// NewBlastCalculator creates a blast radius calculator.
func NewBlastCalculator() *BlastCalculator {
	return &BlastCalculator{
		criticalPaths: []string{
			"/etc/shadow", "/etc/passwd", "/etc/sudoers",
			"/root/", "/.ssh/", "/var/log/auth.log",
			"/etc/kubernetes/", "/var/lib/mysql/",
			"/etc/ssl/", "/etc/letsencrypt/",
		},
	}
}

// Calculate computes the blast radius from a compromised node.
func (bc *BlastCalculator) Calculate(graph *provenance.Graph, startNodeID string) *BlastRadius {
	result := &BlastRadius{
		CompromisedNode: startNodeID,
	}
	if n, ok := graph.LookupNode(startNodeID); ok && n != nil {
		result.CompromisedComm = n.Label
	}

	// BFS to find all reachable assets
	visited := make(map[string]bool)
	queue := []bfsAsset{{nodeID: startNodeID, distance: 0}}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		if visited[item.nodeID] {
			continue
		}
		visited[item.nodeID] = true

		// Check what type of asset this is
		if n, ok := graph.LookupNode(item.nodeID); ok && n != nil {
			asset := Asset{
				ID:       n.ID,
				Type:     n.Subtype,
				Label:    n.Label,
				Critical: bc.isCritical(n),
				Distance: item.distance,
			}
			if item.distance > 0 {
				result.addAsset(asset)
			}
		}

		// Enqueue neighbours
		if item.distance < 10 { // max depth
			for _, e := range graph.Edges() {
				var nextID string
				if e.Source == item.nodeID {
					nextID = e.Target
				} else if e.Target == item.nodeID {
					nextID = e.Source
				} else {
					continue
				}
				if !visited[nextID] {
					queue = append(queue, bfsAsset{nodeID: nextID, distance: item.distance + 1})
				}
			}
		}
	}

	result.TotalImpacted = len(result.Files) + len(result.NetworkEndpoints) +
		len(result.Processes) + len(result.Credentials)
	return result
}

// bfsAsset is a BFS queue entry.
type bfsAsset struct {
	nodeID   string
	distance int
}

func (br *BlastRadius) addAsset(a Asset) {
	switch a.Type {
	case "file":
		br.Files = append(br.Files, a)
	case "network":
		br.NetworkEndpoints = append(br.NetworkEndpoints, a)
	case "process":
		br.Processes = append(br.Processes, a)
	case "credential":
		br.Credentials = append(br.Credentials, a)
	}
}

func (bc *BlastCalculator) isCritical(n *provenance.Node) bool {
	label := strings.ToLower(n.Label)
	for _, cp := range bc.criticalPaths {
		if strings.HasPrefix(label, cp) {
			return true
		}
	}
	if v, ok := n.Attributes["setuid"]; ok && v.(bool) {
		return true
	}
	if v, ok := n.Attributes["fileless"]; ok && v.(bool) {
		return true
	}
	return false
}

// Summary returns a human-readable blast radius summary.
func (br *BlastRadius) Summary() string {
	fileLabel := ""
	if len(br.Files) > 0 {
		fileLabel = ", " + br.Files[0].Label
	}
	return fmt.Sprintf("Blast Radius from %s (%s): %d files%s, %d network, %d processes, %d creds",
		br.CompromisedComm, br.CompromisedNode,
		len(br.Files), fileLabel,
		len(br.NetworkEndpoints),
		len(br.Processes), len(br.Credentials))
}
