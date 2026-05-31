// Package heal provides system self-healing capabilities for
// ProvidAPT.  Given a malicious process node, it can:
//
//   1. Assess attack impact — traverse all successor nodes
//   2. Roll back changes — kill processes, quarantine files,
//      trigger BTRFS/ZFS snapshot rollback
//   3. Block C2 communication — integrate with iptables/nftables
package heal

import (
	"fmt"
	"strings"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ═══════════════════════════════════════════════════════════════
// Impact assessment
// ═══════════════════════════════════════════════════════════════

// ImpactReport describes all resources affected by a malicious process.
type ImpactReport struct {
	MaliciousPID   uint32         `json:"malicious_pid"`
	MaliciousNode  string         `json:"malicious_node"`
	MaliciousComm  string         `json:"malicious_comm"`
	ChildProcesses []ProcessNode `json:"child_processes"`
	FilesWritten   []FileNode     `json:"files_written"`
	FilesRead      []FileNode     `json:"files_read"`
	C2Addresses    []NetworkNode  `json:"c2_addresses"`
	CredChanges    []string       `json:"cred_changes,omitempty"`
	TotalImpacted  int            `json:"total_impacted"`
	MaxDepth       int            `json:"max_depth"`
	Truncated      bool           `json:"truncated"`
}

// ProcessNode represents an affected child process.
type ProcessNode struct {
	PID      uint32 `json:"pid"`
	NodeID   string `json:"node_id"`
	Comm     string `json:"comm"`
	Depth    int    `json:"depth"`
}

// FileNode represents an affected file.
type FileNode struct {
	Path   string `json:"path"`
	NodeID string `json:"node_id"`
	Action string `json:"action"` // "written", "read"
}

// NetworkNode represents a C2 communication target.
type NetworkNode struct {
	Address  string `json:"address"`
	NodeID   string `json:"node_id"`
	Action   string `json:"action"` // "connect", "accept"
}

// AssessImpact traverses forward from a malicious process node
// to find all successor nodes (files, child procs, networks).
//
// Algorithm:
//   BFS forward from the seed node, following all outgoing edges.
//   Depth-limited to prevent explosion (default maxDepth=5).
func AssessImpact(graph *provenance.Graph, startNodeID string, maxDepth int) *ImpactReport {
	if maxDepth <= 0 {
		maxDepth = 5
	}

	report := &ImpactReport{
		MaliciousNode: startNodeID,
		MaxDepth:     maxDepth,
	}

	// Extract PID from node ID (format: "p:<pid>")
	pid, _ := parsePID(startNodeID)
	report.MaliciousPID = pid

	// Get process comm
	if n, ok := graph.LookupNode(startNodeID); ok && n != nil {
		report.MaliciousComm = n.Label
	}

	// BFS forward traversal
	type bfsItem struct {
		nodeID string
		depth  int
		parent string
		edge   *provenance.Edge
	}

	visited := make(map[string]int)
	queue := []bfsItem{{nodeID: startNodeID, depth: 0}}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		if item.depth >= maxDepth {
			report.Truncated = true
			continue
		}

		// Find all outgoing edges
		for _, e := range graph.Edges() {
			if e.Source != item.nodeID {
				continue
			}
			targetID := e.Target

			if _, seen := visited[targetID]; seen {
				continue
			}
			visited[targetID] = item.depth + 1

			targetNode, _ := graph.LookupNode(targetID)

			switch {
			case targetNode != nil && targetNode.Subtype == "process":
				childPID, _ := parsePID(targetID)
				child := ProcessNode{
					PID:    childPID,
					NodeID: targetID,
					Comm:   safeLabel(targetNode),
					Depth:  item.depth + 1,
				}
				report.ChildProcesses = append(report.ChildProcesses, child)

				// Recurse into child processes
				queue = append(queue, bfsItem{
					nodeID: targetID,
					depth:  item.depth + 1,
					parent: item.nodeID,
					edge:   e,
				})

			case targetNode != nil && targetNode.Subtype == "file":
				file := FileNode{
					Path:   safeLabel(targetNode),
					NodeID: targetID,
					Action: classifyFileAction(e.Relation),
				}
				report.FilesWritten = append(report.FilesWritten, file)

			case targetNode != nil && targetNode.Subtype == "network":
				net := NetworkNode{
					Address: safeLabel(targetNode),
					NodeID:  targetID,
					Action:  "connect",
				}
				report.C2Addresses = append(report.C2Addresses, net)

			case targetNode != nil && targetNode.Subtype == "credential":
				report.CredChanges = append(report.CredChanges, safeLabel(targetNode))
			}
		}
	}

	report.TotalImpacted = len(report.ChildProcesses) +
		len(report.FilesWritten) + len(report.FilesRead) +
		len(report.C2Addresses)

	return report
}

// ── Helpers ─────────────────────────────────────────────────

// parsePID extracts a PID from a node ID like "p:1234".
func parsePID(nodeID string) (uint32, bool) {
	if !strings.HasPrefix(nodeID, "p:") {
		return 0, false
	}
	var pid uint32
	n, _ := fmt.Sscanf(nodeID, "p:%d", &pid)
	return pid, n == 1
}

func safeLabel(n *provenance.Node) string {
	if n == nil {
		return "?"
	}
	if n.Label != "" {
		return n.Label
	}
	return n.ID
}

func classifyFileAction(rel string) string {
	switch rel {
	case "prov:wasGeneratedBy":
		return "written"
	case "prov:used":
		return "read"
	default:
		return "affected"
	}
}
