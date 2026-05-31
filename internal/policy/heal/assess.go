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

// bfsItem is used internally by AssessImpact for BFS traversal.
type bfsItem struct {
	nodeID string
	depth  int
	parent string
	edge   *provenance.Edge
}

// AssessImpact traverses forward from a malicious process node
// to find all successor nodes (files, child procs, networks).
//
// Algorithm:
//   BFS forward from the seed node, following all outgoing edges.
//   Also follows reverse edges to find child processes (fork creates
//   child→parent edge) and generated files (wasGeneratedBy goes file→process).
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

	visited := make(map[string]int)
	queue := []bfsItem{{nodeID: startNodeID, depth: 0}}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		if item.depth >= maxDepth {
			report.Truncated = true
			continue
		}

		// Follow outgoing edges (forward direction)
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
			report.discoverNode(targetID, targetNode, e.Relation, item.depth+1, &queue, item.nodeID, e)
		}

		// Follow incoming edges (reverse direction):
		//   - fork creates wasInformedBy(child, parent) — child is the source
		//   - wasGeneratedBy(file, process) — file is the source
		//   These edges flow toward the process, so the related node is the source.
		for _, e := range graph.Edges() {
			if e.Target != item.nodeID {
				continue
			}
			sourceID := e.Source

			if _, seen := visited[sourceID]; seen {
				continue
			}
			visited[sourceID] = item.depth + 1

			sourceNode, _ := graph.LookupNode(sourceID)
			report.discoverNode(sourceID, sourceNode, e.Relation, item.depth+1, &queue, item.nodeID, e)
		}
	}

	report.TotalImpacted = len(report.ChildProcesses) +
		len(report.FilesWritten) + len(report.FilesRead) +
		len(report.C2Addresses)

	return report
}

// discoverNode processes a discovered node and adds it to the report.
func (report *ImpactReport) discoverNode(nodeID string, node *provenance.Node, relation string,
	depth int, queue *[]bfsItem, parent string, edge *provenance.Edge) {
	if node == nil {
		return
	}

	switch node.Subtype {
	case "process":
		childPID, _ := parsePID(nodeID)
		child := ProcessNode{
			PID:    childPID,
			NodeID: nodeID,
			Comm:   safeLabel(node),
			Depth:  depth,
		}
		report.ChildProcesses = append(report.ChildProcesses, child)
		*queue = append(*queue, bfsItem{
			nodeID: nodeID,
			depth:  depth,
			parent: parent,
			edge:   edge,
		})

	case "file":
		file := FileNode{
			Path:   safeLabel(node),
			NodeID: nodeID,
			Action: classifyFileAction(relation),
		}
		report.FilesWritten = append(report.FilesWritten, file)

	case "network":
		net := NetworkNode{
			Address: safeLabel(node),
			NodeID:  nodeID,
			Action:  "connect",
		}
		report.C2Addresses = append(report.C2Addresses, net)

	case "credential":
		report.CredChanges = append(report.CredChanges, safeLabel(node))
	}
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
