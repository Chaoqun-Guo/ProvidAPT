// Package query provides a high-level query interface for the
// ProvidAPT v2 storage layer.  It supports:
//
//   - Lookup by PID  → process node + all associated edges
//   - Lookup by Inode → file node + all associated edges
//   - Full node detail with attributes
//   - Time-range edge filtering
package graphquery

import (
	"fmt"
	"time"

	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
)

// Store defines the storage operations needed by QueryEngine.
type Store interface {
	GetNodeByPID(pid uint32) (*pb.Node, error)
	GetNodeByInode(inode uint64) (*pb.Node, error)
	GetNode(nodeType, nodeID string) (*pb.Node, error)
	GetEdgesBySource(source string) ([]*pb.Edge, error)
	GetEdgesByTarget(target string) ([]*pb.Edge, error)
	GetEdgesByTimeRange(startNs, endNs uint64) ([]*pb.Edge, error)
}

// ═══════════════════════════════════════════════════════════════
// Query Result
// ═══════════════════════════════════════════════════════════════

// NodeDetail is the complete result of a node query.
type NodeDetail struct {
	Node  *pb.Node   `json:"node"`
	Edges []*pb.Edge `json:"edges"`
}

// QueryEngine provides graph query operations.
type QueryEngine struct {
	store Store
}

// New creates a query engine.
func New(st Store) *QueryEngine {
	return &QueryEngine{store: st}
}

// ─── By PID ─────────────────────────────────────────────────

// GetProcessByPID retrieves a process node and all its edges.
func (qe *QueryEngine) GetProcessByPID(pid uint32) (*NodeDetail, error) {
	node, err := qe.store.GetNodeByPID(pid)
	if err != nil {
		return nil, fmt.Errorf("get node by pid %d: %w", pid, err)
	}
	if node == nil {
		return nil, nil
	}
	return qe.getDetail(node)
}

// ─── By Inode ───────────────────────────────────────────────

// GetFileByInode retrieves a file node and all its edges.
func (qe *QueryEngine) GetFileByInode(inode uint64) (*NodeDetail, error) {
	node, err := qe.store.GetNodeByInode(inode)
	if err != nil {
		return nil, fmt.Errorf("get node by inode %d: %w", inode, err)
	}
	if node == nil {
		return nil, nil
	}
	return qe.getDetail(node)
}

// ─── By ID ──────────────────────────────────────────────────

// GetNodeByID retrieves any node by its type-specific ID.
func (qe *QueryEngine) GetNodeByID(nodeType, nodeID string) (*NodeDetail, error) {
	node, err := qe.store.GetNode(nodeType, nodeID)
	if err != nil {
		return nil, fmt.Errorf("get node %s/%s: %w", nodeType, nodeID, err)
	}
	if node == nil {
		return nil, nil
	}
	return qe.getDetail(node)
}

// ─── Time-range edge query ─────────────────────────────────

// GetEdgesInRange returns all edges in the given time window.
func (qe *QueryEngine) GetEdgesInRange(start, end time.Time) ([]*pb.Edge, error) {
	return qe.store.GetEdgesByTimeRange(
		uint64(start.UnixNano()),
		uint64(end.UnixNano()),
	)
}

// ─── Internal ───────────────────────────────────────────────

// getDetail enriches a node with its edges.
func (qe *QueryEngine) getDetail(node *pb.Node) (*NodeDetail, error) {
	detail := &NodeDetail{
		Node:  node,
		Edges: make([]*pb.Edge, 0),
	}

	// Outgoing edges
	out, err := qe.store.GetEdgesBySource(node.Id)
	if err != nil {
		return nil, fmt.Errorf("get outgoing edges: %w", err)
	}
	detail.Edges = append(detail.Edges, out...)

	// Incoming edges (via reverse index)
	in, err := qe.store.GetEdgesByTarget(node.Id)
	if err != nil {
		return nil, fmt.Errorf("get incoming edges: %w", err)
	}
	detail.Edges = append(detail.Edges, in...)

	return detail, nil
}

// ─── Display helpers ────────────────────────────────────────

// FormatNode returns a human-readable node representation.
func FormatNode(n *pb.Node) string {
	if n == nil {
		return "(nil)"
	}
	return fmt.Sprintf("[%s] %s — label=%s pid=%d inode=%d",
		n.Type, n.Id, n.Label, n.Pid, n.Inode)
}

// FormatEdge returns a human-readable edge representation.
func FormatEdge(e *pb.Edge) string {
	return fmt.Sprintf("%s ──%s──▶ %s (count=%d)",
		e.Source, e.Relation, e.Target, e.Count)
}
