package provenance

import (
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/internal/syscall"
)

// Graph is a thread-safe, in-memory provenance DAG built from
// kernel events.  Nodes and edges follow the W3C PROV data model.
//
// CamFlow-inspired features:
//   - Entity versioning — writes create new version nodes (wasDerivedFrom)
//   - Credential state machine — setuid/capset → credential entity nodes
//   - Path pruning — periodic dead code elimination of non-interesting paths
//
// The graph guarantees:
//   - Node deduplication (same logical entity → same node)
//   - Edge deduplication   (same relation+source+target → count incremented)
//   - No cycles at construction (events are temporal by nature)
//   - Concurrent-safe via sync.RWMutex
type Graph struct {
	mu         sync.RWMutex
	nodes      map[string]*Node
	edges      map[string]*Edge
	edgeOrder  []string

	firstTS   uint64
	startTime time.Time

	// CamFlow-inspired extensions
	versionTracker *VersionTracker
	credTracker    *CredTracker
}

// Stats is returned by Graph.Stats().
type Stats struct {
	Nodes int
	Edges int
}

// NewGraph creates an empty provenance graph with CamFlow-inspired
// versioning, credential tracking, and pruning support.
func NewGraph() *Graph {
	return &Graph{
		nodes:          make(map[string]*Node),
		edges:          make(map[string]*Edge),
		edgeOrder:      make([]string, 0, 4096),
		startTime:      time.Now(),
		versionTracker: NewVersionTracker(),
		credTracker:    NewCredTracker(),
	}
}

// ── Event ingestion ──────────────────────────────────────────

// AddEvent maps a kernel event to PROV relations and updates the graph.
// Thread-safe.
func (g *Graph) AddEvent(evt *collector.Event) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.recordFirstTS(evt.TimestampNS)
	ts := g.nsToTime(evt.TimestampNS)

	switch evt.Type {
	case syscall.EventProcessFork:
		g.addFork(evt, ts)
	case syscall.EventProcessExec:
		g.addExec(evt, ts)
	case syscall.EventFileOpen:
		g.addFileUse(evt, ts)
	case syscall.EventFileCreate, syscall.EventFileModify:
		g.addFileGenerate(evt, ts)
	case syscall.EventFileDelete:
		g.addFileUse(evt, ts) // deletion also counts as "use"
	case syscall.EventMemfdCreate, syscall.EventMprotectRX,
		syscall.EventPipeWrite, syscall.EventPipeRead:
		g.addMemoryEvent(evt, ts)
	}
}

// ── Fork ─────────────────────────────────────────────────────

// addFork maps: wasInformedBy(child, parent)
func (g *Graph) addFork(evt *collector.Event, ts time.Time) {
	parentID := nodeID("p", evt.PID)
	childID := nodeID("p", evt.ChildPID)

	parent := g.getOrCreateNode(parentID, ProvActivity, SubProcess,
		evt.Comm, ts)
	parent.setAttr("pid", evt.PID)
	parent.setAttr("uid", evt.UID)
	parent.touch(ts)

	child := g.getOrCreateNode(childID, ProvActivity, SubProcess,
		evt.Comm, ts)
	child.setAttr("pid", evt.ChildPID)
	child.touch(ts)

	g.addEdge(ProvWasInformedBy, childID, parentID, ts, map[string]interface{}{
		"pid":      evt.PID,
		"child_pid": evt.ChildPID,
	})
}

// ── Exec ─────────────────────────────────────────────────────

// addExec maps: used(process, binary_file)
// Also invokes credential tracking for setuid detection.
func (g *Graph) addExec(evt *collector.Event, ts time.Time) {
	procID := nodeID("p", evt.PID)
	proc := g.getOrCreateNode(procID, ProvActivity, SubProcess,
		evt.Comm, ts)
	proc.upsertAttr("pid", evt.PID)
	proc.upsertAttr("uid", evt.UID)
	proc.upsertAttr("comm", evt.Comm)
	if evt.Flags&syscall.EventFlagExecSetuid != 0 {
		proc.upsertAttr("setuid", true)
	}
	proc.touch(ts)

	// Credential state machine: detect privilege transitions
	credID := g.credTracker.OnExec(evt, ts, g)
	if credID != "" {
		proc.upsertAttr("credential", credID)
	}

	// Edge: process used the binary
	if evt.Pathname != "" && evt.Pathname != "?" {
		fileNode, fileID := g.getOrCreateBaseFileNode(evt, ts)
		fileNode.touch(ts)

		g.addEdge(ProvUsed, procID, fileID, ts, map[string]interface{}{
			"type": "exec",
		})
	}
}

// ── File read ────────────────────────────────────────────────

// addFileUse maps: used(process, file)
// Reads always target the latest versioned node.
func (g *Graph) addFileUse(evt *collector.Event, ts time.Time) {
	if evt.Pathname == "" || evt.Pathname == "?" {
		return
	}

	procID := nodeID("p", evt.PID)
	proc := g.getOrCreateNode(procID, ProvActivity, SubProcess,
		evt.Comm, ts)
	proc.upsertAttr("pid", evt.PID)
	proc.upsertAttr("uid", evt.UID)
	proc.touch(ts)

	fileNode, fileID := g.getOrCreateBaseFileNode(evt, ts)
	_ = fileNode

	g.addEdge(ProvUsed, procID, fileID, ts, map[string]interface{}{
		"f_flags": evt.FFlags,
	})
}

// ── File write ───────────────────────────────────────────────

// addFileGenerate maps: wasGeneratedBy(file, process)
// Creates a NEW versioned node for the file and links it via
// wasDerivedFrom to the previous version (if any).
func (g *Graph) addFileGenerate(evt *collector.Event, ts time.Time) {
	if evt.Pathname == "" || evt.Pathname == "?" {
		return
	}

	procID := nodeID("p", evt.PID)
	proc := g.getOrCreateNode(procID, ProvActivity, SubProcess,
		evt.Comm, ts)
	proc.upsertAttr("pid", evt.PID)
	proc.upsertAttr("uid", evt.UID)
	proc.touch(ts)

	// Create next version node (wasDerivedFrom edge is added internally)
	prevID, newID := g.createNextFileVersion(evt, ts)

	g.addEdge(ProvWasGeneratedBy, newID, procID, ts, map[string]interface{}{
		"f_flags": evt.FFlags,
		"prev":    prevID,
	})
}

// ── Node / Edge helpers ──────────────────────────────────────

func (g *Graph) getOrCreateNode(id, provType, subtype, label string,
	ts time.Time) *Node {

	if n, ok := g.nodes[id]; ok {
		return n
	}
	n := newNode(id, provType, subtype, label, ts)
	g.nodes[id] = n
	return n
}

func (g *Graph) addEdge(relation, source, target string, ts time.Time,
	attrs map[string]interface{}) {

	id := edgeID(relation, source, target)
	if existing, ok := g.edges[id]; ok {
		existing.merge(ts)
		return
	}
	e := newEdge(id, relation, source, target, ts)
	for k, v := range attrs {
		e.Attributes[k] = v
	}
	g.edges[id] = e
	g.edgeOrder = append(g.edgeOrder, id)
}

// fileID builds a deterministic node identifier for a file.
// Priority: inode-based > path-hash-based.
func (g *Graph) fileID(evt *collector.Event) string {
	if evt.Inode > 0 {
		return nodeID("f", evt.Inode, evt.DevMajor, evt.DevMinor)
	}
	// Fall back to path hash when inode isn't available.
	h := fnv.New64a()
	h.Write([]byte(evt.Pathname))
	return nodeID("f", "path", h.Sum64())
}

// recordFirstTS captures the very first timestamp seen for offset
// calculation.
func (g *Graph) recordFirstTS(ts uint64) {
	if g.firstTS == 0 || ts < g.firstTS {
		g.firstTS = ts
	}
}

// nsToTime converts a monotonic nanosecond timestamp to a wall-clock
// time by anchoring the first event at g.startTime.
func (g *Graph) nsToTime(ns uint64) time.Time {
	if g.firstTS == 0 {
		return g.startTime
	}
	offset := time.Duration(ns - g.firstTS)
	return g.startTime.Add(offset)
}

// ── Queries ──────────────────────────────────────────────────

// Stats returns summary counts. Thread-safe.
func (g *Graph) Stats() Stats {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return Stats{
		Nodes: len(g.nodes),
		Edges: len(g.edges),
	}
}

// Nodes returns a snapshot of all nodes. Thread-safe.
func (g *Graph) Nodes() []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		out = append(out, n)
	}
	return out
}

// Edges returns a snapshot of all edges in insertion order. Thread-safe.
func (g *Graph) Edges() []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]*Edge, 0, len(g.edges))
	for _, id := range g.edgeOrder {
		if e, ok := g.edges[id]; ok {
			out = append(out, e)
		}
	}
	return out
}

// LookupNode returns a single node by ID. Thread-safe.
func (g *Graph) LookupNode(id string) (*Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	return n, ok
}

// ── DAG traversal ────────────────────────────────────────────

// WalkFrom traverses the graph forward (following edge direction)
// from a starting node, calling fn for each visited node and edge.
// Not thread-safe with concurrent writes (caller should hold read lock).
func (g *Graph) WalkFrom(startID string, fn func(n *Node, e *Edge, depth int) bool) {
	visited := make(map[string]bool)
	var walk func(id string, depth int)
	walk = func(id string, depth int) {
		if visited[id] || depth > 1000 {
			return
		}
		visited[id] = true
		n, ok := g.nodes[id]
		if !ok {
			return
		}
		for _, e := range g.edges {
			if e.Source == id {
				if fn(n, e, depth) {
					walk(e.Target, depth+1)
				}
			}
		}
	}
	walk(startID, 0)
}
