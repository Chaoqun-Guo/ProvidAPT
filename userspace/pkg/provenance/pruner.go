package provenance

import (
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Graph path pruning (dead code elimination)
//
// Periodically removes provenance nodes and edges that are not
// connected (via forward or backward traversal) to any "interesting"
// node.  An interesting node is one involved in:
//
//   - Network connection (prov:used with network endpoint)
//   - Sensitive file access (/etc/shadow, /etc/passwd, /root/*)
//   - Privilege escalation (setuid, credential change)
//   - Tainted process activity
//
// The algorithm is a standard mark-and-sweep:
//   1. Mark all interesting nodes as reachable.
//   2. BFS backward from interesting nodes (follow reverse edges)
//      to find all ancestors (causal chain).
//   3. BFS forward from interesting nodes (follow forward edges)
//      to find all descendants (impact chain).
//   4. The union of (2) and (3) is the "keep" set.
//   5. Delete all nodes and edges NOT in the keep set.
// ═══════════════════════════════════════════════════════════════

// isPathSensitive returns true if the path looks like a sensitive file.
func isPathSensitive(path string) bool {
	sensitivePrefixes := []string{
		"/etc/shadow", "/etc/passwd", "/etc/sudoers",
		"/etc/ssh/", "/root/", "/.ssh/",
		"/var/log/auth.log", "/var/log/secure",
	}
	for _, p := range sensitivePrefixes {
		if len(path) >= len(p) && path[:len(p)] == p {
			return true
		}
	}
	return false
}

// InterestingChecker returns true if a node is deemed "interesting"
// and should not be pruned.  This is checked during the mark phase.
type InterestingChecker func(n *Node) bool

// DefaultInterestingChecker returns the default implementation:
// a node is interesting if it is a network endpoint, a sensitive
// file, or has credential attributes.
func DefaultInterestingChecker() InterestingChecker {
	return func(n *Node) bool {
		if n.Subtype == "network" {
			return true
		}
		if n.Subtype == "credential" {
			return true
		}
		if n.Subtype == "file" && isPathSensitive(n.Label) {
			return true
		}
		if v, ok := n.Attributes["setuid"]; ok {
			if b, isBool := v.(bool); isBool && b {
				return true
			}
		}
		return false
	}
}

// ── Graph pruning methods ───────────────────────────────────

// Prune performs dead code elimination on the graph.
// It removes all nodes and edges that are not reachable from any
// "interesting" node via forward or backward traversal.
//
// The pruneSet argument is an additional set of node IDs to treat as
// interesting (set by the analyzer when alerts are generated).
//
// Returns the number of nodes removed.
func (g *Graph) Prune(pruneSet map[string]bool, checker InterestingChecker) int {
	g.mu.Lock()
	defer g.mu.Unlock()

	if len(g.nodes) == 0 {
		return 0
	}

	// Phase 1: find interesting nodes
	interesting := make(map[string]bool)
	for id, n := range g.nodes {
		if pruneSet != nil && pruneSet[id] {
			interesting[id] = true
		}
		if checker != nil && checker(n) {
			interesting[id] = true
		}
	}

	if len(interesting) == 0 {
		return 0
	}

	// Phase 2: BFS backward and forward from interesting nodes
	reachable := make(map[string]bool)
	queue := make([]string, 0, len(interesting))

	for id := range interesting {
		reachable[id] = true
		queue = append(queue, id)
	}

	// Build reverse edge index for backward traversal
	reverseIdx := make(map[string][]string) // target → sources
	for _, e := range g.edges {
		reverseIdx[e.Target] = append(reverseIdx[e.Target], e.Source)
	}

	for head := 0; head < len(queue); head++ {
		id := queue[head]

		// Forward: follow edges from this node
		for _, e := range g.edges {
			if e.Source == id && !reachable[e.Target] {
				reachable[e.Target] = true
				queue = append(queue, e.Target)
			}
		}

		// Backward: follow reverse edges to ancestors
		for _, src := range reverseIdx[id] {
			if !reachable[src] {
				reachable[src] = true
				queue = append(queue, src)
			}
		}
	}

	// Phase 3: sweep — remove non-reachable nodes and edges
	removedNodes := 0
	for id := range g.nodes {
		if !reachable[id] {
			delete(g.nodes, id)
			removedNodes++
		}
	}

	removedEdges := 0
	for id, e := range g.edges {
		if !reachable[e.Source] || !reachable[e.Target] {
			delete(g.edges, id)
			removedEdges++
		}
	}

	// Rebuild edgeOrder with surviving edges
	newOrder := make([]string, 0, len(g.edges))
	for _, id := range g.edgeOrder {
		if _, ok := g.edges[id]; ok {
			newOrder = append(newOrder, id)
		}
	}
	g.edgeOrder = newOrder

	if removedNodes > 0 || removedEdges > 0 {
		log.Printf("[pruner] removed %d nodes and %d edges (kept %d/%d)",
			removedNodes, removedEdges, len(g.nodes), len(g.nodes)+removedNodes)
	}
	return removedNodes
}

// ── Periodic pruning ─────────────────────────────────────────

// PruneLoop runs periodic pruning in a background goroutine.
// It calls Prune at the given interval.  The loop exits when stopCh
// is closed.
func (g *Graph) PruneLoop(interval time.Duration, checker InterestingChecker, stopCh <-chan struct{}, wg *sync.WaitGroup) {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				n := g.Prune(nil, checker)
				if n > 0 {
					log.Printf("[pruner] pruned %d nodes", n)
				}
			case <-stopCh:
				return
			}
		}
	}()
}
