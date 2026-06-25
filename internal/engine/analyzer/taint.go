// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ═══════════════════════════════════════════════════════════════
// Taint level
// ═══════════════════════════════════════════════════════════════

// TaintLevel represents how strongly a node is suspected.
// Each propagation hop reduces the level by one.
type TaintLevel int

const (
	TaintNone     TaintLevel = 0
	TaintLow      TaintLevel = 1
	TaintMedium   TaintLevel = 2
	TaintHigh     TaintLevel = 3
	TaintCritical TaintLevel = 4
)

func (l TaintLevel) String() string {
	switch l {
	case TaintLow:
		return "LOW"
	case TaintMedium:
		return "MEDIUM"
	case TaintHigh:
		return "HIGH"
	case TaintCritical:
		return "CRITICAL"
	default:
		return "NONE"
	}
}

// ─── Knowledge base: initial suspicion seeds ────────────────

var (
	taintMu        sync.RWMutex
	untrustedComms = defaultUntrustedComms()
	networkTools   = defaultNetworkTools()
	sensitivePaths = defaultSensitivePaths()
)

func defaultUntrustedComms() map[string]bool {
	return map[string]bool{
		"nginx": true, "apache2": true, "httpd": true, "tomcat": true,
		"uwsgi": true, "gunicorn": true, "php-fpm": true, "php-cgi": true,
		"node": true, "sshd": true, "smtpd": true, "dovecot": true,
		"cupsd": true, "rpcbind": true, "dhclient": true, "systemd-resolve": true,
	}
}

func defaultNetworkTools() map[string]bool {
	return map[string]bool{
		"curl": true, "wget": true, "nc": true, "ncat": true,
		"socat": true, "tftp": true, "ftp": true,
		"scp": true, "sftp": true, "rsync": true,
	}
}

func defaultSensitivePaths() []string {
	return []string{
		"/etc/shadow", "/etc/passwd", "/etc/security",
		"/etc/sudoers", "/etc/sudoers.d",
		"/etc/ssh/", "/.ssh/",
		"/root/", "/var/log/auth.log",
		"/var/log/secure", "/var/log/syslog",
		"/etc/cron", "/var/spool/cron",
	}
}

// ReloadTaintSeeds replaces the taint seed lists at runtime.
// All subsequent TaintEngine instances will use the new values.
func ReloadTaintSeeds(untrusted map[string]bool, network map[string]bool, sensitive []string) {
	taintMu.Lock()
	defer taintMu.Unlock()
	untrustedComms = untrusted
	networkTools = network
	sensitivePaths = sensitive
	log.Printf("[analyzer] taint seeds reloaded: %d untrusted comms, %d network tools, %d sensitive paths",
		len(untrusted), len(network), len(sensitive))
}

// AddUntrustedComm adds a comm to the untrusted list at runtime.
func AddUntrustedComm(comm string) {
	taintMu.Lock()
	defer taintMu.Unlock()
	untrustedComms[comm] = true
	log.Printf("[analyzer] added untrusted comm: %s", comm)
}

// RemoveUntrustedComm removes a comm from the untrusted list at runtime.
func RemoveUntrustedComm(comm string) {
	taintMu.Lock()
	defer taintMu.Unlock()
	delete(untrustedComms, comm)
	log.Printf("[analyzer] removed untrusted comm: %s", comm)
}

// getUntrustedComms returns a thread-safe copy of the untrusted comms map.
func getUntrustedComms() map[string]bool {
	taintMu.RLock()
	defer taintMu.RUnlock()
	m := make(map[string]bool, len(untrustedComms))
	for k, v := range untrustedComms {
		m[k] = v
	}
	return m
}

// getNetworkTools returns a thread-safe copy of the network tools map.
func getNetworkTools() map[string]bool {
	taintMu.RLock()
	defer taintMu.RUnlock()
	m := make(map[string]bool, len(networkTools))
	for k, v := range networkTools {
		m[k] = v
	}
	return m
}

// getSensitivePaths returns a thread-safe copy of the sensitive paths list.
func getSensitivePaths() []string {
	taintMu.RLock()
	defer taintMu.RUnlock()
	out := make([]string, len(sensitivePaths))
	copy(out, sensitivePaths)
	return out
}

// ═══════════════════════════════════════════════════════════════
// TaintNode — per-node taint state
// ═══════════════════════════════════════════════════════════════

type TaintNode struct {
	Level   TaintLevel
	Depth   int    // propagation hops from earliest source
	PrevID  string // previous node in the propagation chain
	PrevRel string // relation from previous node
	Reasons []string
}

// ═══════════════════════════════════════════════════════════════
// TaintEngine — runs propagation over a graph snapshot
// ═══════════════════════════════════════════════════════════════

type TaintEngine struct {
	nodes   map[string]*provenance.Node
	forward map[string][]*provenance.Edge // source → edges
	reverse map[string][]*provenance.Edge // target → edges
	tainted map[string]*TaintNode
}

// Snapshot is the input to the taint engine: a frozen view of the graph.
type Snapshot struct {
	Nodes []*provenance.Node
	Edges []*provenance.Edge
}

// NewTaintEngine builds indices and runs propagation to convergence.
// This is the main entry point.
func NewTaintEngine(snap *Snapshot) *TaintEngine {
	te := &TaintEngine{
		nodes:   make(map[string]*provenance.Node),
		forward: make(map[string][]*provenance.Edge),
		reverse: make(map[string][]*provenance.Edge),
		tainted: make(map[string]*TaintNode),
	}
	for _, n := range snap.Nodes {
		te.nodes[n.ID] = n
	}
	for _, e := range snap.Edges {
		te.forward[e.Source] = append(te.forward[e.Source], e)
		te.reverse[e.Target] = append(te.reverse[e.Target], e)
	}
	te.propagate()
	return te
}

// ── Propagation ─────────────────────────────────────────────

// propagate runs fixpoint iteration.
func (te *TaintEngine) propagate() {
	worklist := te.seedTaints()
	if len(worklist) == 0 {
		return
	}

	for head := 0; head < len(worklist); head++ {
		id := worklist[head]
		tn := te.tainted[id]
		nextLevel := tn.Level - 1
		if nextLevel < TaintLow {
			continue
		}

		for _, e := range te.forward[id] {
			te.tryTaint(e.Target, id, e.Relation, nextLevel,
				fmt.Sprintf("forward via %s", e.Relation), &worklist)
		}
		for _, e := range te.reverse[id] {
			te.tryTaint(e.Source, id, e.Relation, nextLevel,
				fmt.Sprintf("reverse via %s", e.Relation), &worklist)
		}
	}
}

// seedTaints places initial taint seeds and returns the worklist.
func (te *TaintEngine) seedTaints() []string {
	var worklist []string

	add := func(id string, level TaintLevel, reason string) {
		if existing := te.tainted[id]; existing != nil {
			if existing.Level >= level {
				return
			}
			existing.Level = level
			existing.Depth = 0
			existing.PrevID = ""
			existing.PrevRel = ""
			existing.Reasons = []string{reason}
			worklist = append(worklist, id)
			return
		}
		te.tainted[id] = &TaintNode{
			Level:   level,
			Depth:   0,
			Reasons: []string{reason},
		}
		worklist = append(worklist, id)
	}

	for id, n := range te.nodes {
		if n.Subtype != "process" && n.Subtype != "file" {
			continue
		}
		comm := strings.ToLower(n.Label)

		switch n.Subtype {
		case "process":
			if te.isForkChild(id) {
				continue
			}
			// Untrusted network-facing daemon
			if getUntrustedComms()[comm] {
				add(id, TaintCritical,
					fmt.Sprintf("network-facing process: %s", comm))
			}
			// Network tool that could exfiltrate
			if getNetworkTools()[comm] {
				add(id, TaintMedium,
					fmt.Sprintf("network-capable tool: %s", comm))
			}

		case "file":
			if te.isSensitivePath(comm) {
				add(id, TaintHigh,
					fmt.Sprintf("sensitive file: %s", comm))
			}
		}
	}
	return worklist
}

// tryTaint attempts to taint a node and adds it to the worklist if
// the new level is higher than any existing taint.
func (te *TaintEngine) tryTaint(id, prevID, rel string, level TaintLevel,
	reason string, worklist *[]string) {

	prevTn, _ := te.tainted[prevID]
	newDepth := 0
	if prevTn != nil {
		newDepth = prevTn.Depth + 1
	}

	existing, ok := te.tainted[id]
	if ok {
		if existing.Level > level {
			return
		}
		if existing.Level == level && existing.Depth >= newDepth {
			return
		}
		existing.Level = level
		existing.Depth = newDepth
		existing.PrevID = prevID
		existing.PrevRel = rel
		existing.Reasons = append(te.reasons(prevID), reason)
		*worklist = append(*worklist, id)
		return
	}

	te.tainted[id] = &TaintNode{
		Level:   level,
		Depth:   newDepth,
		PrevID:  prevID,
		PrevRel: rel,
		Reasons: append(te.reasons(prevID), reason),
	}
	*worklist = append(*worklist, id)
}

// PropagationPath returns node IDs from the initial seed to the given
// node, following PrevID pointers, EARLIEST first.
func (te *TaintEngine) PropagationPath(id string) []string {
	var rev []string
	for cur := id; cur != ""; cur = te.tainted[cur].PrevID {
		rev = append(rev, cur)
	}
	// Reverse: earliest source first
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev
}

// ── Public accessors ─────────────────────────────────────────

// Tainted returns the taint node for a given node ID, or nil.
func (te *TaintEngine) Tainted(id string) *TaintNode {
	return te.tainted[id]
}

// TaintedProcesses returns IDs of all tainted process nodes.
func (te *TaintEngine) TaintedProcesses() []string {
	var out []string
	for id := range te.tainted {
		if n, ok := te.nodes[id]; ok && n != nil && n.Subtype == "process" {
			out = append(out, id)
		}
	}
	return out
}

// TaintedNodes returns IDs of all tainted nodes.
func (te *TaintEngine) TaintedNodes() []string {
	var out []string
	for id := range te.tainted {
		out = append(out, id)
	}
	return out
}

// ── Helpers ─────────────────────────────────────────────────

func (te *TaintEngine) isSensitivePath(path string) bool {
	paths := getSensitivePaths()
	for _, p := range paths {
		matched, err := filepath.Match(p, path)
		if err == nil && matched {
			return true
		}
		if strings.HasPrefix(path, p) {
			return true
		}
		full := p
		if strings.HasSuffix(p, "/") {
			full = p + "*"
		}
		matched, err = filepath.Match(full, path)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func (te *TaintEngine) reasons(nodeID string) []string {
	if tn := te.tainted[nodeID]; tn != nil {
		return tn.Reasons
	}
	return nil
}

func (te *TaintEngine) isForkChild(nodeID string) bool {
	for _, e := range te.forward[nodeID] {
		if e.Relation == "prov:wasInformedBy" {
			return true
		}
	}
	return false
}

// SnapshotFromGraph constructs a Snapshot from the provenance graph.
func SnapshotFromGraph(g *provenance.Graph) *Snapshot {
	return &Snapshot{
		Nodes: g.Nodes(),
		Edges: g.Edges(),
	}
}
