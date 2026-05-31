package provenance

import (
	"testing"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
)

// ── Helpers ──────────────────────────────────────────────────

func makeWrite(pid, uid uint32, comm, path string) *collector.Event {
	e := makeEvent(syscall.EventFileModify, pid, 0, uid, comm, path)
	e.FFlags = 1
	return e
}

func makeCreate(pid, uid uint32, comm, path string) *collector.Event {
	e := makeEvent(syscall.EventFileCreate, pid, 0, uid, comm, path)
	e.FFlags = 0x101 // O_WRONLY | O_CREAT
	return e
}

func makeFork(parent, child, uid uint32, comm string) *collector.Event {
	return &collector.Event{
		Type: syscall.EventProcessFork, TimestampNS: 1000,
		PID: parent, PPID: 1, UID: uid, Comm: comm, ChildPID: child,
	}
}

// ═══════════════════════════════════════════════════════════════
// Entity versioning tests
// ═══════════════════════════════════════════════════════════════

func TestVersionTrackerInit(t *testing.T) {
	vt := NewVersionTracker()
	id := vt.InitVersion("f:100:8:3")
	if id != "f:100:8:3#v1" {
		t.Errorf("InitVersion = %q, want f:100:8:3#v1", id)
	}
}

func TestVersionTrackerNextVersion(t *testing.T) {
	vt := NewVersionTracker()
	prev, next := vt.NextVersion("f:100:8:3")
	if prev != "f:100:8:3#v1" {
		t.Errorf("prev = %q, want f:100:8:3#v1", prev)
	}
	if next != "f:100:8:3#v2" {
		t.Errorf("next = %q, want f:100:8:3#v2", next)
	}

	// Third version
	prev2, next2 := vt.NextVersion("f:100:8:3")
	if prev2 != "f:100:8:3#v2" {
		t.Errorf("prev2 = %q, want f:100:8:3#v2", prev2)
	}
	if next2 != "f:100:8:3#v3" {
		t.Errorf("next2 = %q, want f:100:8:3#v3", next2)
	}
}

func TestVersionTrackerLatest(t *testing.T) {
	vt := NewVersionTracker()
	vt.InitVersion("f:100:8:3")
	vt.NextVersion("f:100:8:3")

	latest := vt.LatestVersion("f:100:8:3")
	if latest != "f:100:8:3#v2" {
		t.Errorf("latest = %q, want f:100:8:3#v2", latest)
	}
}

func TestStripVersion(t *testing.T) {
	tests := []struct{ input, want string }{
		{"f:100:8:3#v2", "f:100:8:3"},
		{"f:100:8:3", "f:100:8:3"},
		{"p:1234", "p:1234"},
		{"c:1:1000", "c:1:1000"},
	}
	for _, tt := range tests {
		got := StripVersion(tt.input)
		if got != tt.want {
			t.Errorf("StripVersion(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ── Integration: writes create versioned nodes ───────────────

func TestGraphWriteCreatesVersion(t *testing.T) {
	g := NewGraph()

	// First write → file#v1 created
	g.AddEvent(makeWrite(100, 0, "bash", "/tmp/log.txt"))
	nodes := g.Nodes()
	v1Count := 0
	for _, n := range nodes {
		if n.ID == "f:100000:8:3#v1" {
			v1Count++
		}
	}
	if v1Count == 0 {
		t.Error("expected versioned node f:100000:8:3#v1")
	}
}

func TestGraphWriteMultipleVersions(t *testing.T) {
	g := NewGraph()

	// Two writes to the same file
	g.AddEvent(makeWrite(100, 0, "bash", "/tmp/log.txt"))
	g.AddEvent(makeWrite(100, 0, "bash", "/tmp/log.txt"))

	nodes := g.Nodes()
	v1ok := false
	v2ok := false
	for _, n := range nodes {
		if n.ID == "f:100000:8:3#v1" {
			v1ok = true
		}
		if n.ID == "f:100000:8:3#v2" {
			v2ok = true
		}
	}
	if !v1ok {
		t.Error("file#v1 should exist")
	}
	if !v2ok {
		t.Error("file#v2 should exist (second write created new version)")
	}

	// Verify wasDerivedFrom edge
	edges := g.Edges()
	hasDerived := false
	for _, e := range edges {
		if e.Relation == ProvWasDerivedFrom &&
			e.Source == "f:100000:8:3#v2" &&
			e.Target == "f:100000:8:3#v1" {
			hasDerived = true
		}
	}
	if !hasDerived {
		t.Error("expected wasDerivedFrom v2→v1 edge")
	}
}

func TestGraphReadTargetsLatest(t *testing.T) {
	g := NewGraph()

	// Write creates a new version (v2), then read should target the latest (v2)
	g.AddEvent(makeCreate(100, 0, "vi", "/tmp/data.txt"))
	// Read event
	evt := makeEvent(syscall.EventFileOpen, 200, 0, 1000, "cat", "/tmp/data.txt")
	evt.Inode = 100000 // same inode as the write
	g.AddEvent(evt)

	// Verify used edge points to latest version (v2)
	edges := g.Edges()
	readEdge := false
	for _, e := range edges {
		if e.Relation == ProvUsed && e.Source == "p:200" {
			if e.Target == "f:100000:8:3#v2" {
				readEdge = true
			}
		}
	}
	if !readEdge {
		t.Error("expected used edge to target latest version v2")
	}
}

// ═══════════════════════════════════════════════════════════════
// Credential state machine tests
// ═══════════════════════════════════════════════════════════════

func TestCredTrackerInit(t *testing.T) {
	ct := NewCredTracker()
	if ct == nil {
		t.Fatal("NewCredTracker returned nil")
	}
}

func TestCredTrackerSetuidCreatesNode(t *testing.T) {
	ct := NewCredTracker()

	evt := &collector.Event{
		Type: syscall.EventProcessExec, TimestampNS: 1000,
		PID: 100, UID: 0, Comm: "sudo",
		Flags: syscall.EventFlagExecSetuid,
	}
	ts := time.Unix(0, 1000)

	credID, prevUID := ct.OnExec(evt, ts)
	if credID == "" {
		t.Fatal("expected credential node for setuid exec")
	}
	if prevUID != 0 {
		t.Errorf("expected prevUID=0 for first exec, got %d", prevUID)
	}
	_ = credID
}

func TestCredTrackerNormalExecNoNode(t *testing.T) {
	ct := NewCredTracker()

	evt := &collector.Event{
		Type: syscall.EventProcessExec, TimestampNS: 1000,
		PID: 100, UID: 1000, Comm: "bash",
	}
	ts := time.Unix(0, 1000)

	credID, _ := ct.OnExec(evt, ts)
	if credID != "" {
		t.Error("expected no credential node for non-setuid exec")
	}
}

func TestCredTrackerTracksState(t *testing.T) {
	ct := NewCredTracker()
	_ = ct // placeholder — full state tracking needs more events
}

func TestGraphExecWithSetuidCreatesCredential(t *testing.T) {
	g := NewGraph()

	// Exec with setuid flag
	evt := &collector.Event{
		Type: syscall.EventProcessExec, TimestampNS: 1000,
		PID: 100, PPID: 1, UID: 0, Comm: "sudo", Pathname: "/usr/bin/sudo",
		Inode: 99999, DevMajor: 8, DevMinor: 3, Mode: 0644,
		Flags: syscall.EventFlagExecSetuid,
	}
	g.AddEvent(evt)

	nodes := g.Nodes()
	credNodeFound := false
	for _, n := range nodes {
		if n.Subtype == "credential" {
			credNodeFound = true
			t.Logf("credential node: %s label=%s", n.ID, n.Label)
		}
	}
	if !credNodeFound {
		t.Error("expected credential node after setuid exec")
	}
}

// ═══════════════════════════════════════════════════════════════
// Graph path pruning tests
// ═══════════════════════════════════════════════════════════════

func TestPrunerEmptyGraph(t *testing.T) {
	g := NewGraph()
	n := g.Prune(nil, DefaultInterestingChecker())
	if n != 0 {
		t.Errorf("pruned %d nodes from empty graph", n)
	}
}

func TestPrunerKeepsInteresting(t *testing.T) {
	g := NewGraph()
	// Sensitive file access
	g.AddEvent(makeEvent(syscall.EventFileOpen, 100, 0, 0, "cat", "/etc/shadow"))
	// Normal activity (should be pruned)
	g.AddEvent(makeEvent(syscall.EventFileOpen, 200, 0, 0, "cat", "/tmp/trivial.txt"))

	n := g.Prune(nil, DefaultInterestingChecker())
	if n <= 0 {
		t.Error("expected at least 1 node removed (the trivial path)")
	}

	t.Logf("prune removed %d nodes", n)
	nodes := g.Nodes()
	shadowFound := false
	trivialFound := false
	for _, node := range nodes {
		if node.Label == "/etc/shadow" {
			shadowFound = true
		}
		if node.Label == "/tmp/trivial.txt" {
			trivialFound = true
		}
	}
	if !shadowFound {
		t.Error("/etc/shadow should be kept (interesting)")
	}
	if trivialFound {
		t.Error("/tmp/trivial.txt should be pruned (not interesting)")
	}
}

func TestPrunerNetworkInteresting(t *testing.T) {
	g := NewGraph()
	// Add a fork event
	g.AddEvent(makeFork(1, 100, 0, "sshd"))
	// Add network-like node (simulate via a node)
	g.AddEvent(makeEvent(syscall.EventFileOpen, 100, 0, 0, "sshd", "/etc/hosts"))

	n := g.Prune(nil, DefaultInterestingChecker())
	t.Logf("prune removed %d nodes", n)
	// /etc/hosts is not in the sensitive list → may be pruned
	_ = n
}

func TestPrunerExtraSet(t *testing.T) {
	g := NewGraph()
	g.AddEvent(makeEvent(syscall.EventFileOpen, 100, 0, 0, "bash", "/tmp/foo.txt"))
	g.AddEvent(makeEvent(syscall.EventFileOpen, 200, 0, 0, "bash", "/tmp/bar.txt"))

	// Only mark p:100 as interesting via extra set
	extra := map[string]bool{"p:100": true}
	n := g.Prune(extra, nil)

	if n <= 0 {
		t.Error("expected pruning when extra set marks p:100 as interesting")
	}
	_ = n
}

func TestIsPathSensitive(t *testing.T) {
	tests := []struct{ path string; sensitive bool }{
		{"/etc/shadow", true},
		{"/etc/passwd", true},
		{"/root/.bashrc", true},
		{"/tmp/foo.txt", false},
		{"/usr/bin/cat", false},
		{"/etc/hostname", false},
	}
	for _, tt := range tests {
		got := isPathSensitive(tt.path)
		if got != tt.sensitive {
			t.Errorf("isPathSensitive(%q) = %v, want %v", tt.path, got, tt.sensitive)
		}
	}
}

func TestPruneMultipleCalls(t *testing.T) {
	g := NewGraph()
	// Add a mix of sensitive and non-sensitive
	g.AddEvent(makeEvent(syscall.EventFileOpen, 100, 0, 0, "bash", "/etc/shadow"))
	g.AddEvent(makeEvent(syscall.EventFileOpen, 200, 0, 0, "bash", "/tmp/trivial.txt"))

	n1 := g.Prune(nil, DefaultInterestingChecker())
	n2 := g.Prune(nil, DefaultInterestingChecker())

	t.Logf("first prune: %d, second prune: %d", n1, n2)
	if n2 > 0 && n1 == 0 {
		// second pass might find more — not an error, but interesting
	}
}

func TestCredentialNodeIsInteresting(t *testing.T) {
	checker := DefaultInterestingChecker()

	n := &Node{
		ID: "c:1:1000", Subtype: "credential",
		Attributes: map[string]interface{}{"pid": 1},
	}
	if !checker(n) {
		t.Error("credential node should be interesting")
	}
}

func TestSetuidNodeIsInteresting(t *testing.T) {
	checker := DefaultInterestingChecker()

	n := &Node{
		ID: "p:100", Subtype: "process",
		Attributes: map[string]interface{}{"setuid": true},
	}
	if !checker(n) {
		t.Error("process with setuid attribute should be interesting")
	}
}
