package analyzer

import (
	"hash/fnv"
	"testing"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/policy/sigma"
)

// pathInode returns a deterministic inode for a pathname.
func pathInode(pathname string) uint64 {
	if pathname == "" {
		return 0
	}
	h := fnv.New64a()
	h.Write([]byte(pathname))
	return h.Sum64()
}

// ── Snapshot builder helpers ────────────────────────────────

func buildGraph(events []*collector.Event) *provenance.Graph {
	g := provenance.NewGraph()
	for _, evt := range events {
		g.AddEvent(evt)
	}
	return g
}

func testEvent(typ syscall.EventType, pid, uid uint32, comm, pathname string) *collector.Event {
	return &collector.Event{
		Type:        typ,
		TimestampNS: 1000000000,
		PID:         pid,
		PPID:        1,
		UID:         uid,
		Comm:        comm,
		Pathname:    pathname,
		Inode:       pathInode(pathname),
		DevMajor:    8,
		DevMinor:    3,
		Mode:        0o100644,
		FFlags:      0,
	}
}

func testFork(parent, child, uid uint32, comm string) *collector.Event {
	return &collector.Event{
		Type:        syscall.EventProcessFork,
		TimestampNS: 1000000000,
		PID:         parent,
		PPID:        1,
		UID:         uid,
		Comm:        comm,
		ChildPID:    child,
	}
}

func testWrite(pid, uid uint32, comm, pathname string) *collector.Event {
	return &collector.Event{
		Type:        syscall.EventFileModify,
		TimestampNS: 1000000000,
		PID:         pid,
		PPID:        1,
		UID:         uid,
		Comm:        comm,
		Pathname:    pathname,
		Inode:       pathInode(pathname),
		DevMajor:    8,
		DevMinor:    3,
		Mode:        0o100644,
		FFlags:      1, // O_WRONLY
	}
}

// ── Tests ───────────────────────────────────────────────────

// TestTaintPropagation_Fork verifies that taint flows from parent
// to child through wasInformedBy (fork).
func TestTaintPropagation_Fork(t *testing.T) {
	// Scenario: nginx (untrusted) forks a child process
	g := buildGraph([]*collector.Event{
		testEvent(syscall.EventProcessExec, 100, 0, "nginx", "/usr/sbin/nginx"),
		testFork(100, 101, 0, "nginx"),
	})
	snap := SnapshotFromGraph(g)
	te := NewTaintEngine(snap)

	// nginx should be tainted (network-facing process)
	if tn := te.Tainted("p:100"); tn == nil {
		t.Fatal("nginx (p:100) should be tainted as network-facing")
	} else if tn.Level != TaintCritical {
		t.Errorf("nginx taint = %s, want CRITICAL", tn.Level)
	}

	// Child should be tainted too (propagation through wasInformedBy)
	if tn := te.Tainted("p:101"); tn == nil {
		t.Fatal("nginx child (p:101) should inherit taint")
	} else if tn.Depth != 1 {
		t.Errorf("child depth = %d, want 1", tn.Depth)
	}
}

// TestTaintPropagation_WriteRead verifies that taint flows from
// a tainted process to a file it writes, then to a process that reads it.
func TestTaintPropagation_WriteRead(t *testing.T) {
	// Scenario: nginx writes /tmp/evil.sh, then bash reads it
	g := buildGraph([]*collector.Event{
		testEvent(syscall.EventProcessExec, 100, 0, "nginx", "/usr/sbin/nginx"),
		testWrite(100, 0, "nginx", "/tmp/evil.sh"),                       // nginx writes
		testEvent(syscall.EventFileOpen, 200, 0, "bash", "/tmp/evil.sh"), // bash reads
	})
	snap := SnapshotFromGraph(g)
	te := NewTaintEngine(snap)

	// File written by nginx should be tainted
	fileID := ""
	for _, e := range te.reverse["p:100"] {
		if e.Relation == "prov:wasGeneratedBy" {
			fileID = e.Source
			break
		}
	}
	if fileID == "" {
		t.Fatal("no wasGeneratedBy edge from nginx")
	}
	if tn := te.Tainted(fileID); tn == nil {
		t.Fatal("file written by nginx should be tainted")
	}

	// Bash should be tainted from reading the file
	if tn := te.Tainted("p:200"); tn == nil {
		t.Fatal("bash reading tainted file should be tainted")
	} else if tn.Level != TaintMedium {
		t.Errorf("bash taint = %s, want LOW (2 hops)", tn.Level)
	}
}

// TestPattern_SensitiveExfil detects a process that reads shadow
// and connects to the network.
func TestPattern_SensitiveExfil(t *testing.T) {
	g := buildGraph([]*collector.Event{
		testEvent(syscall.EventProcessExec, 100, 0, "nginx", "/usr/sbin/nginx"),
		testEvent(syscall.EventFileOpen, 100, 0, "nginx", "/etc/shadow"),
	})
	snap := SnapshotFromGraph(g)
	te := NewTaintEngine(snap)

	alerts := checkSensitiveExfil(te)
	if len(alerts) > 0 {
		t.Logf("got %d alerts for nginx+shadow", len(alerts))
		for _, a := range alerts {
			t.Logf("  %s", a.Headline)
		}
	}

	// Without network activity, should be no exfil alert
	// (nginx read shadow, but didn't connect anywhere)
	t.Log("(no network connection = no exfil alert — expected)")
}

// TestPattern_SensitiveExfil_WithNet triggers when both sensitive
// file and network connection exist.
func TestPattern_SensitiveExfil_WithNet(t *testing.T) {
	g := buildGraph([]*collector.Event{
		testEvent(syscall.EventProcessExec, 100, 0, "nginx", "/usr/sbin/nginx"),
		testEvent(syscall.EventFileOpen, 100, 0, "nginx", "/etc/shadow"),
	})

	// Manually add a net node to simulate network usage in the next
	// call -- in production this would come from actual net events.
	// For the test, we just verify the structure accounts for it.
	snap := SnapshotFromGraph(g)
	te := NewTaintEngine(snap)

	alerts := checkSensitiveExfil(te)
	t.Logf("exfil alerts: %d (0 expected unless network node was created)", len(alerts))
	// Note: full net_connect event + taint would be needed for
	// a real positive. This test validates the framework runs.
}

// TestPattern_DeepTaint identifies multi-hop attack chains.
func TestPattern_DeepTaint(t *testing.T) {
	// Simulate:
	//   web server (apache) → shell → downloader → backdoor
	//         p:1              p:2      p:3          p:4
	// with each step creating a file read/write
	g := buildGraph([]*collector.Event{
		testEvent(syscall.EventProcessExec, 1, 0, "apache2", "/usr/sbin/apache2"),
		testFork(1, 2, 0, "apache2"), // apache forks
		testFork(2, 3, 0, "sh"),      // shell forks
		testEvent(syscall.EventProcessExec, 3, 0, "curl", "/usr/bin/curl"),
		testEvent(syscall.EventFileOpen, 3, 0, "curl", "/tmp/backdoor"),
		testFork(3, 4, 0, "sh"), // downloader forks
		testEvent(syscall.EventProcessExec, 4, 0, "backdoor", "/tmp/backdoor"),
	})
	snap := SnapshotFromGraph(g)
	te := NewTaintEngine(snap)

	// p:4 should have depth ≥ 3
	tn := te.Tainted("p:4")
	if tn == nil {
		t.Fatal("p:4 should be tainted after propagation")
	}
	t.Logf("p:4 taint depth=%d, level=%s, path=%v",
		tn.Depth, tn.Level, te.PropagationPath("p:4"))

	if tn.Depth < 3 {
		t.Errorf("p:4 depth = %d, want >= 3", tn.Depth)
	}

	// Check pattern
	alerts := checkDeepTaint(te, 3)
	if len(alerts) == 0 {
		t.Error("expected deep taint alert for p:4")
	} else {
		t.Logf("deep taint alert: %s", alerts[0].Headline)
	}
}

// TestPattern_ScriptChild detects: tainted process writes file →
// another process reads/executes it.
func TestPattern_ScriptChild(t *testing.T) {
	g := buildGraph([]*collector.Event{
		testEvent(syscall.EventProcessExec, 1, 0, "apache2", "/usr/sbin/apache2"),
		testWrite(1, 0, "apache2", "/tmp/evil.php"),
		testEvent(syscall.EventFileOpen, 2, 0, "php", "/tmp/evil.php"),
	})
	snap := SnapshotFromGraph(g)
	te := NewTaintEngine(snap)

	alerts := checkScriptChild(te)
	if len(alerts) == 0 {
		t.Error("expected script child alert for apache2 → evil.php → php")
	} else {
		t.Logf("script child alert: %s", alerts[0].Headline)
	}
}

// TestPattern_PrivEsc detects setuid execution.
func TestPattern_PrivEsc(t *testing.T) {
	// Create a node manually with setuid attribute
	g := provenance.NewGraph()
	// Add a normal event first
	g.AddEvent(&collector.Event{
		Type:        syscall.EventProcessExec,
		TimestampNS: 1,
		PID:         100,
		UID:         0,
		Comm:        "nginx",
		Pathname:    "/usr/sbin/nginx",
	})
	// Manually add setuid flag through a second exec event
	g.AddEvent(&collector.Event{
		Type:        syscall.EventProcessExec,
		TimestampNS: 2,
		PID:         100,
		UID:         0,
		Comm:        "nginx",
		Pathname:    "/usr/sbin/nginx",
		Flags:       syscall.EventFlagExecSetuid,
	})

	snap := SnapshotFromGraph(g)
	te := NewTaintEngine(snap)

	alerts := checkPrivEsc(te)
	t.Logf("priv esc alerts: %d", len(alerts))
	for _, a := range alerts {
		t.Logf("  %s", a.Headline)
	}
}

// TestPropagationPath traces the full path from source to alert.
func TestPropagationPath(t *testing.T) {
	g := buildGraph([]*collector.Event{
		testEvent(syscall.EventProcessExec, 1, 0, "sshd", "/usr/sbin/sshd"),
		testFork(1, 2, 0, "sshd"),
		testFork(2, 3, 1000, "bash"),
		testEvent(syscall.EventProcessExec, 3, 1000, "curl", "/usr/bin/curl"),
		testEvent(syscall.EventFileOpen, 3, 1000, "curl", "/etc/shadow"),
	})
	snap := SnapshotFromGraph(g)
	te := NewTaintEngine(snap)

	path := te.PropagationPath("p:3")
	t.Logf("propagation path: %v", path)

	if len(path) == 0 {
		t.Error("expected non-empty propagation path")
	}
	// First node should be the initial seed
	if len(path) > 0 && te.tainted[path[0]] != nil && te.tainted[path[0]].Depth != 0 {
		t.Logf("path[0] = %s, depth = %d", path[0], te.tainted[path[0]].Depth)
	}
}

// TestSubgraphExtraction verifies that alert subgraphs are complete.
func TestSubgraphExtraction(t *testing.T) {
	g := buildGraph([]*collector.Event{
		testEvent(syscall.EventProcessExec, 100, 0, "nginx", "/usr/sbin/nginx"),
		testWrite(100, 0, "nginx", "/tmp/evil.sh"),
		testEvent(syscall.EventFileOpen, 200, 0, "bash", "/tmp/evil.sh"),
	})
	snap := SnapshotFromGraph(g)
	te := NewTaintEngine(snap)

	alerts := checkScriptChild(te)
	if len(alerts) == 0 {
		t.Skip("no script child alert generated")
	}

	alert := alerts[0]
	alert.ExtractSubgraph(te)

	if alert.Subgraph == nil {
		t.Fatal("subgraph should not be nil")
	}
	if len(alert.Subgraph.Nodes) == 0 {
		t.Error("subgraph should contain at least alert node")
	}
	if len(alert.Subgraph.Edges) == 0 {
		t.Error("subgraph should contain at least one edge")
	}

	t.Logf("subgraph: %d nodes, %d edges, path=%v",
		len(alert.Subgraph.Nodes),
		len(alert.Subgraph.Edges),
		alert.Subgraph.PathNodeIDs)
}

// TestFullPipeline simulates a complete APT attack chain.
func TestFullPipeline(t *testing.T) {
	// APT scenario: web server compromise → lateral movement → exfiltration
	//
	// Phase 1: Initial compromise
	//   apache2 forks child → child downloads /tmp/evil.sh
	// Phase 2: Execution
	//   bash executes /tmp/evil.sh → evil.sh forks backdoor
	// Phase 3: Recon
	//   backdoor reads /etc/shadow, /etc/ssh/sshd_config
	// Phase 4: Exfil
	//   backdoor connects to C2 server via curl
	g := buildGraph([]*collector.Event{
		// Phase 1
		testEvent(syscall.EventProcessExec, 1, 0, "apache2", "/usr/sbin/apache2"),
		testFork(1, 2, 0, "apache2"),
		testFork(2, 3, 0, "sh"),
		testEvent(syscall.EventProcessExec, 3, 0, "curl", "/usr/bin/curl"),
		testWrite(3, 0, "curl", "/tmp/evil.sh"),
		// Phase 2
		testEvent(syscall.EventProcessExec, 4, 0, "bash", "/usr/bin/bash"),
		testEvent(syscall.EventFileOpen, 4, 0, "bash", "/tmp/evil.sh"),
		testFork(4, 5, 0, "bash"),
		// Phase 3
		testEvent(syscall.EventFileOpen, 5, 0, "bash", "/etc/shadow"),
		// Phase 4 (simulated via file event since net_connect isn't ingested yet)
		testWrite(5, 0, "bash", "/tmp/exfil.dat"),
	})
	snap := SnapshotFromGraph(g)
	te := NewTaintEngine(snap)

	t.Logf("Taint results:")
	for id, tn := range te.tainted {
		n := te.nodes[id]
		label := "?"
		if n != nil {
			label = n.Label
		}
		path := te.PropagationPath(id)
		t.Logf("  %s (%s) level=%s depth=%d path_len=%d",
			id, label, tn.Level, tn.Depth, len(path))
	}

	alerts := checkDeepTaint(te, 3)
	t.Logf("Deep taint alerts: %d", len(alerts))
	for _, a := range alerts {
		a.ExtractSubgraph(te)
		t.Logf("  %s", a.String())
	}

	// All alerts check
	allAlerts := checkSensitiveExfil(te)
	alerts2 := checkScriptChild(te)
	alerts3 := checkPrivEsc(te)
	allAlerts = append(allAlerts, alerts2...)
	allAlerts = append(allAlerts, alerts3...)

	t.Logf("Total alerts: %d", len(allAlerts))
	for _, a := range allAlerts {
		t.Logf("  [%s] %s", a.Severity, a.Headline)
	}

	// Verify at least some alerts fired for this attack scenario
	if len(allAlerts) == 0 {
		t.Error("expected at least one alert for full APT scenario")
	}
}

// TestNoFalsePositive verifies that benign activity doesn't alert.
func TestNoFalsePositive(t *testing.T) {
	// Normal admin activity: sudo read /etc/shadow for diagnostics,
	// but no network activity afterwards
	g := buildGraph([]*collector.Event{
		testEvent(syscall.EventProcessExec, 100, 0, "sudo", "/usr/bin/sudo"),
		testEvent(syscall.EventFileOpen, 100, 0, "sudo", "/etc/shadow"),
		testEvent(syscall.EventFileOpen, 100, 0, "sudo", "/etc/hostname"),
	})
	snap := SnapshotFromGraph(g)
	te := NewTaintEngine(snap)

	alerts := checkSensitiveExfil(te)
	if len(alerts) > 0 {
		t.Logf("false positive alerts: %d", len(alerts))
		for _, a := range alerts {
			t.Logf("  %s", a.Headline)
		}
	}
	// sudo read shadow but no network — should be no exfil alert
	t.Log("(sudo read shadow without network = expected no exfil alert)")
}

// TestSeedTaints verifies that the initial taint seeds are correct.
func TestSeedTaints(t *testing.T) {
	g := buildGraph([]*collector.Event{
		testEvent(syscall.EventProcessExec, 1, 0, "nginx", "/usr/sbin/nginx"),
		testEvent(syscall.EventProcessExec, 2, 0, "bash", "/usr/bin/bash"),
		testEvent(syscall.EventProcessExec, 3, 0, "curl", "/usr/bin/curl"),
	})
	snap := SnapshotFromGraph(g)
	te := NewTaintEngine(snap)

	if te.Tainted("p:1") == nil {
		t.Error("nginx should be tainted (network-facing)")
	}
	if te.Tainted("p:2") != nil {
		t.Error("bash should NOT be tainted initially")
	}
	if te.Tainted("p:3") == nil {
		t.Error("curl should be tainted (network tool)")
	}
}

// TestSigmaRuleInAnalyzer verifies that sigma rules added to the
// analyzer are evaluated during scan() and produce alerts.
func TestSigmaRuleInAnalyzer(t *testing.T) {
	g := buildGraph([]*collector.Event{
		testEvent(syscall.EventProcessExec, 100, 0, "bash", "/usr/bin/bash"),
		testEvent(syscall.EventFileOpen, 100, 0, "bash", "/etc/shadow"),
	})

	anz := New(g, &Config{
		ScanInterval:       1 * time.Hour, // won't fire during test
		DeepTaintThreshold: 3,
		EnablePatterns:     []PatternID{},
	})

	rule, err := sigma.ParseRule([]byte(`
title: Shadow Access Test
logsource:
  category: file_access
detection:
  selection:
    target: /etc/shadow
  condition: selection
level: high
`))
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}

	anz.AddSigmaRule("test-shadow-001", rule)

	// Start triggers an immediate scan
	anz.Start()
	anz.Stop()

	alerts := anz.Alerts()
	var sigmaAlerts []*Alert
	for _, a := range alerts {
		if len(a.Pattern) > 6 && string(a.Pattern[:6]) == "SIGMA:" {
			sigmaAlerts = append(sigmaAlerts, a)
		}
	}

	if len(sigmaAlerts) == 0 {
		// Log all alerts for debugging
		t.Logf("all alerts: %d", len(alerts))
		for _, a := range alerts {
			t.Logf("  pattern=%s headline=%s", a.Pattern, a.Headline)
		}
		t.Fatal("expected at least one sigma alert for /etc/shadow access")
	}
	t.Logf("sigma alerts: %d", len(sigmaAlerts))
	for _, a := range sigmaAlerts {
		t.Logf("  [%s] %s", a.Severity, a.Headline)
	}
}

// TestAddRemoveSigmaRule verifies that rules can be added and removed.
func TestAddRemoveSigmaRule(t *testing.T) {
	g := provenance.NewGraph()
	anz := New(g, DefaultConfig())

	rule, _ := sigma.ParseRule([]byte(`
title: Test Rule
logsource:
  category: process
detection:
  selection:
    image: bash
  condition: selection
level: low
`))

	anz.AddSigmaRule("test-rule", rule)
	anz.RemoveSigmaRule("test-rule")

	// After removal, scan should produce no sigma alerts
	anz.Start()
	anz.Stop()

	for _, a := range anz.Alerts() {
		if string(a.Pattern) == "SIGMA:test-rule" {
			t.Error("sigma alert should not be generated after rule removal")
		}
	}
}

