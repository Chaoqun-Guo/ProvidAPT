package taint

import (
	"testing"
	"time"
)

// ─── Config tests ───────────────────────────────────────────

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.NonInternalPrefixes) == 0 {
		t.Error("no internal prefixes")
	}
	if len(cfg.CleanCommands) == 0 {
		t.Error("no clean commands")
	}
	if len(cfg.SensitivePaths) == 0 {
		t.Error("no sensitive paths")
	}
}

// ─── Taint level tests ──────────────────────────────────────

func TestLevelStrings(t *testing.T) {
	if Clean.String() != "CLEAN" {
		t.Errorf("Clean = %s", Clean)
	}
	if Tainted.String() != "TAINTED" {
		t.Errorf("Tainted = %s", Tainted)
	}
	if HighlyTainted.String() != "HIGH_TAINT" {
		t.Errorf("HighTaint = %s", HighlyTainted)
	}
}

// ─── Taint engine tests ─────────────────────────────────────

func TestNewEngine(t *testing.T) {
	te := New(nil)
	if te == nil {
		t.Fatal("New returned nil")
	}
}

func TestIsExternalIP(t *testing.T) {
	te := New(nil)
	if te.IsExternalIP("10.0.0.1") {
		t.Error("10.x should be internal")
	}
	if te.IsExternalIP("192.168.1.1") {
		t.Error("192.168.x should be internal")
	}
	if te.IsExternalIP("172.16.0.1") {
		t.Error("172.16.x should be internal")
	}
	if !te.IsExternalIP("5.6.7.8") {
		t.Error("5.6.7.8 should be external")
	}
	if !te.IsExternalIP("203.0.113.1") {
		t.Error("203.0.113.1 should be external")
	}
}

func TestMarkSocketSource(t *testing.T) {
	te := New(nil)
	state := te.MarkSocketSource("p:100", "curl", "5.6.7.8")
	if state.Level != Tainted {
		t.Errorf("level = %d", state.Level)
	}
	if state.SourceIP != "5.6.7.8" {
		t.Errorf("IP = %s", state.SourceIP)
	}
}

func TestPropagateReadFromTaintedFile(t *testing.T) {
	te := New(nil)
	// File is tainted
	te.mu.Lock()
	te.states["f:5000"] = &State{ID: "f:5000", Type: "file", Level: Tainted}
	te.mu.Unlock()

	// Process reads the tainted file
	state := te.PropagateRead("p:100", "f:5000", "bash")
	if state == nil {
		t.Fatal("propagation failed")
	}
	if state.Level != Tainted {
		t.Errorf("level = %d", state.Level)
	}
	if state.ID != "p:100" {
		t.Errorf("id = %s", state.ID)
	}
}

func TestPropagateWriteFromTaintedProcess(t *testing.T) {
	te := New(nil)
	// Process is tainted
	te.mu.Lock()
	te.states["p:100"] = &State{ID: "p:100", Type: "process", Level: Tainted}
	te.mu.Unlock()

	// Process writes a file
	state := te.PropagateWrite("p:100", "f:5000")
	if state == nil {
		t.Fatal("propagation failed")
	}
	if state.Level != Tainted {
		t.Errorf("level = %d", state.Level)
	}
	if state.ID != "f:5000" {
		t.Errorf("id = %s", state.ID)
	}
}

func TestPropagateFork(t *testing.T) {
	te := New(nil)
	te.mu.Lock()
	te.states["p:100"] = &State{ID: "p:100", Type: "process", Level: Tainted, SourceIP: "5.6.7.8"}
	te.mu.Unlock()

	child := te.PropagateFork("p:100", "p:101")
	if child == nil {
		t.Fatal("fork propagation failed")
	}
	if child.Level != Tainted {
		t.Errorf("level = %d", child.Level)
	}
	if child.SourceIP != "5.6.7.8" {
		t.Errorf("IP not inherited: %s", child.SourceIP)
	}
}

func TestNoPropagationFromClean(t *testing.T) {
	te := New(nil)
	// Process is clean (no taint state)
	state := te.PropagateWrite("p:100", "f:500")
	if state != nil {
		t.Error("clean process should not propagate taint")
	}
}

// ─── Taint decay tests ──────────────────────────────────────

func TestIsCleanCommand(t *testing.T) {
	te := New(nil)
	if !te.IsCleanCommand("openssl") {
		t.Error("openssl should be clean")
	}
	if !te.IsCleanCommand("gpg") {
		t.Error("gpg should be clean")
	}
	if te.IsCleanCommand("bash") {
		t.Error("bash should not be clean")
	}
	if te.IsCleanCommand("curl") {
		t.Error("curl should not be clean")
	}
}

func TestCleanTaint(t *testing.T) {
	te := New(nil)
	te.mu.Lock()
	te.states["p:100"] = &State{ID: "p:100", Type: "process", Level: Tainted}
	te.mu.Unlock()

	te.CleanTaint("p:100")
	state := te.GetTaint("p:100")
	if state.Level != Clean {
		t.Errorf("level = %d after clean", state.Level)
	}
}

func TestDecayTaint(t *testing.T) {
	te := New(&Config{
		TaintDecayAfter: 0, // no decay
	})
	_ = te.DecayTaint()

	te2 := New(&Config{
		TaintDecayAfter: time.Nanosecond,
	})
	te2.mu.Lock()
	te2.states["p:100"] = &State{
		ID: "p:100", Type: "process", Level: Tainted,
		UpdatedAt: time.Now().Add(-time.Hour),
	}
	te2.mu.Unlock()

	n := te2.DecayTaint()
	if n != 1 {
		t.Errorf("decayed = %d, want 1", n)
	}
}

// ─── Alert tests ────────────────────────────────────────────

func TestCheckActionCleanProcess(t *testing.T) {
	te := New(nil)
	alert := te.CheckAction("p:100", "bash", "read", "/etc/hosts")
	if alert != nil {
		t.Error("clean process should not trigger alert")
	}
}

func TestCheckActionTaintedProcess(t *testing.T) {
	te := New(nil)
	te.mu.Lock()
	te.states["p:100"] = &State{ID: "p:100", Type: "process", Level: Tainted, SourceIP: "5.6.7.8"}
	te.mu.Unlock()

	alert := te.CheckAction("p:100", "bash", "write", "/etc/shadow")
	if alert == nil {
		t.Fatal("tainted process accessing /etc/shadow should alert")
	}
	if alert.Severity != "CRITICAL" {
		t.Errorf("severity = %s", alert.Severity)
	}
	if alert.TaintIP != "5.6.7.8" {
		t.Errorf("IP = %s", alert.TaintIP)
	}
}

func TestCheckActionNonSensitive(t *testing.T) {
	te := New(nil)
	te.mu.Lock()
	te.states["p:100"] = &State{ID: "p:100", Type: "process", Level: Tainted}
	te.mu.Unlock()

	alert := te.CheckAction("p:100", "bash", "read", "/tmp/foo.txt")
	if alert != nil {
		t.Log("non-sensitive read may not alert")
	}
}

func TestCheckActionPtrace(t *testing.T) {
	te := New(nil)
	te.mu.Lock()
	te.states["p:100"] = &State{ID: "p:100", Type: "process", Level: Tainted}
	te.mu.Unlock()

	alert := te.CheckAction("p:100", "bash", "ptrace", "p:200")
	if alert == nil {
		t.Fatal("ptrace by tainted process should alert")
	}
}

func TestIsSensitivePath(t *testing.T) {
	te := New(nil)
	if !te.IsSensitivePath("/etc/shadow") {
		t.Error("shadow should be sensitive")
	}
	if !te.IsSensitivePath("/etc/ssh/ssh_config") {
		t.Error("ssh config should be sensitive")
	}
	if te.IsSensitivePath("/tmp/foo") {
		t.Error("/tmp should not be sensitive")
	}
}

// ─── Full propagation chain test ─────────────────────────────

func TestFullPropagationChain(t *testing.T) {
	te := New(nil)

	// 1. External socket read taints curl
	te.MarkSocketSource("p:100", "curl", "203.0.113.5")

	// 2. curl writes to /tmp/evil.sh → file tainted
	te.PropagateWrite("p:100", "f:5000")

	// 3. bash reads /tmp/evil.sh → bash tainted
	te.PropagateRead("p:200", "f:5000", "bash")

	// 4. bash forks child → child tainted
	te.PropagateFork("p:200", "p:201")

	// 5. child writes shadow → alert
	alert := te.CheckAction("p:201", "bash", "write", "/etc/shadow")
	if alert == nil {
		t.Fatal("full chain should end with alert")
	}

	stats := te.Stats()
	t.Logf("=== Full Taint Chain ===")
	t.Logf("Tainted nodes: %d", stats["tainted_nodes"])
	t.Logf("Tainted procs: %d", stats["tainted_procs"])
	t.Logf("Tainted files: %d", stats["tainted_files"])
	t.Logf("Alerts:        %d", stats["total_alerts"])
	t.Logf("Source IP:     %s", alert.TaintIP)
	t.Logf("Alert severity:%s", alert.Severity)

	if stats["tainted_nodes"].(int) < 3 {
		t.Error("expected ≥3 tainted nodes in chain")
	}
}

// ─── Stats tests ────────────────────────────────────────────

func TestStats(t *testing.T) {
	te := New(nil)
	te.MarkSocketSource("p:100", "curl", "1.2.3.4")
	stats := te.Stats()
	if stats["tainted_nodes"].(int) != 1 {
		t.Errorf("tainted = %d", stats["tainted_nodes"])
	}
}

func TestAlerts(t *testing.T) {
	te := New(nil)
	te.mu.Lock()
	te.states["p:1"] = &State{ID: "p:1", Type: "process", Level: Tainted}
	te.mu.Unlock()
	te.CheckAction("p:1", "bash", "write", "/etc/shadow")

	alerts := te.Alerts()
	if len(alerts) != 1 {
		t.Errorf("alerts = %d", len(alerts))
	}
}

// ─── Integration test ───────────────────────────────────────

func TestTaintIntegration(t *testing.T) {
	te := New(nil)

	// Simulate attack scenario
	t.Log("=== Taint Tracking Integration ===")

	// Step 1: External download
	te.MarkSocketSource("p:curl", "curl", "5.6.7.8")
	t.Log("Step 1: curl tainted by external IP 5.6.7.8")

	// Step 2: Write payload to /tmp
	te.PropagateWrite("p:curl", "f:/tmp/evil.sh")
	t.Log("Step 2: /tmp/evil.sh tainted by curl")

	// Step 3: bash reads and executes payload
	te.PropagateRead("p:bash", "f:/tmp/evil.sh", "bash")
	t.Log("Step 3: bash tainted by reading /tmp/evil.sh")

	// Step 4: Fork child processes
	te.PropagateFork("p:bash", "p:sh")
	t.Log("Step 4: sh tainted via fork")

	// Step 5: Sensitive action → Alert
	alert := te.CheckAction("p:bash", "bash", "write", "/etc/shadow")
	if alert != nil {
		t.Logf("Step 5: ALERT [%s] %s → %s (IP: %s)",
			alert.Severity, alert.ProcessComm, alert.Target, alert.TaintIP)
	}

	// Verify chain
	stats := te.Stats()
	t.Logf("Stats: %d tainted nodes, %d alerts",
		stats["tainted_nodes"], stats["total_alerts"])

	if stats["tainted_nodes"].(int) < 3 {
		t.Error("expected ≥3 tainted nodes")
	}
	if stats["total_alerts"].(int) < 1 {
		t.Error("expected at least 1 alert")
	}
}
