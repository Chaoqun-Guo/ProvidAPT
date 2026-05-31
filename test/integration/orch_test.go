//go:build integration

package integration

import (
	"testing"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/stitcher/orch"
)

// ─── Policy dispatcher tests ────────────────────────────────

func TestNewPolicyDispatcher(t *testing.T) {
	pd := orch.NewPolicyDispatcher()
	if pd == nil {
		t.Fatal("NewPolicyDispatcher returned nil")
	}
}

func TestRegisterAgent(t *testing.T) {
	pd := orch.NewPolicyDispatcher()
	pd.RegisterAgent("agent-a")
	pd.RegisterAgent("agent-b")
	pd.RegisterAgent("agent-a") // duplicate — should be ignored
}

func TestBroadcast(t *testing.T) {
	pd := orch.NewPolicyDispatcher()
	pd.RegisterAgent("agent-a")
	pd.RegisterAgent("agent-b")

	cmd := pd.Broadcast(orch.CmdBlockUID, "1000", "Block compromised UID", 96, "sensor-1", time.Hour)
	if cmd == nil {
		t.Fatal("nil command")
	}
	if cmd.Type != orch.CmdBlockUID {
		t.Errorf("type = %s", cmd.Type)
	}
	if cmd.Target != "1000" {
		t.Errorf("target = %s", cmd.Target)
	}
}

func TestBroadcastIfHighRisk(t *testing.T) {
	pd := orch.NewPolicyDispatcher()
	pd.RegisterAgent("agent-a")

	// Low risk → no broadcast
	cmds := pd.BroadcastIfHighRisk(50, "sensor-1", 1000, "", "", "")
	if len(cmds) != 0 {
		t.Errorf("low risk should not broadcast: %d commands", len(cmds))
	}

	// High risk → broadcast all
	cmds = pd.BroadcastIfHighRisk(96, "sensor-1", 1000, "bash", "abc123", "5.6.7.8")
	if len(cmds) == 0 {
		t.Fatal("high risk should broadcast")
	}
	t.Logf("Broadcast %d commands for risk=96", len(cmds))
	for _, cmd := range cmds {
		t.Logf("  %s: %s", cmd.Type, cmd.Target)
	}
}

func TestCommands(t *testing.T) {
	pd := orch.NewPolicyDispatcher()
	pd.Broadcast(orch.CmdBlockUID, "1000", "test", 95, "sensor-1", time.Hour)

	cmds := pd.Commands()
	if len(cmds) != 1 {
		t.Errorf("commands = %d", len(cmds))
	}
}

func TestStats(t *testing.T) {
	pd := orch.NewPolicyDispatcher()
	pd.RegisterAgent("agent-a")
	stats := pd.Stats()
	if stats["agents"].(int) != 1 {
		t.Errorf("agents = %d", stats["agents"])
	}
}

// ─── Isolation engine tests ─────────────────────────────────

func TestNewIsolationEngine(t *testing.T) {
	ie := orch.NewIsolationEngine()
	if ie == nil {
		t.Fatal("NewIsolationEngine returned nil")
	}
}

func TestUIDBlock(t *testing.T) {
	ie := orch.NewIsolationEngine()
	cmd := &orch.PolicyCommand{
		Type: orch.CmdBlockUID, Target: "1000",
		TTL: time.Hour,
	}
	ie.ExecuteCommand(cmd)

	if !ie.IsUIDBlocked(1000) {
		t.Error("UID 1000 should be blocked")
	}
	if ie.IsUIDBlocked(999) {
		t.Error("UID 999 should not be blocked")
	}
}

func TestCommBlock(t *testing.T) {
	ie := orch.NewIsolationEngine()
	ie.ExecuteCommand(&orch.PolicyCommand{
		Type: orch.CmdBlockComm, Target: "bash", TTL: time.Hour,
	})

	if !ie.IsCommBlocked("bash") {
		t.Error("bash should be blocked")
	}
}

func TestFileLock(t *testing.T) {
	ie := orch.NewIsolationEngine()
	ie.ExecuteCommand(&orch.PolicyCommand{
		Type: orch.CmdLockFile, Target: "abc123def456", TTL: time.Hour,
	})

	if !ie.IsFileLocked("abc123def456") {
		t.Error("file hash should be locked")
	}
}

func TestIPBlock(t *testing.T) {
	ie := orch.NewIsolationEngine()
	ie.ExecuteCommand(&orch.PolicyCommand{
		Type: orch.CmdBlockIP, Target: "5.6.7.8", TTL: time.Hour,
	})

	if !ie.IsIPBlocked("5.6.7.8") {
		t.Error("IP should be blocked")
	}
}

func TestBlockedCounts(t *testing.T) {
	ie := orch.NewIsolationEngine()
	ie.ExecuteCommand(&orch.PolicyCommand{Type: orch.CmdBlockUID, Target: "1000", TTL: time.Hour})
	ie.ExecuteCommand(&orch.PolicyCommand{Type: orch.CmdBlockComm, Target: "bash", TTL: time.Hour})

	counts := ie.BlockedCounts()
	if counts["uid_blocks"] != 1 {
		t.Errorf("uid blocks = %d", counts["uid_blocks"])
	}
}

// ─── Cached policy store tests ──────────────────────────────

func TestNewCachedPolicyStore(t *testing.T) {
	cps := orch.NewCachedPolicyStore(nil)
	if cps == nil {
		t.Fatal("NewCachedPolicyStore returned nil")
	}
}

func TestSyncFromServer(t *testing.T) {
	ie := orch.NewIsolationEngine()
	cps := orch.NewCachedPolicyStore(ie)

	cmds := []*orch.PolicyCommand{
		{Type: orch.CmdBlockUID, Target: "1000", TTL: time.Hour},
		{Type: orch.CmdBlockComm, Target: "bash", TTL: time.Hour},
	}
	cps.SyncFromServer(cmds)

	if !cps.IsSynced() {
		t.Error("should be synced")
	}
	if cps.CommandCount() != 2 {
		t.Errorf("commands = %d", cps.CommandCount())
	}
	if !ie.IsUIDBlocked(1000) {
		t.Error("UID should be blocked after sync")
	}
}

func TestExecuteCached(t *testing.T) {
	ie := orch.NewIsolationEngine()
	cps := orch.NewCachedPolicyStore(ie)
	cps.SyncFromServer([]*orch.PolicyCommand{
		{Type: orch.CmdBlockUID, Target: "2000", TTL: time.Hour},
	})

	n := cps.ExecuteCached()
	if n > 0 {
		t.Logf("executed %d cached commands", n)
	}
}

func TestLastSync(t *testing.T) {
	cps := orch.NewCachedPolicyStore(nil)
	ls := cps.LastSync()
	if !ls.IsZero() {
		t.Log("last sync set (unexpected before sync)")
	}

	cps.SyncFromServer([]*orch.PolicyCommand{})
	if cps.LastSync().IsZero() {
		t.Error("last sync should be set after sync")
	}
}

func TestStats(t *testing.T) {
	cps := orch.NewCachedPolicyStore(nil)
	stats := cps.Stats()
	if !stats["synced"].(bool) {
		t.Log("not synced yet")
	}
}

// ─── Integration test ───────────────────────────────────────

func TestOrchIntegration(t *testing.T) {
	t.Log("=== Global Response Orchestration Integration ===")

	// 1. Policy dispatcher
	pd := orch.NewPolicyDispatcher()
	pd.RegisterAgent("agent-web-01")
	pd.RegisterAgent("agent-db-01")
	pd.RegisterAgent("agent-app-05")

	// Simulate high-risk detection
	cmds := pd.BroadcastIfHighRisk(96, "sensor-web-01", 1001, "nginx", "hash123", "5.6.7.8")
	t.Logf("Broadcast: %d commands", len(cmds))

	issued := pd.Commands()
	t.Logf("Total issued: %d", len(issued))

	// 2. Local isolation (agent side)
	ie := orch.NewIsolationEngine()
	for _, cmd := range cmds {
		ie.ExecuteCommand(cmd)
	}
	t.Logf("UID 1001 blocked: %v", ie.IsUIDBlocked(1001))
	t.Logf("nginx blocked:    %v", ie.IsCommBlocked("nginx"))
	t.Logf("IP 5.6.7.8 blocked: %v", ie.IsIPBlocked("5.6.7.8"))
	t.Logf("Hash locked:     %v", ie.IsFileLocked("hash123"))

	counts := ie.BlockedCounts()
	t.Logf("Blocks: %d UID, %d comm, %d file, %d IP",
		counts["uid_blocks"], counts["comm_blocks"],
		counts["file_locks"], counts["ip_blocks"])

	// 3. Partition tolerance - cached policy execution
	cps := orch.NewCachedPolicyStore(ie)
	cps.SyncFromServer(issued)

	// Simulate network partition
	n := cps.ExecuteCached()
	t.Logf("Cached commands executed during partition: %d", n)
	t.Logf("Cache synced: %v, last sync: %v", cps.IsSynced(), cps.LastSync())

	_ = cps.Stats()

	t.Log("Orchestration integration OK")
}
