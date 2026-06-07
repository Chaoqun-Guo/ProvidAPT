// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package orch

import (
	"testing"
	"time"
)

func TestIsolationEngineNew(t *testing.T) {
	ie := NewIsolationEngine()
	if ie == nil {
		t.Fatal("NewIsolationEngine returned nil")
	}
}

func TestIsolationEngineBlockUID(t *testing.T) {
	ie := NewIsolationEngine()
	ie.ExecuteCommand(&PolicyCommand{
		Type:   CmdBlockUID,
		Target: "1000",
		TTL:    time.Hour,
	})

	if !ie.IsUIDBlocked(1000) {
		t.Error("expected UID 1000 to be blocked")
	}
	if ie.IsUIDBlocked(999) {
		t.Error("UID 999 should not be blocked")
	}
}

func TestIsolationEngineBlockComm(t *testing.T) {
	ie := NewIsolationEngine()
	ie.ExecuteCommand(&PolicyCommand{
		Type:   CmdBlockComm,
		Target: "nc",
		TTL:    time.Hour,
	})

	if !ie.IsCommBlocked("nc") {
		t.Error("expected nc to be blocked")
	}
	if ie.IsCommBlocked("bash") {
		t.Error("bash should not be blocked")
	}
}

func TestIsolationEngineBlockFile(t *testing.T) {
	ie := NewIsolationEngine()
	ie.ExecuteCommand(&PolicyCommand{
		Type:   CmdLockFile,
		Target: "abc123hash",
		TTL:    time.Hour,
	})

	if !ie.IsFileLocked("abc123hash") {
		t.Error("expected file to be locked")
	}
}

func TestIsolationEngineBlockIP(t *testing.T) {
	ie := NewIsolationEngine()
	ie.ExecuteCommand(&PolicyCommand{
		Type:   CmdBlockIP,
		Target: "198.51.100.1",
		TTL:    time.Hour,
	})

	if !ie.IsIPBlocked("198.51.100.1") {
		t.Error("expected IP to be blocked")
	}
}

func TestIsolationEngineBlockedCounts(t *testing.T) {
	ie := NewIsolationEngine()
	ie.ExecuteCommand(&PolicyCommand{Type: CmdBlockUID, Target: "1000", TTL: time.Hour})
	ie.ExecuteCommand(&PolicyCommand{Type: CmdBlockComm, Target: "nc", TTL: time.Hour})
	ie.ExecuteCommand(&PolicyCommand{Type: CmdBlockIP, Target: "10.0.0.1", TTL: time.Hour})

	counts := ie.BlockedCounts()
	if counts["uid_blocks"] != 1 {
		t.Errorf("uid_blocks = %d", counts["uid_blocks"])
	}
	if counts["comm_blocks"] != 1 {
		t.Errorf("comm_blocks = %d", counts["comm_blocks"])
	}
}

func TestCachedPolicyStoreNew(t *testing.T) {
	ie := NewIsolationEngine()
	cps := NewCachedPolicyStore(ie)
	if cps == nil {
		t.Fatal("NewCachedPolicyStore returned nil")
	}
}

func TestCachedPolicyStoreSync(t *testing.T) {
	ie := NewIsolationEngine()
	cps := NewCachedPolicyStore(ie)

	cps.SyncFromServer([]*PolicyCommand{
		{Type: CmdBlockUID, Target: "1000", TTL: time.Hour},
		{Type: CmdBlockComm, Target: "nc", TTL: time.Hour},
	})

	if !cps.IsSynced() {
		t.Error("expected synced")
	}
	if cps.CommandCount() != 2 {
		t.Errorf("commands = %d", cps.CommandCount())
	}

	if !ie.IsUIDBlocked(1000) {
		t.Error("expected UID to be blocked after sync")
	}
}

func TestCachedPolicyStoreExecuteCached(t *testing.T) {
	ie := NewIsolationEngine()
	cps := NewCachedPolicyStore(ie)

	cps.SyncFromServer([]*PolicyCommand{
		{Type: CmdBlockUID, Target: "2000", TTL: time.Hour},
	})

	n := cps.ExecuteCached()
	if n != 1 {
		t.Errorf("executed = %d", n)
	}
}

func TestCachedPolicyStoreLastSync(t *testing.T) {
	ie := NewIsolationEngine()
	cps := NewCachedPolicyStore(ie)
	if !cps.LastSync().IsZero() {
		t.Error("expected zero time initially")
	}
}

func TestPolicyDispatcherNew(t *testing.T) {
	pd := NewPolicyDispatcher()
	if pd == nil {
		t.Fatal("NewPolicyDispatcher returned nil")
	}
}

func TestPolicyDispatcherRegisterAgent(t *testing.T) {
	pd := NewPolicyDispatcher()
	pd.RegisterAgent("agent-1")
	cmds := pd.Commands()
	if len(cmds) != 0 {
		t.Errorf("commands = %d", len(cmds))
	}
}

func TestPolicyDispatcherBroadcast(t *testing.T) {
	pd := NewPolicyDispatcher()
	pd.RegisterAgent("agent-1")

	cmd := pd.Broadcast(CmdBlockComm, "nc", "Block netcat", 85.0, "admin", 10*time.Minute)
	if cmd == nil {
		t.Fatal("nil command")
	}
	if cmd.Type != CmdBlockComm {
		t.Errorf("type = %v", cmd.Type)
	}
	if cmd.Target != "nc" {
		t.Errorf("target = %s", cmd.Target)
	}

	cmds := pd.Commands()
	if len(cmds) != 1 {
		t.Errorf("commands = %d", len(cmds))
	}
}

func TestPolicyDispatcherBroadcastIfHighRisk(t *testing.T) {
	pd := NewPolicyDispatcher()
	pd.RegisterAgent("agent-1")

	// Low risk (<=95) should not broadcast
	cmd := pd.BroadcastIfHighRisk(30.0, "admin", 0, "", "", "")
	if cmd != nil {
		t.Error("expected nil for low risk")
	}

	// High risk (>95) should broadcast
	cmd = pd.BroadcastIfHighRisk(96.0, "admin", 1001, "", "", "")
	if cmd == nil {
		t.Fatal("expected commands for high risk")
	}
}

func TestPolicyDispatcherStats(t *testing.T) {
	pd := NewPolicyDispatcher()
	pd.RegisterAgent("agent-1")
	pd.Broadcast(CmdBlockComm, "nc", "Block nc", 50.0, "admin", time.Hour)

	stats := pd.Stats()
	if stats["agents"].(int) != 1 {
		t.Errorf("agents = %d", stats["agents"])
	}
	if stats["commands_issued"].(int) != 1 {
		t.Errorf("commands = %d", stats["commands_issued"])
	}
}

func TestIsolationEngineMultipleCommands(t *testing.T) {
	ie := NewIsolationEngine()
	commands := []*PolicyCommand{
		{Type: CmdBlockUID, Target: "0", TTL: time.Hour},
		{Type: CmdBlockUID, Target: "1000", TTL: time.Hour},
		{Type: CmdBlockComm, Target: "bash", TTL: time.Hour},
		{Type: CmdBlockComm, Target: "sh", TTL: time.Hour},
		{Type: CmdLockFile, Target: "hash1", TTL: time.Hour},
		{Type: CmdLockFile, Target: "hash2", TTL: time.Hour},
		{Type: CmdLockFile, Target: "hash3", TTL: time.Hour},
		{Type: CmdBlockIP, Target: "10.0.0.1", TTL: time.Hour},
	}

	for _, cmd := range commands {
		ie.ExecuteCommand(cmd)
	}

	if !ie.IsUIDBlocked(0) {
		t.Error("UID 0 should be blocked")
	}
	if !ie.IsCommBlocked("bash") {
		t.Error("bash should be blocked")
	}
	if !ie.IsFileLocked("hash3") {
		t.Error("hash3 should be locked")
	}
	if !ie.IsIPBlocked("10.0.0.1") {
		t.Error("10.0.0.1 should be blocked")
	}

	counts := ie.BlockedCounts()
	if counts["uid_blocks"] != 2 {
		t.Errorf("uid_blocks = %d", counts["uid_blocks"])
	}
	if counts["file_locks"] != 3 {
		t.Errorf("file_locks = %d", counts["file_locks"])
	}
}
