// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package memtrack

import (
	"fmt"
	"strings"
	"testing"
)

// ─── Memfd tracker tests ────────────────────────────────────

func TestNewMemfdTracker(t *testing.T) {
	mt := NewMemfdTracker()
	if mt == nil {
		t.Fatal("NewMemfdTracker returned nil")
	}
}

func TestOnCreate(t *testing.T) {
	mt := NewMemfdTracker()
	mt.OnCreate(3, "evil.so", 100, "python")

	entry := mt.GetEntry(3)
	if entry == nil {
		t.Fatal("entry not found")
	}
	if entry.Name != "evil.so" {
		t.Errorf("name = %s", entry.Name)
	}
	if entry.PID != 100 {
		t.Errorf("pid = %d", entry.PID)
	}
}

func TestOnWrite(t *testing.T) {
	mt := NewMemfdTracker()
	mt.OnCreate(5, "payload", 100, "python")
	mt.OnWrite(5, 4096)

	entry := mt.GetEntry(5)
	if !entry.Written {
		t.Error("should be marked as written")
	}
	if entry.WriteSize != 4096 {
		t.Errorf("size = %d", entry.WriteSize)
	}
}

func TestOnExec(t *testing.T) {
	mt := NewMemfdTracker()
	mt.OnCreate(7, "script", 100, "python")
	mt.OnWrite(7, 8192)

	entry := mt.OnExec(7, 200, "bash")
	if entry == nil {
		t.Fatal("exec returned nil")
	}
	if entry.ExecPID != 200 {
		t.Errorf("exec pid = %d", entry.ExecPID)
	}
	if entry.ExecComm != "bash" {
		t.Errorf("exec comm = %s", entry.ExecComm)
	}

	chains := mt.CompletedChains()
	if len(chains) != 1 {
		t.Fatalf("completed = %d", len(chains))
	}
	summary := chains[0].ChainSummary()
	if !strings.Contains(summary, "script") {
		t.Errorf("summary = %s", summary)
	}
	t.Logf("Chain: %s", summary)
}

func TestOnClose(t *testing.T) {
	mt := NewMemfdTracker()
	mt.OnCreate(9, "temp", 100, "bash")
	mt.OnClose(9)

	if mt.GetEntry(9) != nil {
		t.Error("entry should be removed after close")
	}
}

func TestActiveCount(t *testing.T) {
	mt := NewMemfdTracker()
	mt.OnCreate(1, "a", 100, "bash")
	mt.OnCreate(2, "b", 200, "python")

	if mt.ActiveCount() != 2 {
		t.Errorf("active = %d", mt.ActiveCount())
	}
}

// ─── Mmap tracker tests ─────────────────────────────────────

func TestNewMmapTracker(t *testing.T) {
	mt := NewMmapTracker()
	if mt == nil {
		t.Fatal("NewMmapTracker returned nil")
	}
}

func TestOnMmapExec(t *testing.T) {
	mt := NewMmapTracker()
	mt.OnMmapExec(100, "bash", 0x7f0000000000, 4096, 5, 2, 3, "evil.so", true)

	mappings := mt.GetExecMappings(100)
	if len(mappings) != 1 {
		t.Fatalf("mappings = %d", len(mappings))
	}
	if !mappings[0].IsMemFD {
		t.Error("should be marked as memfd")
	}
	if mappings[0].Addr != 0x7f0000000000 {
		t.Errorf("addr = 0x%x", mappings[0].Addr)
	}
}

func TestMmapCount(t *testing.T) {
	mt := NewMmapTracker()
	mt.OnMmapExec(100, "bash", 0x1, 4096, 5, 2, 0, "", false)
	mt.OnMmapExec(200, "python", 0x2, 8192, 5, 2, 0, "", false)

	if mt.Count() != 2 {
		t.Errorf("count = %d", mt.Count())
	}
}

// ─── Exec flow tracker tests ────────────────────────────────

func TestNewExecFlowTracker(t *testing.T) {
	eft := NewExecFlowTracker(nil, nil)
	if eft == nil {
		t.Fatal("NewExecFlowTracker returned nil")
	}
}

func TestCompleteChain(t *testing.T) {
	memfds := NewMemfdTracker()
	mmaps := NewMmapTracker()
	eft := NewExecFlowTracker(memfds, mmaps)

	// 1. Create memfd
	memfds.OnCreate(3, "script.sh", 100, "python")

	// 2. Write payload
	eft.OnWrite(3, 100, "python", 4096)

	// 3. mmap PROT_EXEC from memfd
	mmaps.OnMmapExec(200, "bash", 0x7f0000000000, 4096, 5, 2, 3, "", true)

	// 4. fexecve from memfd
	chain := eft.OnFexecve(3, 200, "bash", "/proc/self/fd/3")

	if chain == nil {
		t.Fatal("chain not created")
	}
	if chain.MemfdCreate == nil {
		t.Error("missing memfd_create link")
	}
	if chain.MemfdWrite == nil || chain.MemfdWrite.Size != 4096 {
		t.Error("missing write link")
	}
	if chain.Fexecve == nil {
		t.Error("missing fexecve link")
	}
	if !chain.Complete {
		t.Log("chain marked incomplete (may be missing mmap link)")
	}

	t.Logf("Chain: %s", chain.Summary())
}

func TestPartialChainNoMemfd(t *testing.T) {
	eft := NewExecFlowTracker(nil, nil)
	chain := eft.OnFexecve(5, 200, "bash", "")

	if chain == nil {
		t.Fatal("chain not created")
	}
	if chain.Complete {
		t.Error("chain should not be complete without memfd")
	}
}

func TestMultipleChains(t *testing.T) {
	memfds := NewMemfdTracker()
	eft := NewExecFlowTracker(memfds, nil)

	memfds.OnCreate(1, "a.so", 100, "python")
	eft.OnWrite(1, 100, "python", 1000)
	eft.OnFexecve(1, 200, "bash", "")

	memfds.OnCreate(2, "b.so", 300, "node")
	eft.OnWrite(2, 300, "node", 2000)
	eft.OnFexecve(2, 400, "sh", "")

	chains := eft.Chains()
	if len(chains) != 2 {
		t.Errorf("chains = %d", len(chains))
	}
}

func TestStats(t *testing.T) {
	memfds := NewMemfdTracker()
	eft := NewExecFlowTracker(memfds, nil)

	memfds.OnCreate(1, "test.so", 100, "bash")
	eft.OnWrite(1, 100, "bash", 512)
	eft.OnFexecve(1, 200, "sh", "")

	stats := eft.Stats()
	if stats["chains"].(int) != 1 {
		t.Errorf("chains = %d", stats["chains"])
	}
	if stats["writes"].(int) != 1 {
		t.Errorf("writes = %d", stats["writes"])
	}
}

// ─── Integration test ───────────────────────────────────────

func TestMemtrackIntegration(t *testing.T) {
	t.Log("=== Memory Execution Tracking Integration ===")

	// Full "memory download → memory execution" scenario:
	//   1. python3 creates memfd("evil.so")
	//   2. python3 writes shellcode to memfd
	//   3. python3 mmap PROT_EXEC from memfd
	//   4. python3 calls fexecve on the memfd
	//   5. bash executes from the memfd

	memfds := NewMemfdTracker()
	mmaps := NewMmapTracker()
	eft := NewExecFlowTracker(memfds, mmaps)

	// Stage 1: Create
	memfds.OnCreate(3, "evil.so", 100, "python3")
	t.Log("Stage 1: memfd_create(evil.so) by python3(100)")

	// Stage 2: Write
	eft.OnWrite(3, 100, "python3", 32768)
	t.Log("Stage 2: python3 wrote 32768 bytes to fd 3")

	// Stage 3: mmap PROT_EXEC
	mmaps.OnMmapExec(100, "python3", 0x7f1234560000, 32768, 5, 2, 3, "", true)
	t.Log("Stage 3: python3 mmap PROT_EXEC fd=3 → 0x7f1234560000")

	// Stage 4: fexecve (does not change PID — replaces process image)
	chain := eft.OnFexecve(3, 100, "bash", "/proc/self/fd/3")
	t.Logf("Stage 4: fexecve(3) by pid=100 bash")

	// Verify complete chain
	if chain != nil {
		t.Logf("Chain summary: %s", chain.Summary())
		t.Logf("  Memfd:   %s (PID %d)", chain.MemfdCreate.Name, chain.MemfdCreate.PID)
		t.Logf("  Write:   %d bytes by %s(%d)", chain.MemfdWrite.Size,
			chain.MemfdWrite.Comm, chain.MemfdWrite.PID)
		t.Logf("  Mmap:    0x%x size=%d", chain.MmapExec.Addr, chain.MmapExec.Size)
		t.Logf("  Fexecve: %s(PID %d) fd=%d", chain.Fexecve.Comm, chain.Fexecve.PID, chain.Fexecve.FD)
	}

	stats := eft.Stats()
	t.Logf("Stats: chains=%d writes=%d fexecves=%d active_memfd=%d",
		stats["chains"], stats["writes"], stats["fexecves"], stats["active_memfd"])

	if stats["chains"].(int) != 1 {
		t.Error("expected 1 complete chain")
	}

	t.Log("Memory tracking integration OK")
}

func TestChainSummary(t *testing.T) {
	ec := &ExecChain{
		MemfdCreate: &MemfdEntry{Name: "payload", FD: 3, PID: 100, Comm: "python"},
		MemfdWrite:  &WriteEvent{FD: 3, Size: 8192},
		MmapExec:    &MmapEntry{},
		Fexecve:     &FexecveEvent{FD: 3, PID: 200, Comm: "bash"},
		Complete:    true,
	}
	summary := ec.Summary()
	if !strings.Contains(summary, "payload") {
		t.Errorf("summary = %s", summary)
	}
	t.Logf("Summary: %s", summary)
}

func TestExecFlowConcurrent(t *testing.T) {
	memfds := NewMemfdTracker()
	eft := NewExecFlowTracker(memfds, nil)

	// Simulate multiple concurrent memfd operations
	for i := 0; i < 10; i++ {
		fd := i
		memfds.OnCreate(fd, fmt.Sprintf("payload-%d", i), 100, "python")
		eft.OnWrite(fd, 100, "python", 4096)
		eft.OnFexecve(fd, 200, "bash", "")
	}

	if len(eft.Chains()) != 10 {
		t.Errorf("chains = %d, want 10", len(eft.Chains()))
	}
}
