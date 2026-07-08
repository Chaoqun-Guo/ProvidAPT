// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package response

import (
	"encoding/hex"
	"os"
	"testing"
	"unsafe"
)

// ── Test helpers ────────────────────────────────────────────

type memStore struct {
	data map[string][]byte
}

func newMemStore() *memStore                           { return &memStore{data: make(map[string][]byte)} }
func (m *memStore) Put(key string, value []byte) error { m.data[key] = value; return nil }
func (m *memStore) Get(key string) ([]byte, error)     { v, _ := m.data[key]; return v, nil }

// ── Dump tests ─────────────────────────────────────────────

func TestParseMaps(t *testing.T) {
	// Can't rely on real /proc/self/maps in all environments
	regions, err := ParseMaps(os.Getpid())
	if err != nil {
		t.Logf("ParseMaps(self) skipped: %v", err)
		return
	}
	t.Logf("self maps: %d regions", len(regions))
	if len(regions) > 0 {
		t.Logf("  first: %x-%x %s %s", regions[0].Start, regions[0].End, regions[0].Perms, regions[0].Pathname)
	}
}

func TestReadProcessMemory(t *testing.T) {
	// Read our own memory at a known address
	local := []byte("hello providapt")
	addr := uintptr(unsafe.Pointer(&local[0]))
	buf := make([]byte, len(local))
	n, err := readProcessMemory(os.Getpid(), uint64(addr), buf)
	if err != nil {
		t.Fatalf("readProcessMemory: %v", err)
	}
	if n != len(local) {
		t.Errorf("read %d bytes, want %d", n, len(local))
	}
	if string(buf[:n]) != "hello providapt" {
		t.Errorf("got %q", string(buf[:n]))
	}
}

func TestFormatDumpSize(t *testing.T) {
	tests := []struct {
		bytes int
		want  string
	}{
		{500, "500 B"},
		{2048, "2.0 KB"},
		{5 * 1024 * 1024, "5.0 MB"},
	}
	for _, tt := range tests {
		got := FormatDumpSize(tt.bytes)
		if got != tt.want {
			t.Errorf("FormatDumpSize(%d) = %q", tt.bytes, got)
		}
	}
}

// ── Capture tests ──────────────────────────────────────────

func TestCaptureContext(t *testing.T) {
	pc, err := CaptureContext(os.Getpid())
	if err != nil {
		t.Fatalf("CaptureContext: %v", err)
	}
	if pc.PID <= 0 {
		t.Errorf("PID = %d", pc.PID)
	}
	if len(pc.Status) == 0 {
		t.Error("no status fields captured")
	}
	t.Logf("captured: pid=%d comm=%s status=%d fds=%d env=%d",
		pc.PID, pc.Comm, len(pc.Status), len(pc.OpenFDs), pc.Environment.Count)
}

func TestSaveCapture(t *testing.T) {
	pc := &ProcessCapture{
		PID:  1234,
		Comm: "test",
		OpenFDs: []FDCapture{
			{FD: 0, Target: "/dev/pts/0"},
			{FD: 1, Target: "pipe:[12345]"},
		},
		Environment: EnvCapture{
			Raw:   []string{"PATH=/usr/bin", "HOME=/root"},
			Count: 2,
		},
	}
	dir := t.TempDir()
	path, err := SaveCapture(dir, pc)
	if err != nil {
		t.Fatalf("SaveCapture: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("empty capture file")
	}
	t.Logf("capture saved (%d bytes): %s", len(data), path)
}

// ── Evidence tests ─────────────────────────────────────────

func TestEvidenceCreate(t *testing.T) {
	em := NewEvidenceManager(newMemStore())
	rec, err := em.CreateEvidence(
		"alert-001", 35.0, 1234, "bash",
		"abc123", "def456", "ghi789",
		"systemd → sshd → bash → /etc/shadow",
		"/tmp/dump", "/tmp/capture.txt",
	)
	if err != nil {
		t.Fatalf("CreateEvidence: %v", err)
	}
	if rec.CaseID == "" {
		t.Error("empty CaseID")
	}
	if rec.Signature == "" {
		t.Error("empty signature")
	}
	t.Logf("evidence: case=%s sig=%s", rec.CaseID, rec.Signature[:16])
}

func TestEvidenceVerify(t *testing.T) {
	store := newMemStore()
	em := NewEvidenceManager(store)
	rec, _ := em.CreateEvidence(
		"alert-002", 40.0, 5678, "python3",
		"hash1", "hash2", "hash3",
		"apache2 → bash",
		"/tmp/dump2", "/tmp/cap2.txt",
	)

	valid, err := em.Verify(rec)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !valid {
		t.Error("signature verification failed")
	}
}

func TestEvidenceTampered(t *testing.T) {
	store := newMemStore()
	em := NewEvidenceManager(store)
	rec, _ := em.CreateEvidence(
		"alert-003", 30.0, 9999, "test",
		"h1", "h2", "h3",
		"path", "/d", "/c",
	)

	// Tamper with the record
	rec.ThreatScore = 100.0

	valid, _ := em.Verify(rec)
	if valid {
		t.Error("tampered record should not verify")
	}
}

func TestEvidencePersistAndLoad(t *testing.T) {
	store := newMemStore()
	em := NewEvidenceManager(store)
	created, _ := em.CreateEvidence(
		"alert-004", 50.0, 1111, "nc",
		"m1", "c1", "g1",
		"bash → nc → 5.6.7.8:443",
		"/d1", "/c1",
	)

	// Load from store
	loaded, valid, err := em.GetEvidence(created.CaseID)
	if err != nil {
		t.Fatalf("GetEvidence: %v", err)
	}
	if !valid {
		t.Error("loaded evidence not valid")
	}
	if loaded.AlertID != "alert-004" {
		t.Errorf("AlertID = %q", loaded.AlertID)
	}
}

func TestEvidenceKeyIntegrity(t *testing.T) {
	// Verify HMAC key is 32 bytes
	key := make([]byte, HMACKeySize)
	if len(key) != 32 {
		t.Errorf("HMAC key size = %d", len(key))
	}
}

func TestEvidenceManagerWithKey(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	em := NewEvidenceManagerWithKey(newMemStore(), key)
	if hex.EncodeToString(key) != em.HMACKeyHex() {
		t.Error("key not stored correctly")
	}
}

// ── Response hook tests ────────────────────────────────────

func TestResponseConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ThreatThreshold != 25.0 {
		t.Errorf("threshold = %.1f", cfg.ThreatThreshold)
	}
	if !cfg.EnableMemoryDump {
		t.Error("memory dump should be enabled by default")
	}
}

func TestResponseHookBelowThreshold(t *testing.T) {
	rh := New(DefaultConfig(), newMemStore())
	result := rh.OnAlert(&AlertSummary{
		AlertID: "test-001", ThreatScore: 10.0, PID: 100, Comm: "bash",
	})
	if result.Triggered {
		t.Error("should not trigger below threshold")
	}
}

func TestResponseHookAboveThreshold(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ThreatThreshold = 10.0 // low for testing
	rh := New(cfg, newMemStore())

	result := rh.OnAlert(&AlertSummary{
		AlertID: "test-002", ThreatScore: 50.0,
		PID: os.Getpid(), Comm: "test",
		GraphPath: "p:1 → p:100 → /etc/shadow",
	})
	if !result.Triggered {
		t.Error("should trigger above threshold")
	}
	t.Logf("case: %s", result.CaseID)
	t.Logf("dump_hash: %s", result.DumpHash)
	t.Logf("cap_hash: %s", result.CaptureHash)
}

func TestResponseHandlerCallback(t *testing.T) {
	rh := New(DefaultConfig(), newMemStore())
	fn := rh.ResponseHandler()
	// Should not panic
	fn("alert-999", 5.0, 9999, "test", "graph path")
}

func TestDisabledMemoryDump(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ThreatThreshold = 1.0
	cfg.EnableMemoryDump = false
	rh := New(cfg, newMemStore())

	result := rh.OnAlert(&AlertSummary{
		AlertID: "test-003", ThreatScore: 30.0,
		PID: os.Getpid(), Comm: "test",
	})
	if result.DumpDir != "" {
		t.Error("dump should be disabled")
	}
	if result.CaseID == "" {
		t.Error("evidence should still be created")
	}
}
