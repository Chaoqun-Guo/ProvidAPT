package forensic

import (
	"os"
	"testing"
)

// ── Hasher tests ────────────────────────────────────────────

func TestNewHasher(t *testing.T) {
	h := NewHasher()
	if h == nil {
		t.Fatal("NewHasher returned nil")
	}
}

func TestHashFile(t *testing.T) {
	h := NewHasher()
	path := t.TempDir() + "/test.bin"
	os.WriteFile(path, []byte("test data"), 0644)

	hash, err := h.HashFile(path)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}
	if len(hash) != 64 { // SHA-256 = 32 bytes = 64 hex chars
		t.Errorf("hash length = %d", len(hash))
	}
	t.Logf("SHA256: %s", hash)
}

func TestHashFileCaching(t *testing.T) {
	h := NewHasher()
	path := t.TempDir() + "/cached.bin"
	os.WriteFile(path, []byte("cache test"), 0644)

	h1, _ := h.HashFile(path)
	h2, _ := h.HashFile(path)

	if h1 != h2 {
		t.Error("cached hash should match")
	}
	stats := h.CacheStats()
	if stats["cached_hashes"] != 1 {
		t.Errorf("cached = %d", stats["cached_hashes"])
	}
}

func TestHashHex(t *testing.T) {
	hash := HashHex([]byte("test"))
	if len(hash) != 64 {
		t.Errorf("HashHex length = %d", len(hash))
	}
}

func TestHashPathFromInode(t *testing.T) {
	h := NewHasher()
	path := t.TempDir() + "/inode_test.bin"
	os.WriteFile(path, []byte("inode test"), 0644)

	hash, err := h.HashPathFromInode(path)
	if err != nil {
		t.Fatalf("HashPathFromInode: %v", err)
	}
	if len(hash) != 64 {
		t.Errorf("hash = %s", hash)
	}
}

func TestHashFileNotFound(t *testing.T) {
	h := NewHasher()
	_, err := h.HashFile("/nonexistent/path")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// ── YARA tests ──────────────────────────────────────────────

func TestNewYARAScanner(t *testing.T) {
	s := NewYARAScanner(nil)
	if s == nil {
		t.Fatal("NewYARAScanner returned nil")
	}
}

func TestYARAConfigDefaults(t *testing.T) {
	cfg := DefaultYARAConfig()
	if cfg.Binary != "yara" {
		t.Errorf("binary = %s", cfg.Binary)
	}
	if cfg.Timeout != 30 {
		t.Errorf("timeout = %d", cfg.Timeout)
	}
}

func TestYARAScanNoRules(t *testing.T) {
	s := NewYARAScanner(DefaultYARAConfig())
	result := s.ScanFile("/bin/sh")
	if result.Error == "" {
		t.Log("YARA scan attempted (yara may or may not be installed)")
	}
	t.Logf("YARA result: rules=%d, error=%s", result.RulesCount, result.Error)
}

func TestYARAAvailable(t *testing.T) {
	s := NewYARAScanner(DefaultYARAConfig())
	avail := s.IsAvailable()
	t.Logf("YARA available: %v", avail)
	// This test passes regardless of YARA installation
}

func TestYARAScanMemory(t *testing.T) {
	s := NewYARAScanner(DefaultYARAConfig())
	result := s.ScanMemory(os.Getpid())
	t.Logf("memory scan: %v", result.Error)
}

// ── Anomaly detection tests ─────────────────────────────────

func TestNewAnomalyDetector(t *testing.T) {
	ad := NewAnomalyDetector(NewHasher())
	if ad == nil {
		t.Fatal("NewAnomalyDetector returned nil")
	}
}

func TestCheckProcessBasic(t *testing.T) {
	ad := NewAnomalyDetector(NewHasher())
	anomaly := ad.CheckProcess(os.Getpid())
	if anomaly != nil {
		t.Logf("Anomaly detected: %s (severity=%s)", anomaly.Anomaly, anomaly.Severity)
	} else {
		t.Log("No anomaly detected for self (expected)")
	}
}

func TestCheckProcessHash(t *testing.T) {
	ad := NewAnomalyDetector(NewHasher())
	hash := ad.CheckProcessExeHash(os.Getpid())
	if hash == "" {
		t.Log("No hash returned (may be running as test binary)")
	} else {
		t.Logf("Process SHA256: %s", hash)
	}
}

func TestCheckProcessAnomalyMemory(t *testing.T) {
	// We can't easily create a real memory-executed binary in a test,
	// but we can test that the function handles edge cases gracefully
	ad := NewAnomalyDetector(NewHasher())
	anomaly := ad.CheckProcess(999999) // nonexistent PID
	if anomaly != nil {
		t.Logf("Non-existent PID: %s", anomaly.Anomaly)
	}
}

func TestQuickSummary(t *testing.T) {
	ad := NewAnomalyDetector(NewHasher())
	summary := ad.QuickSummary(os.Getpid())
	if summary == nil {
		t.Fatal("QuickSummary returned nil")
	}
	t.Logf("Summary: pid=%v, sha256=%v, anomaly=%v",
		summary["pid"], summary["sha256"], summary["anomaly"])
	if hash, ok := summary["sha256"]; ok && hash != "" {
		t.Logf("Binary hash: %s", hash)
	}
}

// ── Integration test ────────────────────────────────────────

func TestForensicIntegration(t *testing.T) {
	// Create a temporary "binary"
	path := t.TempDir() + "/test_binary"
	content := []byte("#!/bin/sh\necho test")
	os.WriteFile(path, content, 0755)

	// Hash it
	hasher := NewHasher()
	hash, err := hasher.HashFile(path)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}
	t.Logf("Binary hash: %s", hash)
	if len(hash) != 64 {
		t.Errorf("hash length = %d", len(hash))
	}

	// YARA scan (may not have yara installed)
	yar := NewYARAScanner(&YARAConfig{
		Binary:    "yara",
		RulesPath: path, // using the file itself as rules = won't match
	})
	_ = yar.ScanFile(path)

	// Anomaly check
	ad := NewAnomalyDetector(hasher)
	summary := ad.QuickSummary(os.Getpid())
	t.Logf("Forensic summary: %v", summary)

	t.Log("Forensic integration OK")
}
