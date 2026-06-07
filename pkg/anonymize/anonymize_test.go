// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package anonymize

import (
	"os"
	"testing"
)

// ── Anonymizer tests ────────────────────────────────────────

func TestNewAnonymizer(t *testing.T) {
	a, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a == nil {
		t.Fatal("New returned nil")
	}
}

func TestHashDeterministic(t *testing.T) {
	a, _ := New(nil)
	h1 := a.HashPath("/etc/shadow")
	h2 := a.HashPath("/etc/shadow")
	if h1 != h2 {
		t.Errorf("not deterministic: %s vs %s", h1, h2)
	}
}

func TestHashDifferent(t *testing.T) {
	a, _ := New(nil)
	h1 := a.HashPath("/etc/shadow")
	h2 := a.HashPath("/etc/passwd")
	if h1 == h2 {
		t.Error("different paths should produce different hashes")
	}
}

func TestHashPathLength(t *testing.T) {
	a, _ := New(nil)
	h := a.HashPath("/etc/hosts")
	if len(h) != 16 {
		t.Errorf("hash length = %d, want 16", len(h))
	}
}

func TestHashIP(t *testing.T) {
	a, _ := New(nil)
	ip1 := a.HashIP("10.0.0.1")
	ip2 := a.HashIP("10.0.0.2")
	if ip1 == ip2 {
		t.Error("different IPs should produce different hashes")
	}
	if !hasPrefix(ip1, "ip_") {
		t.Errorf("IP hash prefix = %s", ip1[:3])
	}
}

func TestHashComm(t *testing.T) {
	a, _ := New(nil)
	c := a.HashComm("nginx")
	if len(c) != 8 {
		t.Errorf("comm hash length = %d", len(c))
	}
}

func TestKeyFile(t *testing.T) {
	cfg := &Config{
		HMACKeyHex: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		EncKeyHex:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	path := t.TempDir() + "/key.json"
	if err := SaveKeyFile(path, cfg); err != nil {
		t.Fatalf("SaveKeyFile: %v", err)
	}
	loaded, err := LoadKeyFile(path)
	if err != nil {
		t.Fatalf("LoadKeyFile: %v", err)
	}
	if loaded.HMACKeyHex != cfg.HMACKeyHex {
		t.Error("HMAC key mismatch")
	}
	if loaded.EncKeyHex != cfg.EncKeyHex {
		t.Error("Enc key mismatch")
	}
}

func TestHMACKeyManagement(t *testing.T) {
	a, _ := New(nil)
	keyHex := a.HMACKeyHex()
	if len(keyHex) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("key hex length = %d", len(keyHex))
	}
}

func TestIsAnonymizedPath(t *testing.T) {
	tests := []struct{ s string; want bool }{
		{"a3f8b2c1e4d5f6a7", true},
		{"/etc/shadow", false},
		{"short", false},
		{"nothex!@#$%^&*()", false},
	}
	for _, tt := range tests {
		got := IsAnonymizedPath(tt.s)
		if got != tt.want {
			t.Errorf("IsAnonymizedPath(%q) = %v", tt.s, got)
		}
	}
}

func TestKeyFilePermissions(t *testing.T) {
	path := t.TempDir() + "/secure.key"
	cfg := &Config{
		HMACKeyHex: "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
		EncKeyHex:  "55667788eeff001155667788eeff001155667788eeff001155667788eeff0011",
	}
	if err := SaveKeyFile(path, cfg); err != nil {
		t.Fatalf("SaveKeyFile: %v", err)
	}
	// File should exist
	if !fileExists(path) {
		t.Error("key file not created")
	}
}

// ── De-anonymization store tests ────────────────────────────

func TestDeAnonStore(t *testing.T) {
	path := t.TempDir() + "/deanon.json"
	key := make([]byte, 32)
	store, err := NewDeAnonStore(path, key)
	if err != nil {
		t.Fatalf("NewDeAnonStore: %v", err)
	}

	if err := store.Store("hash123", "/etc/shadow"); err != nil {
		t.Fatalf("Store: %v", err)
	}

	original, err := store.Lookup("hash123")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if original != "/etc/shadow" {
		t.Errorf("got %q, want /etc/shadow", original)
	}
}

func TestDeAnonStoreNotFound(t *testing.T) {
	path := t.TempDir() + "/deanon2.json"
	store, _ := NewDeAnonStore(path, make([]byte, 32))
	_, err := store.Lookup("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent hash")
	}
}

func TestDeAnonStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/deanon.json"
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	// Store
	s1, _ := NewDeAnonStore(path, key)
	s1.Store("abc", "/etc/shadow")
	s1.Store("def", "/etc/passwd")

	// Load new instance
	s2, _ := NewDeAnonStore(path, key)
	if s2.EntryCount() != 2 {
		t.Errorf("entries = %d, want 2", s2.EntryCount())
	}
	val, _ := s2.Lookup("abc")
	if val != "/etc/shadow" {
		t.Errorf("got %q", val)
	}
}

func TestDeAnonStoreEncryption(t *testing.T) {
	path := t.TempDir() + "/deanon3.json"

	// Different key → decryption should fail
	key1 := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // 32 a's
	key2 := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") // 32 b's

	s1, _ := NewDeAnonStore(path, key1)
	s1.Store("test", "sensitive value")

	// Try to read with different key
	s2, _ := NewDeAnonStore(path, key2)
	_, err := s2.Lookup("test")
	if err == nil {
		t.Error("expected decryption failure with wrong key")
	}
}

// ── Event anonymization tests ──────────────────────────────

func TestAnonymizeEvent(t *testing.T) {
	path := t.TempDir() + "/deanon_events.json"
	a, err := New(&Config{DeAnonPath: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	anon := a.AnonymizeEvent(10, 1000, 100, 1, 0, "bash", "/etc/shadow", 5000, 8, 3, 0644, 0, 0)
	if anon == nil {
		t.Fatal("nil anonymized event")
	}
	if anon.Comm == "bash" {
		t.Error("comm should be hashed")
	}
	if anon.Pathname == "/etc/shadow" {
		t.Error("path should be hashed")
	}
	if anon.Pathname == "" {
		t.Error("path should not be empty")
	}
	if anon.Inode != 5000 {
		t.Errorf("inode = %d", anon.Inode)
	}
}

func TestAnonymizeEventSkippedPath(t *testing.T) {
	a, _ := New(nil)
	anon := a.AnonymizeEvent(10, 1000, 100, 1, 0, "bash", "?", 0, 0, 0, 0, 0, 0)
	if anon.Pathname != "?" {
		t.Errorf("path = %q", anon.Pathname)
	}
}

func TestAnonymizeEventDeAnonStore(t *testing.T) {
	path := t.TempDir() + "/deanon_evt.json"
	a, _ := New(&Config{DeAnonPath: path})
	anon := a.AnonymizeEvent(10, 1, 100, 1, 0, "bash", "/etc/shadow", 5000, 8, 3, 0644, 0, 0)

	// Verify we can recover the original path
	original, err := a.deanon.Lookup(anon.Pathname)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if original != "/etc/shadow" {
		t.Errorf("got %q, want /etc/shadow", original)
	}
}

func TestSameKeySameHash(t *testing.T) {
	// Two anonymizers with the same key should produce the same hash
	cfg := &Config{
		HMACKeyHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	}
	a1, _ := New(cfg)
	a2, _ := New(cfg)

	h1 := a1.HashPath("/etc/hosts")
	h2 := a2.HashPath("/etc/hosts")
	if h1 != h2 {
		t.Error("same key should produce same hash")
	}
}

// ── Helpers ─────────────────────────────────────────────────

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
