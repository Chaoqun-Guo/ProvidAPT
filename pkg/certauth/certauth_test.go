// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package certauth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInitialize(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		CADir:      filepath.Join(dir, "ca"),
		ServerDir:  filepath.Join(dir, "server"),
		ClientDir:  filepath.Join(dir, "client"),
		ValidYears: 1,
		KeyBits:    2048, // faster for tests
	}

	certFile, keyFile, caFile, err := Initialize(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Verify files exist
	if _, err := os.Stat(certFile); err != nil {
		t.Errorf("server cert missing: %v", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Errorf("server key missing: %v", err)
	}
	if _, err := os.Stat(caFile); err != nil {
		t.Errorf("ca cert missing: %v", err)
	}

	// Fingerprint should work
	fp, err := CertFingerprint(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(fp) == 0 {
		t.Error("empty fingerprint")
	}
}

func TestInitializeIdempotent(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		CADir:      filepath.Join(dir, "ca"),
		ServerDir:  filepath.Join(dir, "server"),
		ClientDir:  filepath.Join(dir, "client"),
		ValidYears: 1,
		KeyBits:    2048,
	}

	// First call
	_, _, _, err := Initialize(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Second call should load existing CA and succeed
	_, _, _, err = Initialize(cfg)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateClientCert(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		CADir:      filepath.Join(dir, "ca"),
		ServerDir:  filepath.Join(dir, "server"),
		ClientDir:  filepath.Join(dir, "client"),
		ValidYears: 1,
		KeyBits:    2048,
	}

	_, _, _, err := Initialize(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ca, err := LoadCA(cfg)
	if err != nil {
		t.Fatal(err)
	}

	certPEM, keyPEM, err := ca.CreateClientCert(cfg, "test-client")
	if err != nil {
		t.Fatal(err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Error("empty cert or key")
	}
}

func TestNeedsRotation(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		CADir:      filepath.Join(dir, "ca"),
		ServerDir:  filepath.Join(dir, "server"),
		ClientDir:  filepath.Join(dir, "client"),
		ValidYears: 10,
		KeyBits:    2048,
	}

	certFile, _, _, err := Initialize(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Should not need rotation yet
	needed, err := NeedsRotation(certFile, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if needed {
		t.Error("fresh cert should not need rotation")
	}

	// For a 10-year cert, asking "does it expire in 20 years?" should say yes
	needed, err = NeedsRotation(certFile, 20*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !needed {
		t.Error("cert should need rotation in 20-year window")
	}
}

func TestNeedsRotationMissingFile(t *testing.T) {
	needed, err := NeedsRotation("/nonexistent/cert.pem", 30*24*time.Hour)
	if err == nil {
		t.Error("expected error for missing file")
	}
	if !needed {
		t.Error("missing file should report rotation needed")
	}
}

func TestRotateServerCert(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		CADir:      filepath.Join(dir, "ca"),
		ServerDir:  filepath.Join(dir, "server"),
		ClientDir:  filepath.Join(dir, "client"),
		ValidYears: 1,
		KeyBits:    2048,
	}
	certFile, keyFile, _, err := Initialize(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := RotateServerCert(cfg, certFile, keyFile); err != nil {
		t.Fatalf("RotateServerCert: %v", err)
	}
	if _, err := os.Stat(certFile); err != nil {
		t.Fatalf("rotated cert missing: %v", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Fatalf("rotated key missing: %v", err)
	}
	backups, err := filepath.Glob(certFile + ".bak.*")
	if err != nil {
		t.Fatalf("glob backups: %v", err)
	}
	if len(backups) != 1 {
		t.Fatalf("cert backups = %d, want 1", len(backups))
	}
	needed, err := NeedsRotation(certFile, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("NeedsRotation: %v", err)
	}
	if needed {
		t.Fatal("rotated cert should not need immediate rotation")
	}
}

func TestLoadCAInvalidDir(t *testing.T) {
	cfg := &Config{CADir: "/nonexistent"}
	_, err := LoadCA(cfg)
	if err == nil {
		t.Error("expected error for missing CA dir")
	}
}

func TestDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.defaults()
	if cfg.Org != "ProvidAPT" {
		t.Errorf("expected default Org 'ProvidAPT', got %q", cfg.Org)
	}
	if cfg.ValidYears != 10 {
		t.Errorf("expected default ValidYears 10, got %d", cfg.ValidYears)
	}
	if cfg.KeyBits != 4096 {
		t.Errorf("expected default KeyBits 4096, got %d", cfg.KeyBits)
	}
}

func TestCertFingerprintInvalid(t *testing.T) {
	_, err := CertFingerprint("/nonexistent")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
