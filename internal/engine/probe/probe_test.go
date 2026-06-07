// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"runtime"
	"testing"
)

// ── Version parsing tests ───────────────────────────────────

func TestParseVersion(t *testing.T) {
	v, err := ParseVersion("5.11.0")
	if err != nil {
		t.Fatalf("ParseVersion: %v", err)
	}
	if v.Major != 5 || v.Minor != 11 || v.Patch != 0 {
		t.Errorf("got %d.%d.%d", v.Major, v.Minor, v.Patch)
	}
}

func TestParseVersionWithSuffix(t *testing.T) {
	v, err := ParseVersion("5.15.0-1029-aws")
	if err != nil {
		t.Fatalf("ParseVersion: %v", err)
	}
	if v.Major != 5 || v.Minor != 15 {
		t.Errorf("got %d.%d", v.Major, v.Minor)
	}
}

func TestParseVersionOld(t *testing.T) {
	v, err := ParseVersion("4.18.0")
	if err != nil {
		t.Fatalf("ParseVersion: %v", err)
	}
	if v.Minor != 18 {
		t.Errorf("minor = %d", v.Minor)
	}
}

func TestParseVersionInvalid(t *testing.T) {
	_, err := ParseVersion("invalid")
	if err == nil {
		t.Error("expected error for invalid version")
	}
}

// ── Mode selection tests ───────────────────────────────────

func TestModeDetectionFentry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Probe reads /proc — not available on Windows")
	}
	// With kernel ≥5.11 and BTF, ModeFentry should be selected
	r := Probe()
	if r == nil {
		t.Fatal("Probe returned nil")
	}
	t.Logf("Kernel: %s", r.KernelVer)
	t.Logf("Mode: %s (BTF=%v, LSM=%v, fentry=%v)",
		r.ModeName, r.BTFAvailable, r.BpfLSM, r.HasFentry)
	// Always produces a mode (even if none)
	if r.ModeName == "" {
		t.Error("empty mode name")
	}
}

func TestModeIntegrity(t *testing.T) {
	r := Probe()
	// Mode should be consistent with feature flags
	if r.HasFentry && r.Mode != ModeFentry {
		t.Errorf("has fentry but mode=%s", r.Mode)
	}
	if !r.HasFentry && r.Mode == ModeFentry {
		t.Errorf("mode=fentry but !HasFentry")
	}
}

// ── String tests ───────────────────────────────────────────

func TestModeStrings(t *testing.T) {
	if ModeNone.String() != "none" {
		t.Errorf("ModeNone = %s", ModeNone)
	}
	if ModeFentry.String() != "fentry" {
		t.Errorf("ModeFentry = %s", ModeFentry)
	}
	if ModeKprobe.String() != "kprobe" {
		t.Errorf("ModeKprobe = %s", ModeKprobe)
	}
}

func TestStructopt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Probe reads /proc — not available on Windows")
	}
	r := Probe()
	opts := r.Structopt()
	if opts["mode"] != r.ModeName {
		t.Errorf("Structopt mode = %v", opts["mode"])
	}
	if opts["btf_avail"] != r.BTFAvailable {
		t.Errorf("Structopt btf = %v", opts["btf_avail"])
	}
}

// ── Kallsyms tests ─────────────────────────────────────────

func TestKallsymsLookup(t *testing.T) {
	ks, err := ReadKallsyms()
	if err != nil {
		t.Skipf("kallsyms unavailable: %v (need root)", err)
	}
	if ks.Count() == 0 {
		t.Fatal("no symbols parsed")
	}
	t.Logf("total symbols: %d", ks.Count())

	// Try to find a common function
	addr, ok := ks.Lookup("security_file_open")
	if ok {
		t.Logf("security_file_open @ 0x%x", addr)
	} else {
		t.Log("security_file_open not found (may need root)")
	}
}

func TestKallsymsLookupPrefix(t *testing.T) {
	ks, err := ReadKallsyms()
	if err != nil {
		t.Skipf("kallsyms unavailable: %v", err)
	}
	hooks := ks.LookupPrefix("security_")
	t.Logf("security_* hooks: %d", len(hooks))
	for sym := range hooks {
		t.Logf("  %s", sym)
	}
}

func TestKallsymsBPFSymbols(t *testing.T) {
	ks, err := ReadKallsyms()
	if err != nil {
		t.Skipf("kallsyms unavailable: %v", err)
	}
	syms := ks.BPFSymbols()
	if len(syms) == 0 {
		t.Log("no BPF symbols resolved (expected without root)")
	} else {
		for sym, addr := range syms {
			t.Logf("  %s @ 0x%x", sym, addr)
		}
	}
}

func TestKallsymsStats(t *testing.T) {
	ks, err := ReadKallsyms()
	if err != nil {
		t.Skipf("kallsyms unavailable: %v", err)
	}
	stats := ks.Stats()
	if stats["total"] <= 0 {
		t.Error("total should be > 0")
	}
	t.Logf("kallsyms stats: total=%d sec=%d bpf=%d tp=%d",
		stats["total"], stats["security_hooks"], stats["bpf_symbols"], stats["tracepoints"])
}

func TestKallsymsAttachmentPoints(t *testing.T) {
	ks, err := ReadKallsyms()
	if err != nil {
		t.Skipf("kallsyms unavailable: %v", err)
	}
	points := ks.AttachmentPoints()
	if len(points) > 0 {
		t.Logf("attachment points: %d", len(points))
		for _, p := range points {
			t.Logf("  kprobe: %s @ 0x%x", p.Symbol, p.Address)
		}
	}
}

// ── Release string test ────────────────────────────────────

func TestReleaseString(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ReleaseString reads /proc — not available on Windows")
	}
	s := ReleaseString()
	if s == "" || s == "unknown" {
		t.Error("release string should not be empty")
	}
	t.Logf("release: %s", s)
}
