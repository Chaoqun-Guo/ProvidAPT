// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package control

import (
	"testing"
)

func TestTaintString_None(t *testing.T) {
	if s := TaintString(TaintNone); s != "NONE" {
		t.Errorf("TaintString(0) = %q, want %q", s, "NONE")
	}
}

func TestTaintString_Single(t *testing.T) {
	tests := []struct {
		flags uint32
		want  string
	}{
		{TaintNetConnect, "NET_CONNECT"},
		{TaintFileWrite, "FILE_WRITE"},
		{TaintSetuid, "SETUID"},
		{TaintParent, "PARENT"},
	}
	for _, tt := range tests {
		if got := TaintString(tt.flags); got != tt.want {
			t.Errorf("TaintString(%d) = %q, want %q", tt.flags, got, tt.want)
		}
	}
}

func TestTaintString_Multiple(t *testing.T) {
	flags := TaintNetConnect | TaintFileWrite
	s := TaintString(flags)
	if s != "NET_CONNECT|FILE_WRITE" && s != "FILE_WRITE|NET_CONNECT" {
		t.Errorf("unexpected taint string: %q", s)
	}
}

func TestTaintString_All(t *testing.T) {
	flags := TaintNetConnect | TaintFileWrite | TaintSetuid | TaintParent
	s := TaintString(flags)
	if s == "NONE" || s == "" {
		t.Errorf("unexpected taint string for all flags: %q", s)
	}
}

func TestTaintString_Unknown(t *testing.T) {
	s := TaintString(1 << 7)
	if s != "0x80" {
		t.Errorf("unknown flag should show hex value, got %q", s)
	}
}

func TestTaintString_MixedKnownUnknown(t *testing.T) {
	s := TaintString(TaintNetConnect | (1 << 10))
	if s != "NET_CONNECT|0x400" && s != "0x400|NET_CONNECT" {
		t.Errorf("mixed flags: unexpected string %q", s)
	}
}

func TestStatsNilController(t *testing.T) {
	var ctl *Controller
	stats := ctl.Stats()
	if stats["pid_whitelist_entries"] != 0 {
		t.Fatalf("pid_whitelist_entries = %v, want 0", stats["pid_whitelist_entries"])
	}
	if stats["tainted_processes"] != 0 {
		t.Fatalf("tainted_processes = %v, want 0", stats["tainted_processes"])
	}
	if stats["active_sample_counters"] != 0 {
		t.Fatalf("active_sample_counters = %v, want 0", stats["active_sample_counters"])
	}
}
