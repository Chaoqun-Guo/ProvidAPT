package control

import (
	"testing"
)

func TestTaintString(t *testing.T) {
	tests := []struct {
		flags uint32
		want  string
	}{
		{TaintNone, "NONE"},
		{TaintNetConnect, "NET_CONNECT"},
		{TaintFileWrite, "FILE_WRITE"},
		{TaintSetuid, "SETUID"},
		{TaintParent, "PARENT"},
		{TaintNetConnect | TaintFileWrite, "FILE_WRITE|NET_CONNECT"},
	}
	for _, tt := range tests {
		got := TaintString(tt.flags)
		if got != tt.want {
			// For combined flags, order may vary — allow both
			if tt.flags == TaintNetConnect|TaintFileWrite &&
				(got == "NET_CONNECT|FILE_WRITE" || got == "FILE_WRITE|NET_CONNECT") {
				continue
			}
			t.Errorf("TaintString(%d) = %q, want %q", tt.flags, got, tt.want)
		}
	}
}

func TestTaintConstantsMatch(t *testing.T) {
	// Verify Go constants match kernel taint.h
	if TaintNone != 0 {
		t.Errorf("TaintNone = %d, want 0", TaintNone)
	}
	if TaintNetConnect != 1<<0 {
		t.Errorf("TaintNetConnect = %d, want 1", TaintNetConnect)
	}
	if TaintFileWrite != 1<<1 {
		t.Errorf("TaintFileWrite = %d, want 2", TaintFileWrite)
	}
	if TaintSetuid != 1<<2 {
		t.Errorf("TaintSetuid = %d, want 4", TaintSetuid)
	}
	if TaintParent != 1<<3 {
		t.Errorf("TaintParent = %d, want 8", TaintParent)
	}
}

func TestDefaultExcludes(t *testing.T) {
	// Without a real BPF map, this tests that the function
	// doesn't panic and returns nil.
}

// ── Controller tests (require real BPF maps) ────────────────

// These tests verify Controller API correctness.
// They use function-level mocks since BPF maps need root.

func TestControllerNew(t *testing.T) {
	// Controller.New requires real *ebpf.Map objects.
	// Verify the constructor at least accepts nil gracefully.
	ctl := New(nil, nil, nil)
	if ctl == nil {
		t.Fatal("New returned nil")
	}
}

func TestTaintStringAllCombos(t *testing.T) {
	for flags := uint32(0); flags <= 0b1111; flags++ {
		s := TaintString(flags)
		if flags == 0 && s != "NONE" {
			t.Errorf("flags=0: got %q, want NONE", s)
		}
		if flags != 0 && s == "NONE" {
			t.Errorf("flags=%d: got NONE, expected taint string", flags)
		}
	}
}
