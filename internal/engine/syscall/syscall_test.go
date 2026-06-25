// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package syscall

import (
	"testing"
)

func TestEventTypeString(t *testing.T) {
	tests := []struct {
		et   EventType
		want string
	}{
		{EventProcessFork, "proc_fork"},
		{EventProcessExec, "proc_exec"},
		{EventProcessExit, "proc_exit"},
		{EventFileOpen, "file_open"},
		{EventFileCreate, "file_create"},
		{EventFileModify, "file_modify"},
		{EventFileDelete, "file_delete"},
		{EventFileRename, "file_rename"},
		{EventNetConnect, "net_connect"},
		{EventNetAccept, "net_accept"},
		{EventNetSend, "net_send"},
		{EventNetRecv, "net_recv"},
		{EventCredSetuid, "cred_setuid"},
		{EventCredCapable, "cred_capable"},
		{EventMemfdCreate, "memfd_create"},
		{EventMprotectRX, "mprotect_rx"},
		{EventPipeWrite, "pipe_write"},
		{EventPipeRead, "pipe_read"},
	}

	for _, tt := range tests {
		got := tt.et.String()
		if got != tt.want {
			t.Errorf("EventType(%d).String() = %q, want %q", tt.et, got, tt.want)
		}
	}
}

func TestEventTypeUnknown(t *testing.T) {
	et := EventType(999)
	if et.String() != "unknown" {
		t.Errorf("expected unknown, got %q", et.String())
	}
}

func TestEventFlagConstants(t *testing.T) {
	if EventFlagNone != 0 {
		t.Errorf("EventFlagNone = %d", EventFlagNone)
	}
	if EventFlagFromUser != 1 {
		t.Errorf("EventFlagFromUser = %d", EventFlagFromUser)
	}
	if EventFlagIsRoot != 2 {
		t.Errorf("EventFlagIsRoot = %d", EventFlagIsRoot)
	}
	if EventFlagExecSetuid != 4 {
		t.Errorf("EventFlagExecSetuid = %d", EventFlagExecSetuid)
	}
}

// FuzzEventTypeString fuzzes EventType.String() with arbitrary values.
// FuzzEventTypeString fuzzes EventType.String() with arbitrary values.
func FuzzEventTypeString(f *testing.F) {
	f.Add(int(0))
	f.Add(int(100))
	f.Add(int(255))
	f.Fuzz(func(t *testing.T, n int) {
		et := EventType(n)
		s := et.String()
		if s == "" {
			t.Errorf("String() returned empty for %d", n)
		}
	})
}
