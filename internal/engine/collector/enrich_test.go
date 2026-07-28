package collector

import (
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
)

func TestProcessEnricherCachesProcessContext(t *testing.T) {
	enricher := NewProcessEnricher()
	execEvent := &Event{
		Type:    syscall.EventProcessExec,
		PID:     4242,
		PPID:    100,
		UID:     1000,
		GID:     1000,
		Comm:    "bash",
		ExePath: "/usr/bin/bash",
		Cmdline: "bash /tmp/payload.sh",
	}
	enricher.Enrich(execEvent)

	fileEvent := &Event{
		Type:     syscall.EventFileOpen,
		PID:      4242,
		Pathname: "/tmp/payload.sh",
	}
	enricher.Enrich(fileEvent)

	if fileEvent.Cmdline != "bash /tmp/payload.sh" {
		t.Fatalf("cached cmdline = %q", fileEvent.Cmdline)
	}
	if fileEvent.ExePath != "/usr/bin/bash" {
		t.Fatalf("cached exe_path = %q", fileEvent.ExePath)
	}
	if fileEvent.PPID != 100 {
		t.Fatalf("cached ppid = %d", fileEvent.PPID)
	}
}

func TestProcessEnricherPropagatesForkParentContext(t *testing.T) {
	enricher := NewProcessEnricher()
	parent := &Event{Type: syscall.EventProcessExec, PID: 100, UID: 1000, GID: 1000, Comm: "bash", Cmdline: "bash attack.sh"}
	enricher.Enrich(parent)
	fork := &Event{Type: syscall.EventProcessFork, PID: 100, ChildPID: 101, UID: 1000, GID: 1000, Comm: "bash"}
	enricher.Enrich(fork)

	child := &Event{Type: syscall.EventFileOpen, PID: 101, Pathname: "/tmp/out"}
	enricher.Enrich(child)

	if child.PPID != 100 {
		t.Fatalf("child ppid = %d", child.PPID)
	}
}

func TestProcessEnricherInfersPathFromCmdline(t *testing.T) {
	enricher := NewProcessEnricher()
	event := &Event{
		Type:     syscall.EventFileOpen,
		PID:      4243,
		Comm:     "cat",
		Pathname: "payload.sh",
		Cmdline:  "cat /tmp/providapt_full_chain/payload.sh",
	}

	enricher.Enrich(event)

	if event.Pathname != "/tmp/providapt_full_chain/payload.sh" {
		t.Fatalf("pathname = %q, want cmdline absolute path", event.Pathname)
	}
}
