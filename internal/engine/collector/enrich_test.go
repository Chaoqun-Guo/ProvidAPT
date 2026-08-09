package collector

import (
	"os"
	"path/filepath"
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
		Cwd:     "/tmp",
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
	if fileEvent.CmdlineSource != "cache" {
		t.Fatalf("cached cmdline source = %q", fileEvent.CmdlineSource)
	}
	if fileEvent.ExePath != "/usr/bin/bash" {
		t.Fatalf("cached exe_path = %q", fileEvent.ExePath)
	}
	if fileEvent.Cwd != "/tmp" {
		t.Fatalf("cached cwd = %q", fileEvent.Cwd)
	}
	if fileEvent.PPID != 100 {
		t.Fatalf("cached ppid = %d", fileEvent.PPID)
	}
}

func TestProcessEnricherReadsPPIDFromProcStat(t *testing.T) {
	oldProcRoot := procRoot
	t.Cleanup(func() { procRoot = oldProcRoot })
	root := t.TempDir()
	procRoot = root
	pidDir := filepath.Join(root, "4247")
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "stat"), []byte("4247 (worker thread) S 1234 1 1 0 -1 0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	event := &Event{Type: syscall.EventFileOpen, PID: 4247, Pathname: "/tmp/x"}
	NewProcessEnricher().Enrich(event)

	if event.PPID != 1234 {
		t.Fatalf("procfs ppid = %d, want 1234", event.PPID)
	}
}

func TestProcessEnricherInfersPathFromCwd(t *testing.T) {
	enricher := NewProcessEnricher()
	event := &Event{
		Type:     syscall.EventFileCreate,
		PID:      4244,
		Comm:     "bash",
		Pathname: "payload.sh",
		Cwd:      "/tmp/providapt_full_chain",
	}

	enricher.Enrich(event)

	if event.Pathname != "/tmp/providapt_full_chain/payload.sh" {
		t.Fatalf("pathname = %q, want cwd-relative path", event.Pathname)
	}
}

func TestProcessEnricherDoesNotInferPseudoPathFromCwd(t *testing.T) {
	enricher := NewProcessEnricher()
	event := &Event{
		Type:     syscall.EventFileOpen,
		PID:      4245,
		Comm:     "cat",
		Pathname: "cmdline",
		Cwd:      "/tmp/providapt_full_chain",
	}

	enricher.Enrich(event)

	if event.Pathname != "cmdline" {
		t.Fatalf("pathname = %q, want pseudo path unchanged", event.Pathname)
	}
}

func TestProcessEnricherPropagatesForkParentContext(t *testing.T) {
	enricher := NewProcessEnricher()
	parent := &Event{Type: syscall.EventProcessExec, PID: 100, UID: 1000, GID: 1000, Comm: "bash", Cmdline: "bash attack.sh", Cwd: "/tmp/providapt"}
	enricher.Enrich(parent)
	fork := &Event{Type: syscall.EventProcessFork, PID: 100, ChildPID: 101, UID: 1000, GID: 1000, Comm: "bash"}
	enricher.Enrich(fork)

	child := &Event{Type: syscall.EventFileOpen, PID: 101, Pathname: "out"}
	enricher.Enrich(child)

	if child.PPID != 100 {
		t.Fatalf("child ppid = %d", child.PPID)
	}
	if child.Pathname != "/tmp/providapt/out" {
		t.Fatalf("child pathname = %q", child.Pathname)
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

func TestProcessEnricherUsesExecPathAsCmdlineFallback(t *testing.T) {
	enricher := NewProcessEnricher()
	event := &Event{
		Type:     syscall.EventProcessExec,
		PID:      4246,
		Comm:     "bash",
		Pathname: "/usr/bin/curl",
	}

	enricher.Enrich(event)

	if event.Cmdline != "/usr/bin/curl" || event.CmdlineSource != "exec_path" {
		t.Fatalf("cmdline fallback = %q source=%q", event.Cmdline, event.CmdlineSource)
	}
}
