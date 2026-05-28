package defense

import (
	"os"
	"testing"
)

func TestRegisterPID(t *testing.T) {
	// Manager needs real eBPF maps — test the logic flows
	mgr := New(nil, nil, nil)
	if mgr == nil {
		t.Fatal("New returned nil")
	}
	// Without real maps, these calls will error but not panic
	_ = mgr.RegisterAgentPID(0)
	_ = mgr.UnregisterAgentPID(0)
}

func TestRegisterWatchdog(t *testing.T) {
	mgr := New(nil, nil, nil)
	err := mgr.RegisterWatchdogPID(12345)
	t.Logf("RegisterWatchdogPID (no bpf map): %v", err)
}

func TestProtectPathNoBPF(t *testing.T) {
	mgr := New(nil, nil, nil)
	// Without a real BPF map, this will fail on Put
	err := mgr.ProtectPath("/tmp")
	t.Logf("ProtectPath (no bpf map): %v", err)
}

func TestDeathChannel(t *testing.T) {
	mgr := New(nil, nil, nil)
	ch := mgr.DeathEvents()
	if ch == nil {
		t.Error("DeathEvents returned nil channel")
	}
}

func TestSetupPartial(t *testing.T) {
	mgr := New(nil, nil, nil)
	// Without BPF maps, Setup will log errors but not panic
	err := Setup(mgr, "/tmp")
	if err != nil {
		t.Logf("Setup returned: %v", err)
	}
}

func TestFlagConstants(t *testing.T) {
	if AgentFlag != 1 {
		t.Errorf("AgentFlag = %d, want 1", AgentFlag)
	}
	if WatchdogFlag != 2 {
		t.Errorf("WatchdogFlag = %d, want 2", WatchdogFlag)
	}
}

// ── Integration-style tests ─────────────────────────────

func TestInodeResolution(t *testing.T) {
	// Verify we can resolve inodes (needed for ProtectPath)
	tmp := t.TempDir()
	f, err := os.CreateTemp(tmp, "test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	info, err := os.Stat(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	stat, ok := info.Sys().(interface{ Ino() uint64 })
	if !ok {
		t.Skip("platform does not support Ino() access")
	}
	if stat.Ino() == 0 {
		t.Error("resolved inode is 0")
	} else {
		t.Logf("inode of %s: %d", f.Name(), stat.Ino())
	}
}

func TestDirectoryWalk(t *testing.T) {
	// Create a temp directory structure
	root := t.TempDir()
	os.MkdirAll(root+"/subdir", 0755)
	os.WriteFile(root+"/subdir/data.txt", []byte("test"), 0644)

	// Without BPF maps, this won't protect anything but shouldn't crash
	mgr := New(nil, nil, nil)

	// This should iterate without errors
	err := mgr.ProtectDirectory(root)
	t.Logf("ProtectDirectory (no bpf map): %v", err)
}

func TestAgentConstants(t *testing.T) {
	// Verify the Go constants match the kernel-side defines
	if AgentFlag != 1 {
		t.Errorf("AgentFlag should be 1 (kernel AGENT_FLAG)")
	}
}
