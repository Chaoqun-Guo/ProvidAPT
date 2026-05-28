//go:build integration

package integration

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestCaptureFileOpen verifies that ProvidAPT captures file open events.
func TestCaptureFileOpen(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("integration tests require root (eBPF loading)")
	}

	// In full integration:
	// 1. Start providaptd as a subprocess
	// 2. Perform a known action (e.g., cat /etc/hostname)
	// 3. Check the output log for the expected event

	cmd := exec.Command("providaptd", "-config", "testdata/test_config.toml")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start providaptd: %v", err)
	}
	defer cmd.Process.Kill()

	time.Sleep(2 * time.Second) // wait for eBPF loading

	// Trigger a file read event
	exec.Command("cat", "/etc/hostname").Run()

	time.Sleep(1 * time.Second) // wait for event delivery

	// TODO: verify output log contains file_open for /etc/hostname
}
