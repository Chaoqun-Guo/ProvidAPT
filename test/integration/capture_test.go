//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
)

// TestCaptureFileOpen verifies that ProvidAPT captures file open events.
func TestCaptureFileOpen(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("integration tests require root (eBPF loading)")
	}

	// Use a temp directory for daemon output so we can read events back.
	outDir := t.TempDir()

	cmd := exec.Command("providaptd",
		"-config", "testdata/test_config.toml",
		"-log-level", "debug",
	)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("PROVIDAPT_OUTPUT_DIR=%s", outDir),
	)
	// Capture stderr for diagnostic log inspection.
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("start providaptd: %v", err)
	}
	defer cmd.Process.Kill()

	time.Sleep(2 * time.Second) // wait for eBPF loading

	// Trigger a file read event
	exec.Command("cat", "/etc/hostname").Run()

	time.Sleep(1 * time.Second) // wait for event delivery

	// Verify: scan NDJSON event files in the output directory for a file_open event.
	found := false
	filepath.Walk(outDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".ndjson") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var evt struct {
				Type     int    `json:"type"`
				Pathname string `json:"pathname,omitempty"`
			}
			if err := json.Unmarshal([]byte(line), &evt); err != nil {
				continue
			}
			if evt.Type == int(collector.EventFileOpen) && strings.Contains(evt.Pathname, "/etc/hostname") {
				found = true
				return fmt.Errorf("stop walk") // break out of Walk
			}
		}
		return nil
	})
	if !found {
		t.Logf("daemon stderr:\n%s", stderrBuf.String())
		t.Error("expected file_open event for /etc/hostname in NDJSON output")
	}
}
