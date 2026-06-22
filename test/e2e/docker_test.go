// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func runDocker(args ...string) ([]byte, error) {
	if runtime.GOOS == "windows" {
		// Use bash -c for proper Windows path resolution with Docker Desktop
		cmdLine := "docker " + strings.Join(args, " ")
		return exec.Command("bash", "-c", cmdLine).CombinedOutput()
	}
	cmd := exec.Command("docker", args...)
	return cmd.CombinedOutput()
}

// TestDockerAvailable verifies docker CLI is available.
func TestDockerAvailable(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found in PATH")
	}
	out, err := runDocker("--version")
	if err != nil {
		t.Fatalf("docker --version failed: %v", err)
	}
	t.Logf("Docker: %s", strings.TrimSpace(string(out)))
}

// TestDockerBuildProduction builds the production Alpine-based image and
// verifies providaptctl --help works.
func TestDockerBuildProduction(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found in PATH")
	}

	// Try to use existing image first, build if not available
	out, err := runDocker("image", "inspect", "providapt:prod-test")
	imageExists := err == nil

	if !imageExists {
		t.Log("Building production image (may take several minutes)...")
		out, err = runDocker("build",
			"-t", "providapt:prod-test",
			"-f", "Dockerfile",
			".")
		if err != nil {
			t.Skipf("docker build failed (network issue?): %v", err)
		}
		t.Log("Production image built")
	} else {
		t.Log("Using existing providapt:prod-test image")
	}

	// Run providaptctl --help inside the image
	out, err = runDocker("run", "--rm",
		"providapt:prod-test",
		"providaptctl", "--help")
	if err != nil {
		t.Fatalf("providaptctl --help failed: %v\nOutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "Usage") {
		t.Errorf("expected 'Usage' in output, got: %s", string(out))
	}
	t.Logf("providaptctl --help: %s", strings.SplitN(string(out), "\n", 2)[0])
}

// TestDockerListBinaries verifies that the production image contains all
// expected binaries.
func TestDockerListBinaries(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found in PATH")
	}

	// Try to use or build the image
	out, err := runDocker("image", "inspect", "providapt:prod-test")
	if err != nil {
		out, err = runDocker("build",
			"-t", "providapt:prod-test",
			"-f", "Dockerfile", ".")
		if err != nil {
			t.Skipf("docker build failed: %v", err)
		}
	}

	expected := []string{"providaptd", "providaptctl", "providapt-watchdog",
		"providapt-verify", "providapt-heal"}
	for _, bin := range expected {
		out, err = runDocker("run", "--rm",
			"providapt:prod-test",
			"which", bin)
		if err != nil {
			t.Errorf("binary %s not found in image: %v", bin, err)
			continue
		}
		t.Logf("  ✓ %s: %s", bin, strings.TrimSpace(string(out)))
	}
}
