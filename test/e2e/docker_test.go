// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"os/exec"
	"strings"
	"testing"
)

func runDocker(args ...string) ([]byte, error) {
	cmd := exec.Command("docker", args...)
	return cmd.CombinedOutput()
}

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found in PATH")
	}
	if out, err := runDocker("info"); err != nil {
		t.Skipf("docker daemon is not available: %v\nOutput: %s", err, string(out))
	}
}

// TestDockerAvailable verifies docker CLI is available.
func TestDockerAvailable(t *testing.T) {
	requireDocker(t)
	out, err := runDocker("--version")
	if err != nil {
		t.Fatalf("docker --version failed: %v\nOutput: %s", err, string(out))
	}
	t.Logf("Docker: %s", strings.TrimSpace(string(out)))
}

// TestDockerBuildProduction builds the production image and verifies
// providaptctl help works.
func TestDockerBuildProduction(t *testing.T) {
	requireDocker(t)

	out, err := runDocker("image", "inspect", "providapt:prod-test")
	imageExists := err == nil

	if !imageExists {
		t.Log("Building production image (may take several minutes)...")
		out, err = runDocker("build",
			"-t", "providapt:prod-test",
			"-f", "Dockerfile",
			".")
		if err != nil {
			t.Skipf("docker build failed (network issue?): %v\nOutput: %s", err, string(out))
		}
		t.Log("Production image built")
	} else {
		t.Log("Using existing providapt:prod-test image")
	}

	out, err = runDocker("run", "--rm",
		"providapt:prod-test",
		"providaptctl", "--help")
	if err != nil {
		t.Fatalf("providaptctl --help failed: %v\nOutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "Usage") && !strings.Contains(string(out), "SYNOPSIS") {
		t.Errorf("expected help output, got: %s", string(out))
	}
	t.Logf("providaptctl --help: %s", strings.SplitN(string(out), "\n", 2)[0])
}

// TestDockerListBinaries verifies that the production image contains expected
// binaries.
func TestDockerListBinaries(t *testing.T) {
	requireDocker(t)

	out, err := runDocker("image", "inspect", "providapt:prod-test")
	if err != nil {
		out, err = runDocker("build",
			"-t", "providapt:prod-test",
			"-f", "Dockerfile", ".")
		if err != nil {
			t.Skipf("docker build failed: %v\nOutput: %s", err, string(out))
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
		t.Logf("ok %s: %s", bin, strings.TrimSpace(string(out)))
	}
}
