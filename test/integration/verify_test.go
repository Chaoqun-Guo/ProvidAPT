// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/verify"
)

func TestVerifyIntegrationNonExistentStore(t *testing.T) {
	_, err := verify.RunChecks("/nonexistent/store", true)
	if err != nil {
		// Expected to fail for non-existent path
		t.Logf("expected error for non-existent store: %v", err)
	}
}

func TestVerifyIntegrationEmptyDir(t *testing.T) {
	dir := t.TempDir()
	report, err := verify.RunChecks(dir, true)
	if err != nil {
		t.Fatalf("RunChecks failed: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	if report.StorePath != dir {
		t.Errorf("expected store path %s, got %s", dir, report.StorePath)
	}
	if !report.DryRun {
		t.Error("expected dry_run=true")
	}
}

func TestVerifyIntegrationRepairOnEmptyDir(t *testing.T) {
	dir := t.TempDir()
	report, err := verify.RunChecks(dir, false)
	if err != nil {
		t.Fatalf("RunChecks failed: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	if report.DryRun {
		t.Error("expected dry_run=false")
	}
	// Repair on an empty store should be a no-op
	if err := verify.Repair(report, dir); err != nil {
		t.Fatalf("Repair failed: %v", err)
	}
}
