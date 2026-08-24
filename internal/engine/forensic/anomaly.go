// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package forensic

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// ═══════════════════════════════════════════════════════════════
// Binary anomaly detection
//
// Detects:
//   1. Memory execution — /proc/pid/exe points to deleted file
//      (the binary was replaced or is memory-only)
//   2. File replacement — on-disk file differs from what was exec'd
//      (the binary was replaced after execution)
//   3. Inode mismatch — the inode of the running binary differs
//      from the on-disk file
// ═══════════════════════════════════════════════════════════════

// BinaryAnomaly describes a detected binary anomaly.
type BinaryAnomaly struct {
	PID      int    `json:"pid"`
	ExePath  string `json:"exe_path"`
	Anomaly  string `json:"anomaly"` // type of anomaly detected
	Detail   string `json:"detail"`
	Severity string `json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
}

// AnomalyDetector checks binaries for inconsistencies.
type AnomalyDetector struct {
	hasher *Hasher
}

// NewAnomalyDetector creates a binary anomaly detector.
func NewAnomalyDetector(hasher *Hasher) *AnomalyDetector {
	return &AnomalyDetector{hasher: hasher}
}

// CheckProcess examines a running process for binary anomalies.
func (ad *AnomalyDetector) CheckProcess(pid int) *BinaryAnomaly {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	commPath := fmt.Sprintf("/proc/%d/comm", pid)

	// Try to read the exe symlink
	exeTarget, err := os.Readlink(exePath)
	if err != nil {
		return &BinaryAnomaly{
			PID:      pid,
			ExePath:  exePath,
			Anomaly:  "EXE_UNAVAILABLE",
			Detail:   fmt.Sprintf("Cannot read /proc/%d/exe: %v", pid, err),
			Severity: "HIGH",
		}
	}

	// Check 1: Deleted binary (memory execution)
	if _, err := os.Stat(exeTarget); os.IsNotExist(err) {
		comm, _ := os.ReadFile(commPath)
		return &BinaryAnomaly{
			PID:      pid,
			ExePath:  exeTarget,
			Anomaly:  "MEMORY_EXECUTION",
			Detail:   fmt.Sprintf("Binary %s has been deleted from disk (comm: %s)", exeTarget, strings.TrimSpace(string(comm))),
			Severity: "CRITICAL",
		}
	}

	// Check 2: Inode mismatch (file replacement)
	exeInfo, err := os.Stat(exeTarget)
	if err != nil {
		return nil
	}

	exeStat, ok := exeInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}

	// Get the running binary's inode from /proc/pid/exe
	procExeInfo, err := os.Stat(exePath)
	if err != nil {
		return nil
	}
	procStat, ok := procExeInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}

	// If the inode of /proc/pid/exe differs from the on-disk file,
	// the binary was replaced after execution
	if procStat.Ino != exeStat.Ino {
		comm, _ := os.ReadFile(commPath)
		return &BinaryAnomaly{
			PID:     pid,
			Anomaly: "FILE_REPLACEMENT",
			Detail: fmt.Sprintf("Binary %s replaced after exec (inode diff: %d vs %d, comm: %s)",
				exeTarget, procStat.Ino, exeStat.Ino, strings.TrimSpace(string(comm))),
			Severity: "HIGH",
		}
	}

	return nil
}

// CheckProcessExeHash computes the SHA-256 of a process's binary.
// Returns "" if the binary cannot be read.
func (ad *AnomalyDetector) CheckProcessExeHash(pid int) string {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	hash, err := ad.hasher.HashPathFromInode(exePath)
	if err != nil {
		return ""
	}
	return hash
}

// QuickSummary runs all binary checks and returns a summary.
func (ad *AnomalyDetector) QuickSummary(pid int) map[string]interface{} {
	result := map[string]interface{}{
		"pid": pid,
	}
	anomaly := ad.CheckProcess(pid)
	if anomaly != nil {
		result["anomaly"] = anomaly.Anomaly
		result["anomaly_detail"] = anomaly.Detail
		result["severity"] = anomaly.Severity
	}
	hash := ad.CheckProcessExeHash(pid)
	if hash != "" {
		result["sha256"] = hash
	}
	return result
}
