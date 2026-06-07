// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package response

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ═══════════════════════════════════════════════════════════════
// FD and environment capture
// ═══════════════════════════════════════════════════════════════

// FDCapture represents a single open file descriptor.
type FDCapture struct {
	FD     int    `json:"fd"`
	Target string `json:"target"` // symlink target (file path, socket, pipe)
	Flags  string `json:"flags,omitempty"`
	Pos    int64  `json:"pos,omitempty"`
}

// EnvCapture represents environment variables (values can be redacted).
type EnvCapture struct {
	Raw     []string `json:"raw,omitempty"`     // full key=value list
	Redacted []string `json:"redacted,omitempty"` // keys only, values hidden
	Count   int      `json:"count"`
}

// CaptureCapture holds all captured context for a process.
type ProcessCapture struct {
	PID         int           `json:"pid"`
	Comm        string        `json:"comm"`
	CmdLine     string        `json:"cmdline"`
	Status      map[string]string `json:"status"`
	OpenFDs     []FDCapture   `json:"open_fds"`
	Environment EnvCapture    `json:"environment"`
}

// CaptureContext collects all runtime context for a process.
func CaptureContext(pid int) (*ProcessCapture, error) {
	pc := &ProcessCapture{
		PID:    pid,
		Status: make(map[string]string),
	}

	// Read comm
	if comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		pc.Comm = strings.TrimSpace(string(comm))
	}

	// Read cmdline
	if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		pc.CmdLine = strings.ReplaceAll(string(cmdline), "\x00", " ")
		pc.CmdLine = strings.TrimSpace(pc.CmdLine)
	}

	// Read status
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				pc.Status[key] = val
			}
		}
	}

	// Read open FDs
	if fdDir, err := os.Open(fmt.Sprintf("/proc/%d/fd", pid)); err == nil {
		defer fdDir.Close()
		if entries, err := fdDir.Readdir(-1); err == nil {
			for _, entry := range entries {
				fdNum := 0
				fmt.Sscanf(entry.Name(), "%d", &fdNum)
				target, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()))
				pc.OpenFDs = append(pc.OpenFDs, FDCapture{
					FD:     fdNum,
					Target: target,
				})
			}
		}
	}

	// Read environment
	if envData, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)); err == nil {
		raw := strings.Split(string(envData), "\x00")
		for _, e := range raw {
			e = strings.TrimSpace(e)
			if e == "" {
				continue
			}
			pc.Environment.Raw = append(pc.Environment.Raw, e)
			// Redacted version: key=*** (hide values for security)
			if parts := strings.SplitN(e, "=", 2); len(parts) == 2 {
				pc.Environment.Redacted = append(pc.Environment.Redacted, parts[0]+"=***")
			} else {
				pc.Environment.Redacted = append(pc.Environment.Redacted, e)
			}
		}
		pc.Environment.Count = len(pc.Environment.Raw)
	}

	return pc, nil
}

// SaveCapture writes the capture data to disk as JSON.
func SaveCapture(outDir string, pc *ProcessCapture) (string, error) {
	dir := filepath.Join(outDir, fmt.Sprintf("capture_%d", pc.PID))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}
	path := filepath.Join(dir, "context.txt")
	var b strings.Builder
	b.WriteString(fmt.Sprintf("PID: %d\n", pc.PID))
	b.WriteString(fmt.Sprintf("Comm: %s\n", pc.Comm))
	b.WriteString(fmt.Sprintf("CmdLine: %s\n", pc.CmdLine))
	b.WriteString("\n=== Status ===\n")
	for k, v := range pc.Status {
		b.WriteString(fmt.Sprintf("%s: %s\n", k, v))
	}
	b.WriteString(fmt.Sprintf("\n=== Open FDs (%d) ===\n", len(pc.OpenFDs)))
	for _, fd := range pc.OpenFDs {
		b.WriteString(fmt.Sprintf("fd %d → %s\n", fd.FD, fd.Target))
	}
	b.WriteString(fmt.Sprintf("\n=== Environment (%d vars) ===\n", pc.Environment.Count))
	for _, e := range pc.Environment.Redacted {
		b.WriteString(fmt.Sprintf("  %s\n", e))
	}
	if err := os.WriteFile(path, []byte(b.String()), 0400); err != nil {
		return "", err
	}
	return path, nil
}
