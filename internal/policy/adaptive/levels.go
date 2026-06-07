// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package adaptive implements the adaptive collection engine for
// ProvidAPT.  It dynamically adjusts per-process monitoring levels
// based on risk assessment from the analysis engine.
//
// Monitoring levels:
//
//   Level 1 (DEFAULT) — Core events only:
//     exec, fork, socket_connect
//     No path resolution, no file detail
//
//   Level 2 (SUSPICIOUS) — Detailed event capture:
//     File open/read/write with full paths
//     Socket data flow tracking
//     Environment variable snapshots
//
//   Level 3 (INVESTIGATING) — Full forensic capture:
//     All syscall tracing (kprobes)
//     Memory mapping (mmap, mprotect)
//     Process memory dumps
//     Context captures
//
// Dynamic policy delivery:
//   Analyzer detects alert → AdaptiveController.Upgrade(pid)
//     → Writes PID→Level2/3 to BPF map → eBPF enforces within 1µs
//
// Feedback loop:
//   10-minute cooldown timer → no new alerts → downgrade to Level 1
package adaptive

import "fmt"

// ═══════════════════════════════════════════════════════════════
// Monitoring levels
// ═══════════════════════════════════════════════════════════════

// Level represents a process monitoring intensity level.
type Level int

const (
	LevelDefault      Level = 1 // Core events only
	LevelSuspicious   Level = 2 // Full file, socket, env detail
	LevelInvestigating Level = 3 // Full syscall + memory + dump
	LevelMax          Level = 3
	LevelMin          Level = 1
)

func (l Level) String() string {
	switch l {
	case LevelDefault:
		return "DEFAULT"
	case LevelSuspicious:
		return "SUSPICIOUS"
	case LevelInvestigating:
		return "INVESTIGATING"
	default:
		return fmt.Sprintf("LEVEL_%d", l)
	}
}

// Description returns a human-readable description of the level.
func (l Level) Description() string {
	switch l {
	case LevelDefault:
		return "Core LSM events: exec, fork, connect"
	case LevelSuspicious:
		return "File detail, socket flow, env snapshots"
	case LevelInvestigating:
		return "Full syscall trace, memory dump, context capture"
	default:
		return "Unknown"
	}
}

// ─── Level capabilities ─────────────────────────────────────

// Capabilities returns the set of enabled capabilities for a level.
func (l Level) Capabilities() []string {
	switch l {
	case LevelDefault:
		return []string{"exec", "fork", "connect"}
	case LevelSuspicious:
		return []string{"exec", "fork", "connect", "file_detail", "socket_flow", "env_capture"}
	case LevelInvestigating:
		return []string{"exec", "fork", "connect", "file_detail", "socket_flow",
			"env_capture", "syscall_trace", "memory_trace", "memory_dump"}
	default:
		return nil
	}
}

// ─── Level thresholds ───────────────────────────────────────

// AlertThreshold returns the minimum alert score to upgrade to this level.
// These are used by the adaptive controller to decide when to upgrade.
func (l Level) AlertThreshold() float64 {
	switch l {
	case LevelDefault:
		return 0
	case LevelSuspicious:
		return 5.0 // Low severity
	case LevelInvestigating:
		return 20.0 // Medium-High severity
	default:
		return 999
	}
}

// DowngradeAfter returns the cooldown duration before auto-downgrade.
func (l Level) DowngradeAfter() int {
	switch l {
	case LevelSuspicious:
		return 600 // 10 minutes
	case LevelInvestigating:
		return 300 // 5 minutes (stricter — high cost)
	default:
		return 0
	}
}
