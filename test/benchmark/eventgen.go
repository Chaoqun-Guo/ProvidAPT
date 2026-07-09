// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package benchmark provides a high-throughput event generator that
// simulates realistic kernel provenance events for performance testing.
package benchmark

import (
	"math/rand"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
)

// ─── Event distribution ─────────────────────────────────────
//
// Realistic event mix based on production provenance traces:
//
//   Event type      Share  Description
//   ──────────      ─────  ───────────
//   FileOpen         40%   cat, grep, editor reading files
//   FileModify       20%   writing logs, temp files
//   FileCreate        5%   creating new files
//   ProcessFork      20%   shell forks, daemon spawning
//   ProcessExec      10%   running commands
//   FileDelete        3%   cleanup, temp file removal
//   FileRename        2%   mv, atomic writes

var eventWeights = []struct {
	typ    syscall.EventType
	weight int
}{
	{syscall.EventFileOpen, 40},
	{syscall.EventFileModify, 20},
	{syscall.EventFileCreate, 5},
	{syscall.EventProcessFork, 20},
	{syscall.EventProcessExec, 10},
	{syscall.EventFileDelete, 3},
	{syscall.EventFileRename, 2},
}

// ─── Process tree simulation ────────────────────────────────
//
// A small pool of "processes" that generate events, simulating a
// realistic system with short-lived and long-lived processes.

type simulatedProcess struct {
	pid  uint32
	comm string
	uid  uint32
}

var processPool = []simulatedProcess{
	{1, "systemd", 0},
	{100, "nginx", 0}, {101, "nginx", 0},
	{200, "sshd", 0}, {201, "sshd", 0},
	{300, "bash", 1000}, {301, "bash", 1000},
	{400, "curl", 1000}, {401, "wget", 1000},
	{500, "python3", 1000}, {501, "node", 1000},
	{600, "apache2", 33}, {601, "php-fpm", 33},
	{700, "dockerd", 0}, {701, "containerd", 0},
}

var filePaths = []string{
	"/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/default",
	"/var/log/nginx/access.log", "/var/log/nginx/error.log",
	"/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config",
	"/var/log/auth.log", "/var/log/syslog",
	"/tmp/upload.php", "/tmp/cache.dat", "/tmp/session_abc123",
	"/home/user/.bashrc", "/home/user/.ssh/authorized_keys",
	"/usr/share/nginx/html/index.html",
	"/var/www/html/wp-config.php",
	"/proc/self/status", "/proc/cpuinfo",
}

var exePaths = []string{
	"/usr/sbin/nginx", "/usr/sbin/sshd",
	"/usr/bin/bash", "/usr/bin/curl", "/usr/bin/wget",
	"/usr/bin/python3", "/usr/bin/node",
	"/usr/sbin/apache2", "/usr/sbin/php-fpm",
	"/usr/bin/dockerd", "/usr/bin/containerd",
}

// ─── Generator ───────────────────────────────────────────────

type Generator struct {
	mu         sync.Mutex
	nextPID    uint32
	baseTS     uint64
	eventCount uint64

	rng *rand.Rand
}

// NewGenerator creates an event generator.
func NewGenerator() *Generator {
	return &Generator{
		nextPID: 800,
		baseTS:  uint64(time.Now().UnixNano()),
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Generate produces n random provenance events simulating system
// activity.  Events are time-ordered and realistic.
func (g *Generator) Generate(n int) []*collector.Event {
	out := make([]*collector.Event, n)

	for i := 0; i < n; i++ {
		// Pick event type by weighted random
		typ := g.pickType()

		// Pick a "process" that generates this event
		proc := processPool[g.rng.Intn(len(processPool))]

		g.mu.Lock()
		g.eventCount++
		ts := g.baseTS + g.eventCount*200 // 200 ns between events = 5M/s max
		g.mu.Unlock()

		evt := &collector.Event{
			Type:        typ,
			TimestampNS: ts,
			PID:         proc.pid,
			TID:         proc.pid,
			PPID:        proc.pid - proc.pid%100 + 1, // simplified
			UID:         proc.uid,
			Comm:        proc.comm,
			Inode:       uint64(g.rng.Uint32()) + 1,
			DevMajor:    8,
			DevMinor:    3,
			Mode:        0o100644,
			FFlags:      0,
		}

		// Fill type-specific fields
		switch typ {
		case syscall.EventProcessFork:
			g.mu.Lock()
			g.nextPID++
			evt.ChildPID = g.nextPID
			g.mu.Unlock()
			evt.Comm = proc.comm
			evt.Pathname = ""

		case syscall.EventProcessExec:
			evt.Pathname = exePaths[g.rng.Intn(len(exePaths))]
			evt.Comm = proc.comm
			evt.Inode = uint64(g.rng.Uint32()) + 1

		case syscall.EventFileOpen, syscall.EventFileCreate,
			syscall.EventFileModify, syscall.EventFileDelete,
			syscall.EventFileRename:
			evt.Pathname = filePaths[g.rng.Intn(len(filePaths))]
			evt.Inode = uint64(g.rng.Uint32()) + 1
			if typ == syscall.EventFileCreate || typ == syscall.EventFileModify {
				evt.FFlags = 1 // O_WRONLY
			}
		}

		out[i] = evt
	}
	return out
}

// pickType returns a random event type weighted by distribution.
func (g *Generator) pickType() syscall.EventType {
	total := 0
	for _, ew := range eventWeights {
		total += ew.weight
	}
	r := g.rng.Intn(total)
	for _, ew := range eventWeights {
		r -= ew.weight
		if r < 0 {
			return ew.typ
		}
	}
	return syscall.EventFileOpen
}

// Progress returns the total events generated so far.
func (g *Generator) Progress() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.eventCount
}
