// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package alert

import (
	"encoding/binary"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
)

func newRawBuffer() []byte {
	buf := make([]byte, 332)
	le := binary.LittleEndian
	le.PutUint32(buf[0:4], uint32(syscall.EventFileOpen))
	le.PutUint32(buf[4:8], 0)
	le.PutUint64(buf[8:16], 1000000)
	le.PutUint32(buf[16:20], 1001)
	le.PutUint32(buf[20:24], 1001)
	le.PutUint32(buf[24:28], 1000)
	le.PutUint32(buf[28:32], 1000)
	le.PutUint32(buf[32:36], 1000)
	le.PutUint64(buf[36:44], 123456)
	le.PutUint32(buf[44:48], 8)
	le.PutUint32(buf[48:52], 3)
	le.PutUint32(buf[52:56], 0o644)
	le.PutUint32(buf[56:60], 0)
	copy(buf[60:76], "test\x00")
	copy(buf[76:], "/etc/passwd\x00")
	return buf
}

func rawFork(pid, ppid, childPid uint32, comm string, ts uint64) []byte {
	buf := newRawBuffer()
	le := binary.LittleEndian
	le.PutUint32(buf[0:4], uint32(syscall.EventProcessFork))
	le.PutUint64(buf[8:16], ts)
	le.PutUint32(buf[16:20], pid)
	le.PutUint32(buf[24:28], ppid)
	le.PutUint32(buf[36:40], childPid)
	copy(buf[60:76], []byte(comm+"\x00"))
	copy(buf[76:], "\x00")
	return buf
}

func rawExec(pid uint32, comm, pathname string, ts uint64) []byte {
	buf := newRawBuffer()
	le := binary.LittleEndian
	le.PutUint32(buf[0:4], uint32(syscall.EventProcessExec))
	le.PutUint64(buf[8:16], ts)
	le.PutUint32(buf[16:20], pid)
	copy(buf[60:76], []byte(comm+"\x00"))
	copy(buf[76:], []byte(pathname+"\x00"))
	return buf
}

func rawFileOpen(pid uint32, inode uint64, pathname, comm string, ts uint64) []byte {
	buf := newRawBuffer()
	le := binary.LittleEndian
	le.PutUint32(buf[0:4], uint32(syscall.EventFileOpen))
	le.PutUint64(buf[8:16], ts)
	le.PutUint32(buf[16:20], pid)
	le.PutUint64(buf[36:44], inode)
	copy(buf[60:76], []byte(comm+"\x00"))
	copy(buf[76:], []byte(pathname+"\x00"))
	return buf
}

func rawNetConnect(pid uint32, comm, addr string, ts uint64) []byte {
	buf := newRawBuffer()
	le := binary.LittleEndian
	le.PutUint32(buf[0:4], uint32(syscall.EventNetConnect))
	le.PutUint64(buf[8:16], ts)
	le.PutUint32(buf[16:20], pid)
	copy(buf[60:76], []byte(comm+"\x00"))
	copy(buf[76:], []byte(addr+"\x00"))
	return buf
}

var linearPattern = AttackPattern{
	ID: "TEST-LINEAR", Name: "Test Linear Download",
	Description: "Process forks curl which reads a /tmp file",
	Severity:    "HIGH",
	Steps: []PatternStep{
		{
			SourceType: "process", SourceMatch: "nginx",
			Relation: "wasInformedBy", TargetType: "process", TargetMatch: "curl",
		},
		{
			SourceType: "process", SourceMatch: "curl",
			Relation: "used", TargetType: "file", TargetMatch: "/tmp",
		},
	},
}

func linearMatcher() *PatternMatcher {
	return &PatternMatcher{patterns: []AttackPattern{linearPattern}}
}

func TestE2E_LinearChainDetection(t *testing.T) {
	rawEvents := [][]byte{
		rawFork(100, 1, 101, "nginx", 1000),
		rawExec(101, "curl", "/usr/bin/curl", 2000),
		rawFileOpen(101, 5001, "/tmp/evil.sh", "curl", 3000),
	}

	g := provenance.NewGraph()
	for _, raw := range rawEvents {
		evt, err := collector.ParseRawEvent(raw)
		if err != nil {
			t.Fatalf("ParseRawEvent: %v", err)
		}
		g.AddEvent(evt)
	}

	t.Logf("Graph: %d nodes, %d edges", g.Stats().Nodes, g.Stats().Edges)
	for _, n := range g.Nodes() {
		t.Logf("  node %s (subtype=%s, label=%q)", n.ID, n.Subtype, n.Label)
	}
	for _, e := range g.Edges() {
		t.Logf("  edge %s: %s --[%s]--> %s", e.ID, e.Source, e.Relation, e.Target)
	}

	pm := linearMatcher()
	matches := pm.MatchAll(g)
	if len(matches) == 0 {
		t.Fatal("expected pattern match for nginx->curl->/tmp chain")
	}
	found := false
	for _, m := range matches {
		t.Logf("Match: %s (nodes=%v)", m.Pattern.Name, m.Nodes)
		if m.Pattern.ID == "TEST-LINEAR" {
			found = true
		}
	}
	if !found {
		t.Error("linear pattern not matched")
	}
}

func TestE2E_FullPipeline(t *testing.T) {
	rawEvents := [][]byte{
		rawFork(300, 1, 301, "nginx", 1000),
		rawExec(301, "curl", "/usr/bin/curl", 2000),
		rawFileOpen(301, 6001, "/tmp/payload", "curl", 3000),
	}

	g := provenance.NewGraph()
	for _, raw := range rawEvents {
		evt, err := collector.ParseRawEvent(raw)
		if err != nil {
			t.Fatalf("ParseRawEvent: %v", err)
		}
		g.AddEvent(evt)
	}

	pipe := NewAlertPipeline(g, "")
	pipe.Matcher = linearMatcher()
	pipe.Tick(g)

	incidents := pipe.Incidents.ActiveIncidents()
	t.Logf("Active incidents after tick: %d", len(incidents))
	if len(incidents) == 0 {
		t.Error("expected incidents after tick")
	}
	for _, inc := range incidents {
		t.Logf("  %s (count=%d, severity=%s)", inc.PatternName, inc.Count, inc.Severity)
	}
}

func TestE2E_EmptyGraph(t *testing.T) {
	g := provenance.NewGraph()

	pm := linearMatcher()
	matches := pm.MatchAll(g)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}

	pipe := NewAlertPipeline(g, "")
	pipe.Matcher = linearMatcher()
	pipe.Tick(g)
	if len(pipe.Incidents.ActiveIncidents()) != 0 {
		t.Error("expected 0 incidents for empty graph")
	}
}

func TestE2E_NormalActivityNoMatch(t *testing.T) {
	rawEvents := [][]byte{
		rawFork(400, 1, 401, "systemd", 1000),
		rawExec(401, "sshd", "/usr/sbin/sshd", 2000),
		rawNetConnect(401, "sshd", "10.0.0.1:22", 3000),
	}

	g := provenance.NewGraph()
	for _, raw := range rawEvents {
		evt, err := collector.ParseRawEvent(raw)
		if err != nil {
			t.Fatalf("ParseRawEvent: %v", err)
		}
		g.AddEvent(evt)
	}

	pm := linearMatcher()
	matches := pm.MatchAll(g)
	if len(matches) != 0 {
		for _, m := range matches {
			t.Errorf("unexpected match: %s (nodes=%v)", m.Pattern.Name, m.Nodes)
		}
	}
}
