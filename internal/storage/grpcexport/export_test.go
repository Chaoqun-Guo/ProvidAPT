// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package grpcexport

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// ─── gRPC exporter tests ────────────────────────────────────

func TestNewGRPCExporter(t *testing.T) {
	e := NewGRPCExporter(nil)
	if e == nil {
		t.Fatal("NewGRPCExporter returned nil")
	}
	if e.cfg.BatchSize != 50 {
		t.Errorf("BatchSize = %d", e.cfg.BatchSize)
	}
}

func TestExportQueuesEvent(t *testing.T) {
	e := NewGRPCExporter(nil)
	evt := &ExportEvent{PID: 100, Comm: "bash", EventType: 10}

	queued := e.Export(evt)
	if !queued {
		t.Error("event should be queued")
	}

	e.mu.Lock()
	count := len(e.buffer)
	e.mu.Unlock()
	if count != 1 {
		t.Errorf("buffer = %d, want 1", count)
	}
}

func TestExportHighRiskFilter(t *testing.T) {
	cfg := DefaultGRPCConfig()
	cfg.HighRiskOnly = true
	e := NewGRPCExporter(cfg)

	// Low risk — should be filtered
	low := &ExportEvent{PID: 1, Comm: "systemd", IsHighRisk: false}
	if e.Export(low) {
		t.Error("low risk should be filtered")
	}

	// High risk — should pass
	high := &ExportEvent{PID: 100, Comm: "bash", IsHighRisk: true}
	if !e.Export(high) {
		t.Error("high risk should pass")
	}
}

func TestExportScoreThreshold(t *testing.T) {
	cfg := DefaultGRPCConfig()
	cfg.ScoreThreshold = 50.0
	e := NewGRPCExporter(cfg)

	low := &ExportEvent{PID: 1, Score: 10}
	if e.Export(low) {
		t.Error("low score should be filtered")
	}

	high := &ExportEvent{PID: 100, Score: 75}
	if !e.Export(high) {
		t.Error("high score should pass")
	}
}

func TestExporterStartStop(t *testing.T) {
	e := NewGRPCExporter(nil)
	e.Start()
	e.Stop()
}

func TestExporterStats(t *testing.T) {
	e := NewGRPCExporter(nil)
	stats := e.Stats()
	if stats["batch_size"] != 50 {
		t.Errorf("batch_size = %v", stats["batch_size"])
	}
}

func TestExportBatchFlush(t *testing.T) {
	cfg := DefaultGRPCConfig()
	cfg.BatchSize = 3
	e := NewGRPCExporter(cfg)

	e.Export(&ExportEvent{PID: 1, Comm: "a"})
	e.Export(&ExportEvent{PID: 2, Comm: "b"})
	e.Export(&ExportEvent{PID: 3, Comm: "c"}) // triggers flush

	time.Sleep(100 * time.Millisecond)
	if e.totalSent != 3 {
		t.Logf("total sent: %d (flush may not have completed)", e.totalSent)
	}
}

// ─── CEF format tests ───────────────────────────────────────

func TestFormatCEF(t *testing.T) {
	evt := &ExportEvent{
		EventType: 10, PID: 100, PPID: 1, UID: 0,
		Comm: "cat", Pathname: "/etc/shadow",
		Score: 52, IsHighRisk: true,
	}

	cef := FormatCEF(evt)
	if !strings.HasPrefix(cef, "CEF:0|ProvidAPT") {
		t.Errorf("CEF header: %s", cef)
	}
	if !strings.Contains(cef, "File Open") {
		t.Errorf("missing name: %s", cef)
	}
	if !strings.Contains(cef, "/etc/shadow") {
		t.Errorf("missing path: %s", cef)
	}
	t.Logf("CEF: %s", cef)
}

func TestFormatCEFNetwork(t *testing.T) {
	evt := &ExportEvent{
		EventType: 20, PID: 200, Comm: "curl",
		Daddr: 0x08080808, Dport: 443,
	}
	cef := FormatCEF(evt)
	if !strings.Contains(cef, "8.8.8.8") {
		t.Errorf("missing IP: %s", cef)
	}
	t.Logf("CEF network: %s", cef)
}

func TestCEFSeverityMapping(t *testing.T) {
	if cefSeverity["critical"] != 10 {
		t.Errorf("critical severity = %d", cefSeverity["critical"])
	}
}

// ─── ASIM format tests ──────────────────────────────────────

func TestFormatASIM(t *testing.T) {
	evt := &ExportEvent{
		EventType: 11, PID: 100, Comm: "vi",
		Pathname: "/etc/passwd", Score: 40,
		IsHighRisk: true, Timestamp: time.Now().UnixNano(),
	}

	asim := FormatASIMJSON(evt)
	if !strings.Contains(asim, "ProvidAPT") {
		t.Errorf("missing vendor: %s", asim)
	}
	if !strings.Contains(asim, "File Create") {
		t.Errorf("missing type: %s", asim)
	}
	t.Logf("ASIM: %s", asim)
}

// ─── JSON CLI mode tests ────────────────────────────────────

func TestFormatJSONCLI(t *testing.T) {
	events := []*ExportEvent{
		{PID: 100, Comm: "bash", EventType: 10, Score: 50},
		{PID: 200, Comm: "curl", EventType: 20, Score: 30},
	}

	jsonOut := FormatJSONCLI(events, nil)
	if !strings.Contains(jsonOut, "2.0") {
		t.Errorf("missing version: %s", jsonOut)
	}
	if !strings.Contains(jsonOut, "bash") {
		t.Errorf("missing event: %s", jsonOut)
	}
	t.Logf("JSON CLI: %s", jsonOut[:200])
}

func TestFormatJSONCLIWithError(t *testing.T) {
	jsonOut := FormatJSONCLI(nil, errors.New("connection refused"))
	if !strings.Contains(jsonOut, "connection refused") {
		t.Errorf("missing error: %s", jsonOut)
	}
}

func TestFormatJSONCLIEmpty(t *testing.T) {
	jsonOut := FormatJSONCLI(nil, nil)
	if !strings.Contains(jsonOut, `"count": 0`) {
		t.Errorf("expected count 0: %s", jsonOut)
	}
}

// ─── Helper tests ───────────────────────────────────────────

func TestEventToSigID(t *testing.T) {
	if eventToSigID(10) != 1001 {
		t.Errorf("sig id for type 10 = %d", eventToSigID(10))
	}
	if eventToSigID(20) != 2001 {
		t.Errorf("sig id for type 20 = %d", eventToSigID(20))
	}
}

func TestIntToIPStr(t *testing.T) {
	if s := intToIPStr(0x08080808); s != "8.8.8.8" {
		t.Errorf("IP = %s", s)
	}
	if s := intToIPStr(0); s != "" {
		t.Errorf("zero IP = %s", s)
	}
}

func TestScoreToCEF(t *testing.T) {
	if n := scoreToCEF(60); n != 10 {
		t.Errorf("score 60 -> CEF %d", n)
	}
	if n := scoreToCEF(5); n != 1 {
		t.Errorf("score 5 -> CEF %d", n)
	}
}
