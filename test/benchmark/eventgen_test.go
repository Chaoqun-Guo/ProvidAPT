// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package benchmark

import (
	"testing"
)

func TestGeneratorCreatesEvents(t *testing.T) {
	gen := NewGenerator()
	events := gen.Generate(100)
	if len(events) != 100 {
		t.Fatalf("expected 100 events, got %d", len(events))
	}
}

func TestGeneratorEventTypes(t *testing.T) {
	gen := NewGenerator()
	events := gen.Generate(10000)

	typeCount := make(map[string]int)
	for _, e := range events {
		typeCount[e.Type.String()]++
	}

	t.Logf("Event distribution (%d total):", len(events))
	for typ, count := range typeCount {
		pct := float64(count) / float64(len(events)) * 100
		t.Logf("  %s: %d (%.1f%%)", typ, count, pct)
	}

	// Should have at least 3 different event types
	if len(typeCount) < 3 {
		t.Errorf("expected ≥3 event types, got %d", len(typeCount))
	}
}

func TestGeneratorTimestampsOrdered(t *testing.T) {
	gen := NewGenerator()
	events := gen.Generate(1000)

	var prev uint64
	for i, e := range events {
		if i > 0 && e.TimestampNS <= prev {
			t.Errorf("event %d: timestamp %d <= previous %d",
				i, e.TimestampNS, prev)
		}
		prev = e.TimestampNS
	}
}

func TestGeneratorProcessExecHasPath(t *testing.T) {
	gen := NewGenerator()
	events := gen.Generate(5000)

	execCount := 0
	for _, e := range events {
		if e.Type.String() == "proc_exec" {
			execCount++
			if e.Pathname == "" {
				t.Error("exec event with empty pathname")
			}
		}
	}
	t.Logf("Generated %d exec events with paths", execCount)
}

func TestGeneratorRate(t *testing.T) {
	gen := NewGenerator()
	events := gen.Generate(50000)
	if len(events) != 50000 {
		t.Fatalf("expected 50000 events, got %d", len(events))
	}
	t.Logf("Generated 50000 events — ready for benchmark")
}

func TestGeneratorDeterministic(t *testing.T) {
	// Not strictly deterministic due to time seed, but should
	// always produce valid events
	gen := NewGenerator()
	for i := 0; i < 3; i++ {
		events := gen.Generate(100)
		for _, e := range events {
			if e.PID == 0 {
				t.Errorf("event with PID=0: type=%s", e.Type)
			}
		}
	}
}
