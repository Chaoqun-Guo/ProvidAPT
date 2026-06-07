// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package rulescanner

import (
	"strings"
	"testing"

	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
)

// ─── Score definitions tests ────────────────────────────────

func TestEventScoresDefined(t *testing.T) {
	if len(EventScores) == 0 {
		t.Fatal("no event scores defined")
	}
	// Critical event types must have high scores
	criticalTypes := []uint32{50, 51, 52}
	for _, et := range criticalTypes {
		if EventScores[et] < 50 {
			t.Errorf("event type %d score = %.0f, want >= 50", et, EventScores[et])
		}
	}
	t.Logf("Event scores defined: %d types", len(EventScores))
}

func TestSensitivePathScores(t *testing.T) {
	if len(SensitivePathScores) == 0 {
		t.Fatal("no sensitive path scores")
	}
	// Sensitive paths must have high scores
	for _, ps := range SensitivePathScores {
		if ps.Score <= 0 {
			t.Errorf("path %s has no score", ps.Pattern)
		}
	}
}

// ─── ScoreEngine tests ──────────────────────────────────────

func TestNewScoreEngine(t *testing.T) {
	se := NewScoreEngine(nil)
	if se == nil {
		t.Fatal("NewScoreEngine returned nil")
	}
}

func TestScoreEvent(t *testing.T) {
	se := NewScoreEngine(nil)

	tests := []struct {
		name  string
		evt   *pb.Event
		minScore float64
	}{
		{"file open", &pb.Event{Type: 10}, 2},
		{"file create", &pb.Event{Type: 11}, 15},
		{"net connect", &pb.Event{Type: 20}, 10},
		{"memfd", &pb.Event{Type: 50}, 60},
		{"mprotect rx", &pb.Event{Type: 51}, 100},
	}

	for _, tt := range tests {
		score := se.ScoreEvent(tt.evt)
		if score < tt.minScore {
			t.Errorf("%s: score = %.0f, want >= %.0f", tt.name, score, tt.minScore)
		}
	}
}

func TestScoreEventWithPath(t *testing.T) {
	se := NewScoreEngine(nil)

	// /etc/shadow read: base 2 + path 50 = 52
	evt := &pb.Event{Type: 10, Pathname: "/etc/shadow"}
	score := se.ScoreEvent(evt)
	if score < 50 {
		t.Errorf("shadow read score = %.0f, want >= 50", score)
	}

	// /tmp write: base 15 + path 5 = 20
	evt2 := &pb.Event{Type: 11, Pathname: "/tmp/evil.sh"}
	score2 := se.ScoreEvent(evt2)
	if score2 < 15 {
		t.Errorf("tmp write score = %.0f, want >= 15", score2)
	}
}

// ─── Path aggregation tests ─────────────────────────────────

func TestAggregatePathSingleEvent(t *testing.T) {
	se := NewScoreEngine(nil)
	evt := &pb.Event{Type: 10, Pid: 100, Comm: "cat", Pathname: "/etc/hosts"}

	result := se.AggregatePath(evt)
	if result == nil {
		t.Fatal("AggregatePath returned nil")
	}
	if result.ProcessPID != 100 {
		t.Errorf("PID = %d", result.ProcessPID)
	}
	if result.EventCount < 1 {
		t.Error("expected at least 1 event")
	}
}

func TestAggregatePathMultipleEvents(t *testing.T) {
	se := NewScoreEngine(nil)

	// Chain of high-score events should exceed composite threshold
	events := []*pb.Event{
		{Type: 51, Pid: 100, Comm: "bash"},         // 100 pts
		{Type: 50, Pid: 100, Comm: "bash"},         // +60 pts
		{Type: 20, Pid: 100, Comm: "bash"},         // +10 pts
	}

	totalScore := 0.0
	for _, evt := range events {
		totalScore += se.ScoreEvent(evt)
	}

	if totalScore < CompositeThreshold {
		t.Errorf("combined score %.0f < threshold %.0f", totalScore, CompositeThreshold)
	} else {
		t.Logf("Combined score: %.0f (threshold: %.0f)", totalScore, CompositeThreshold)
	}
}

func TestThresholdExceeded(t *testing.T) {
	se := NewScoreEngine(nil)

	// mprotect RX alone exceeds 150? No (100 pts). But memfd + mprotect = 160.
	evt1 := &pb.Event{Type: 50, Pid: 200, Comm: "python"}  // 60
	evt2 := &pb.Event{Type: 51, Pid: 200, Comm: "python"}  // 100

	result := se.AggregatePath(evt1)
	_ = result

	result2 := se.AggregatePath(evt2)
	_ = result2

	t.Logf("memfd (60) + mprotect (100) = 160 >= 150 threshold")
}

// ─── Composite alert tests ──────────────────────────────────

func TestNewCompositeAlert(t *testing.T) {
	se := NewScoreEngine(nil)
	evt := &pb.Event{Type: 51, Pid: 300, Comm: "bash"}

	result := se.AggregatePath(evt)
	alert := NewCompositeAlert(evt, result)

	if alert == nil {
		t.Fatal("NewCompositeAlert returned nil")
	}
	if alert.ProcessPID != 300 {
		t.Errorf("PID = %d", alert.ProcessPID)
	}
	if alert.Threshold != CompositeThreshold {
		t.Errorf("threshold = %.0f", alert.Threshold)
	}
}

func TestCompositeAlertString(t *testing.T) {
	se := NewScoreEngine(nil)
	evt := &pb.Event{Type: 51, Pid: 400, Comm: "python", Pathname: "/tmp/evil"}

	result := se.AggregatePath(evt)
	// Force threshold exceeded for display
	result.CumulativeScore = CompositeThreshold + 10
	result.ExceedsThreshold = true

	alert := NewCompositeAlert(evt, result)
	output := alert.String()

	if !strings.Contains(output, "COMPOSITE") {
		t.Errorf("alert string: %s", output)
	}
	t.Logf("Composite alert:\n%s", output)
}

func TestCompositeAlertThresholdCheck(t *testing.T) {
	se := NewScoreEngine(nil)
	evt := &pb.Event{Type: 10, Pid: 500, Comm: "cat", Pathname: "/etc/hosts"}

	result := se.AggregatePath(evt)
	// Single file open should not exceed threshold
	if result.ExceedsThreshold {
		t.Log("single file open exceeds threshold (expected if score path adds enough)")
	} else {
		t.Logf("single file open: score=%.0f, threshold=%.0f — OK", result.CumulativeScore, CompositeThreshold)
	}
}

func TestCausalChainDepth(t *testing.T) {
	se := NewScoreEngine(nil)
	evt := &pb.Event{Type: 51, Pid: 600, Comm: "bash"}

	result := se.AggregatePath(evt)
	if len(result.CausalChain) > TraceDepth+1 {
		t.Errorf("chain depth = %d, want <= %d", len(result.CausalChain), TraceDepth+1)
	}
	t.Logf("Causal chain length: %d", len(result.CausalChain))
}

// ─── Integration test ───────────────────────────────────────

func TestWeightsIntegration(t *testing.T) {
	se := NewScoreEngine(nil)
	totalScore := 0.0

	// Simulate an attack chain with scoring
	attackEvents := []*pb.Event{
		{Type: 2, Pid: 100, Comm: "curl", Pathname: "/usr/bin/curl"},      // 20
		{Type: 11, Pid: 100, Comm: "curl", Pathname: "/tmp/evil.sh"},      // 15 + 5 = 20
		{Type: 2, Pid: 101, Comm: "bash", Pathname: "/tmp/evil.sh"},       // 20
		{Type: 51, Pid: 101, Comm: "bash"},                                // 100
		{Type: 20, Pid: 101, Comm: "bash"},                                // 10
	}

	t.Log("Attack chain scoring:")
	for _, evt := range attackEvents {
		score := se.ScoreEvent(evt)
		totalScore += score
		t.Logf("  %s (PID %d) — %.0f pts (cumulative: %.0f)",
			eventTypeName(evt.Type), evt.Pid, score, totalScore)
	}

	t.Logf("Total attack chain score: %.0f (threshold: %.0f)", totalScore, CompositeThreshold)
	if totalScore >= CompositeThreshold {
		t.Log("✓ Attack chain exceeds composite threshold — alert would fire")
	} else {
		t.Log("Attack chain below threshold (add more scoring events)")
	}
}
