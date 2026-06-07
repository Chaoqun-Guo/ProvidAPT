// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package scoring

import (
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/plugin"
)

func TestScoringEmpty(t *testing.T) {
	engine := New()
	result := engine.Score(nil, provenance.NewGraph())
	if result.RiskLevel != "NONE" {
		t.Errorf("expected NONE, got %s", result.RiskLevel)
	}
}

func TestScoringSingleDimension(t *testing.T) {
	engine := New()
	findings := []*plugin.Finding{
		{Title: "Suspicious Network Connection", Score: 8, PluginName: "sigma"},
	}
	result := engine.Score(findings, provenance.NewGraph())
	if result.HitCount != 1 {
		t.Errorf("HitCount = %d, want 1", result.HitCount)
	}
	if result.Multiplier != 1.0 {
		t.Errorf("Multiplier = %.1f, want 1.0", result.Multiplier)
	}
}

func TestScoringMultiDimension(t *testing.T) {
	engine := New()
	findings := []*plugin.Finding{
		{Title: "Suspicious Network Connection", Score: 8, PluginName: "sigma"},
		{Title: "Suspicious Shadow File Access", Score: 8, PluginName: "sigma"},
		{Title: "Privilege Escalation via setuid", Score: 7, PluginName: "sigma"},
	}
	result := engine.Score(findings, provenance.NewGraph())
	t.Logf("Multi-dim score: total=%.1f, hits=%d, mult=%.1f, level=%s",
		result.TotalScore, result.HitCount, result.Multiplier, result.RiskLevel)

	if result.HitCount < 2 {
		t.Error("expected at least 2 dimension hits")
	}
	if result.Multiplier <= 1.0 {
		t.Error("expected multiplier > 1 for multiple dimensions")
	}
}

func TestScoringThresholds(t *testing.T) {
	engine := New()
	tests := []struct {
		score float64
		level string
	}{
		{3, "NONE"},
		{8, "LOW"},
		{18, "MEDIUM"},
		{28, "HIGH"},
		{45, "CRITICAL"},
	}
	for _, tt := range tests {
		got := engine.riskLevel(tt.score)
		if got != tt.level {
			t.Errorf("score %.0f: expected %s, got %s", tt.score, tt.level, got)
		}
	}
}

func TestScoringCeiling(t *testing.T) {
	engine := New()
	result := engine.Score([]*plugin.Finding{
		{Title: "C2 Connection", Score: 10, PluginName: "sigma"},
		{Title: "Sensitive Exfil", Score: 10, PluginName: "sigma"},
		{Title: "Privilege Escalation", Score: 10, PluginName: "sigma"},
		{Title: "Persistence via Cron", Score: 10, PluginName: "sigma"},
	}, provenance.NewGraph())
	if result.TotalScore > 100 {
		t.Errorf("score %.0f exceeds ceiling 100", result.TotalScore)
	}
	t.Logf("Ceiling test: score=%.1f, level=%s, dims=%v",
		result.TotalScore, result.RiskLevel, result.ActiveDims)
}
