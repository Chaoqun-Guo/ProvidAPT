// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package scoring implements a multi-dimensional risk scoring system
// for provenance subgraphs.  Each suspicious node contributes to one
// or more scoring dimensions; the combined score determines the
// overall risk level and whether an alert should be escalated.
//
// Dimensions (inspired by ATT&CK):
//
//   C2              — network callback / beaconing
//   SENSITIVE_FILE  — access to /etc/shadow, /root/* etc.
//   PRIV_ESC        — setuid / credential change
//   PERSISTENCE     — cron, rc.d, systemd unit writes
//   LATERAL_MOVE    — SSH, scp, remote copy
//   INJECTION       — ptrace, /proc/*/mem access
//
// Each dimension has a base weight.  When multiple dimensions hit
// the same subgraph, the score compounds non-linearly:
//
//   combined = sum(weights) * multiplier(count)
//   where multiplier = 1 + 0.5 * (count - 1)   for count > 1
package scoring

import (
	"fmt"
	"math"
	"strings"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/plugin"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ═══════════════════════════════════════════════════════════════
// Dimensions
// ═══════════════════════════════════════════════════════════════

// Dimension represents a risk category.
type Dimension struct {
	ID     string  // unique identifier
	Name   string  // human-readable
	Weight float64 // base score contribution
}

var (
	DimC2            = Dimension{"c2", "Network Callback / C2", 8}
	DimSensitiveFile = Dimension{"sensitive_file", "Sensitive File Access", 6}
	DimPrivEsc       = Dimension{"priv_esc", "Privilege Escalation", 7}
	DimPersistence   = Dimension{"persistence", "Persistence Mechanism", 5}
	DimLateralMove   = Dimension{"lateral_move", "Lateral Movement", 6}
	DimInjection     = Dimension{"injection", "Process Injection", 8}
	DimExfiltration  = Dimension{"exfiltration", "Data Exfiltration", 9}
)

// AllDimensions returns the full dimension set.
func AllDimensions() []Dimension {
	return []Dimension{DimC2, DimSensitiveFile, DimPrivEsc, DimPersistence, DimLateralMove, DimInjection, DimExfiltration}
}

// ─── Hit ────────────────────────────────────────────────────

// Hit records that a dimension was triggered by a specific finding.
type Hit struct {
	Dimension Dimension
	Finding   *plugin.Finding
	NodeIDs   []string
}

// ScoreResult is the output of the scoring engine.
type ScoreResult struct {
	TotalScore    float64            `json:"total_score"`
	RiskLevel     string             `json:"risk_level"` // NONE, LOW, MEDIUM, HIGH, CRITICAL
	ActiveDims    map[string]float64 `json:"active_dimensions"`
	HitCount      int                `json:"hit_count"`
	CombinedScore float64            `json:"combined_score"`
	Multiplier    float64            `json:"multiplier"`
}

// ═══════════════════════════════════════════════════════════════
// ScoringEngine
// ═══════════════════════════════════════════════════════════════

// ScoringEngine evaluates findings against scoring dimensions.
type ScoringEngine struct {
	// thresholds for risk levels
	thresholdLow      float64
	thresholdMedium   float64
	thresholdHigh     float64
	thresholdCritical float64
}

// New creates a scoring engine with default thresholds.
func New() *ScoringEngine {
	return &ScoringEngine{
		thresholdLow:      5,
		thresholdMedium:   15,
		thresholdHigh:     25,
		thresholdCritical: 40,
	}
}

// ── Scoring logic ───────────────────────────────────────────

// Score evaluates a set of findings and returns a ScoreResult.
func (se *ScoringEngine) Score(findings []*plugin.Finding, snap *provenance.Graph) *ScoreResult {
	if len(findings) == 0 {
		return &ScoreResult{RiskLevel: "NONE"}
	}

	// Map findings to dimensions
	dims := make(map[string]float64)
	hitCount := 0

	for _, f := range findings {
		for _, dim := range se.matchDimensions(f, snap) {
			existing := dims[dim.ID]
			// Take the highest score for each dimension
			newScore := f.Score * (dim.Weight / 10.0)
			if newScore > existing {
				dims[dim.ID] = newScore
			}
		}
	}

	// Calculate combined score
	var sum float64
	for _, s := range dims {
		sum += s
		hitCount++
	}

	// Non-linear multiplier for multiple dimensions (compounding risk)
	multiplier := 1.0
	if hitCount > 1 {
		multiplier = 1 + 0.5*float64(hitCount-1)
	}
	combined := sum * multiplier

	// Apply a ceiling (max 100)
	if combined > 100 {
		combined = 100
	}

	// Round to 1 decimal
	combined = math.Round(combined*10) / 10

	return &ScoreResult{
		TotalScore:    combined,
		RiskLevel:     se.riskLevel(combined),
		ActiveDims:    dims,
		HitCount:      hitCount,
		CombinedScore: sum,
		Multiplier:    multiplier,
	}
}

// matchDimensions determines which scoring dimensions a finding hits.
func (se *ScoringEngine) matchDimensions(f *plugin.Finding, snap *provenance.Graph) []Dimension {
	var dims []Dimension
	title := strings.ToLower(f.Title)
	pluginName := strings.ToLower(f.PluginName)

	// C2 / network callback
	if strings.Contains(title, "network") || strings.Contains(title, "c2") ||
		strings.Contains(title, "callback") || strings.Contains(title, "beacon") ||
		pluginName == "threatintel" {
		dims = append(dims, DimC2)
	}

	// Sensitive file access
	if strings.Contains(title, "shadow") || strings.Contains(title, "passwd") ||
		strings.Contains(title, "credential") || strings.Contains(title, "exfil") {
		dims = append(dims, DimSensitiveFile)
		if strings.Contains(title, "exfil") {
			dims = append(dims, DimExfiltration)
		}
	}

	// Privilege escalation
	if strings.Contains(title, "setuid") || strings.Contains(title, "privilege") ||
		strings.Contains(title, "sudo") || strings.Contains(title, "escalation") {
		dims = append(dims, DimPrivEsc)
	}

	// Persistence
	if strings.Contains(title, "cron") || strings.Contains(title, "persist") ||
		strings.Contains(title, "systemd") || strings.Contains(title, "rc.d") ||
		strings.Contains(title, "autorun") {
		dims = append(dims, DimPersistence)
	}

	// Lateral movement
	if strings.Contains(title, "ssh") || strings.Contains(title, "scp") ||
		strings.Contains(title, "lateral") || strings.Contains(title, "rdp") {
		dims = append(dims, DimLateralMove)
	}

	// Injection
	if strings.Contains(title, "inject") || strings.Contains(title, "ptrace") ||
		strings.Contains(title, "mprotect") || strings.Contains(title, "shellcode") {
		dims = append(dims, DimInjection)
	}

	// Check node attributes for additional signals
	for _, nid := range f.NodeIDs {
		n, ok := snap.LookupNode(nid)
		if !ok || n == nil {
			continue
		}
		if n.Subtype == "credential" {
			dims = append(dims, DimPrivEsc)
		}
		if v, ok := n.Attributes["setuid"]; ok {
			if b, _ := v.(bool); b {
				dims = append(dims, DimPrivEsc)
			}
		}
	}

	return uniqueDims(dims)
}

// riskLevel maps a score to a human-readable level.
func (se *ScoringEngine) riskLevel(score float64) string {
	switch {
	case score >= se.thresholdCritical:
		return "CRITICAL"
	case score >= se.thresholdHigh:
		return "HIGH"
	case score >= se.thresholdMedium:
		return "MEDIUM"
	case score >= se.thresholdLow:
		return "LOW"
	default:
		return "NONE"
	}
}

// ═══════════════════════════════════════════════════════════════
// ScoringPlugin
// ═══════════════════════════════════════════════════════════════

// ScoringPlugin wraps the scoring engine as an analysis plugin.
type ScoringPlugin struct {
	Name_    string
	Engine   *ScoringEngine
	Children []plugin.Plugin // sub-plugins whose findings feed the scorer
}

func (p *ScoringPlugin) Name() string { return p.Name_ }

func (p *ScoringPlugin) Analyse(snap *provenance.Graph) []*plugin.Finding {
	// Collect findings from sub-plugins
	var allFindings []*plugin.Finding
	for _, child := range p.Children {
		allFindings = append(allFindings, child.Analyse(snap)...)
	}

	// Score them
	result := p.Engine.Score(allFindings, snap)

	if result.HitCount == 0 {
		return nil
	}

	// If multiple dimensions hit, escalate
	if result.HitCount >= 2 && result.TotalScore >= p.Engine.thresholdMedium {
		return []*plugin.Finding{
			{
				PluginName: p.Name_,
				Title:      fmt.Sprintf("Multi-dimensional attack: %d signals (score=%.1f, level=%s)",
					result.HitCount, result.TotalScore, result.RiskLevel),
				Severity: result.RiskLevel,
				Score:    result.TotalScore,
				Evidence: map[string]interface{}{
					"active_dimensions": result.ActiveDims,
					"hit_count":         result.HitCount,
					"multiplier":        result.Multiplier,
					"base_score":        result.CombinedScore,
				},
			},
		}
	}

	return nil
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

func uniqueDims(dims []Dimension) []Dimension {
	seen := make(map[string]bool)
	var out []Dimension
	for _, d := range dims {
		if !seen[d.ID] {
			seen[d.ID] = true
			out = append(out, d)
		}
	}
	return out
}

// Ensure the variable `se` is accessible (package-level conflict fix)
var se = New()
