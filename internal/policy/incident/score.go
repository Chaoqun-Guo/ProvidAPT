package incident

import (
	"math"
	"strings"
)

// ═══════════════════════════════════════════════════════════════
// Risk scoring — topology-based scoring engine
// ═══════════════════════════════════════════════════════════════

// ScoreConfig controls scoring parameters.
type ScoreConfig struct {
	// Base scores per event type
	ExecScore      float64
	FileWriteScore float64
	NetConnectScore float64
	MemfdScore     float64
	MprotectScore  float64

	// Multipliers
	SensitivePathMultiplier float64 // ×2 for /etc/shadow etc.
	TaintMultiplier         float64 // ×1.5 for tainted source
	PathLengthMultiplier    float64 // ×0.1 per hop

	// Thresholds
	MediumThreshold float64
	HighThreshold   float64
	CriticalThreshold float64
}

// DefaultScoreConfig returns default scoring parameters.
func DefaultScoreConfig() *ScoreConfig {
	return &ScoreConfig{
		ExecScore:      20,
		FileWriteScore: 10,
		NetConnectScore: 15,
		MemfdScore:     60,
		MprotectScore:  100,

		SensitivePathMultiplier: 2.0,
		TaintMultiplier:         1.5,
		PathLengthMultiplier:    0.1,

		MediumThreshold:   30,
		HighThreshold:     70,
		CriticalThreshold: 120,
	}
}

// RiskScorer computes risk scores based on graph topology.
type RiskScorer struct {
	cfg *ScoreConfig
}

// NewRiskScorer creates a risk scorer.
func NewRiskScorer(cfg *ScoreConfig) *RiskScorer {
	if cfg == nil {
		cfg = DefaultScoreConfig()
	}
	return &RiskScorer{cfg: cfg}
}

// ScoreAlert computes the risk score for a single alert.
func (rs *RiskScorer) ScoreAlert(alertType, target, comm string, isTainted bool, pathLength int) float64 {
	score := 0.0

	// Base score by alert type
	switch {
	case strings.Contains(alertType, "mprotect") || strings.Contains(alertType, "shellcode"):
		score = rs.cfg.MprotectScore
	case strings.Contains(alertType, "memfd"):
		score = rs.cfg.MemfdScore
	case strings.Contains(alertType, "exec"):
		score = rs.cfg.ExecScore
	case strings.Contains(alertType, "write") || strings.Contains(alertType, "file"):
		score = rs.cfg.FileWriteScore
	case strings.Contains(alertType, "net") || strings.Contains(alertType, "connect"):
		score = rs.cfg.NetConnectScore
	default:
		score = 5.0
	}

	// Sensitive path multiplier
	for _, sensitive := range []string{"/etc/shadow", "/etc/passwd", "/etc/sudoers",
		"/root/.ssh", "/.aws/credentials"} {
		if strings.Contains(target, sensitive) {
			score *= rs.cfg.SensitivePathMultiplier
			break
		}
	}

	// Taint multiplier
	if isTainted {
		score *= rs.cfg.TaintMultiplier
	}

	// Path length bonus (longer chains = higher confidence)
	if pathLength > 1 {
		score += float64(pathLength) * rs.cfg.PathLengthMultiplier * score
	}

	return math.Round(score*10) / 10
}

// Classify returns the severity level for a score.
func (rs *RiskScorer) Classify(score float64) string {
	switch {
	case score >= rs.cfg.CriticalThreshold:
		return "CRITICAL"
	case score >= rs.cfg.HighThreshold:
		return "HIGH"
	case score >= rs.cfg.MediumThreshold:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
