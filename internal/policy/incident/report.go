package incident

import (
	"fmt"
	"strings"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Context enrichment — natural language briefing
// ═══════════════════════════════════════════════════════════════

// IncidentReport is the enriched output for an incident.
type IncidentReport struct {
	IncidentID    string    `json:"incident_id"`
	GeneratedAt   time.Time `json:"generated_at"`
	RiskScore     float64   `json:"risk_score"`
	RiskLevel     string    `json:"risk_level"`
	AlertCount    int       `json:"alert_count"`

	EntryPoint    string    `json:"entry_point"`     // initial compromise
	FarthestPoint string    `json:"farthest_point"`  // deepest impact
	AttackChain   []string  `json:"attack_chain"`    // step-by-step

	Briefing      string    `json:"briefing"`        // natural language summary
	TTPs          []string  `json:"ttps,omitempty"`  // MITRE ATT&CK refs
}

// ReportGenerator creates context-enriched incident reports.
type ReportGenerator struct {
	config *ScoreConfig
}

// NewReportGenerator creates a report generator.
func NewReportGenerator() *ReportGenerator {
	return &ReportGenerator{config: DefaultScoreConfig()}
}

// Generate creates a full incident report from an incident and its alerts.
func (rg *ReportGenerator) Generate(inc *Incident, alerts []*AlertNode) *IncidentReport {
	report := &IncidentReport{
		IncidentID:  inc.ID,
		GeneratedAt: time.Now(),
		RiskScore:   inc.RiskScore,
		RiskLevel:   NewRiskScorer(rg.config).Classify(inc.RiskScore),
		AlertCount:  inc.TotalAlerts,
	}

	// Extract entry point (first process in the chain)
	for _, alert := range alerts {
		for _, aid := range inc.AlertIDs {
			if alert.ID == aid {
				if report.EntryPoint == "" {
					report.EntryPoint = fmt.Sprintf("%s (PID %d)", alert.Comm, alert.PID)
				}
				report.AttackChain = append(report.AttackChain,
					fmt.Sprintf("[%s] %s → %s (score=%.0f)",
						alert.Type, alert.Comm, alert.Target, alert.Score))
				// Track farthest point
				if alert.Score > 0 {
					if alert.Target != "" {
						report.FarthestPoint = alert.Target
					}
				}
				// Map TTPs
				if ttp := mapTTP(alert.Type); ttp != "" {
					report.TTPs = append(report.TTPs, ttp)
				}
			}
		}
	}

	// Generate natural language briefing
	report.Briefing = rg.generateBriefing(report)
	return report
}

// generateBriefing creates a natural language summary.
func (rg *ReportGenerator) generateBriefing(report *IncidentReport) string {
	parts := []string{
		fmt.Sprintf("Attack chain detected with risk score %.0f (%s).", report.RiskScore, report.RiskLevel),
	}

	if report.EntryPoint != "" {
		parts = append(parts, fmt.Sprintf("Entry point: %s.", report.EntryPoint))
	}
	if report.FarthestPoint != "" {
		parts = append(parts, fmt.Sprintf("Farthest impact: %s.", report.FarthestPoint))
	}

	if len(report.AttackChain) > 0 {
		parts = append(parts, "Attack path:")
		for i, step := range report.AttackChain {
			parts = append(parts, fmt.Sprintf("  Step %d: %s", i+1, step))
		}
	}

	if len(report.TTPs) > 0 {
		unique := uniqueStrings(report.TTPs)
		parts = append(parts, fmt.Sprintf("MITRE ATT&CK techniques: %s.", strings.Join(unique, ", ")))
	}

	return strings.Join(parts, "\n")
}

// mapTTP maps alert types to MITRE ATT&CK techniques.
func mapTTP(alertType string) string {
	switch {
	case strings.Contains(alertType, "taint") || strings.Contains(alertType, "net_connect"):
		return "T1043 (C2)"
	case strings.Contains(alertType, "memfd") || strings.Contains(alertType, "mprotect"):
		return "T1055 (Process Injection)"
	case strings.Contains(alertType, "write"):
		return "T1098 (Account Manipulation)"
	case strings.Contains(alertType, "shadow") || strings.Contains(alertType, "passwd"):
		return "T1003 (OS Credential Dumping)"
	case strings.Contains(alertType, "exec"):
		return "T1204 (User Execution)"
	default:
		return ""
	}
}

func uniqueStrings(s []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// FormatBriefing returns a concise one-line briefing.
func (ir *IncidentReport) FormatBriefing() string {
	return fmt.Sprintf("[%s] %s | Entry: %s | Impact: %s | %.0f pts",
		ir.RiskLevel, ir.IncidentID, ir.EntryPoint, ir.FarthestPoint, ir.RiskScore)
}
