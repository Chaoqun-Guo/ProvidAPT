// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package predict

import (
	"fmt"
	"strings"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ═══════════════════════════════════════════════════════════════
// Automated defense recommendations
// ═══════════════════════════════════════════════════════════════

// DefenseRecommendation is a single actionable remediation suggestion.
type DefenseRecommendation struct {
	Priority   string `json:"priority"`   // IMMEDIATE, HIGH, MEDIUM, LOW
	Action     string `json:"action"`     // contain, eradicate, recover, prevent
	Target     string `json:"target"`     // what to act on (PID, file, IP)
	Suggestion string `json:"suggestion"` // what to do
	Rationale  string `json:"rationale"`  // why this is needed
}

// DefenseEngine generates automated remediation suggestions.
type DefenseEngine struct {
	predictor  *Predictor
	calculator *BlastCalculator
}

// NewDefenseEngine creates a defense recommendation engine.
func NewDefenseEngine() *DefenseEngine {
	return &DefenseEngine{
		predictor:  NewPredictor(),
		calculator: NewBlastCalculator(),
	}
}

// Recommend generates defense recommendations based on the current attack
// context, predicted next steps, and blast radius.
func (de *DefenseEngine) Recommend(
	graph *provenance.Graph, startNodeID string, comm string, pid uint32,
) []*DefenseRecommendation {
	var recs []*DefenseRecommendation

	// 1. Immediate containment based on process type
	recs = append(recs, de.containmentRecs(startNodeID, comm, pid)...)

	// 2. Predict next steps
	predictions := de.predictor.Predict(graph, startNodeID)
	for _, pred := range predictions {
		recs = append(recs, de.predictionRecs(pred)...)
	}

	// 3. Blast radius mitigations
	blast := de.calculator.Calculate(graph, startNodeID)
	recs = append(recs, de.blastRecs(blast)...)

	// Remove duplicates by suggestion text
	return dedupRecs(recs)
}

// containmentRecs generates immediate containment recommendations.
func (de *DefenseEngine) containmentRecs(nodeID, comm string, pid uint32) []*DefenseRecommendation {
	var recs []*DefenseRecommendation

	lower := strings.ToLower(comm)

	// Network tool — block immediately
	if strings.Contains(lower, "curl") || strings.Contains(lower, "wget") ||
		strings.Contains(lower, "nc") || strings.Contains(lower, "ncat") {
		recs = append(recs, &DefenseRecommendation{
			Priority: "IMMEDIATE", Action: "contain",
			Target:     fmt.Sprintf("PID %d", pid),
			Suggestion: fmt.Sprintf("Immediately terminate PID %d (%s) and block its outbound connections", pid, comm),
			Rationale:  "Network-capable process in suspicious context — likely C2 or exfiltration",
		})
	}

	// Shell spawned from non-interactive context
	if strings.Contains(lower, "bash") || strings.Contains(lower, "sh") {
		recs = append(recs, &DefenseRecommendation{
			Priority: "HIGH", Action: "contain",
			Target:     fmt.Sprintf("PID %d", pid),
			Suggestion: fmt.Sprintf("Investigate shell process PID %d — determine if it was legitimately invoked", pid),
			Rationale:  "Interactive shell in automated/service context may indicate backdoor access",
		})
	}

	return recs
}

// predictionRecs generates recommendations based on predicted attack path.
func (de *DefenseEngine) predictionRecs(pred *PredictionResult) []*DefenseRecommendation {
	var recs []*DefenseRecommendation

	for _, next := range pred.NextPhases {
		switch {
		case strings.Contains(next, "credential-access") || strings.Contains(next, "T1003"):
			recs = append(recs, &DefenseRecommendation{
				Priority: "HIGH", Action: "prevent",
				Target:     "/etc/shadow and /etc/passwd",
				Suggestion: "Restrict read access to /etc/shadow using appropriate permissions and auditd rules",
				Rationale:  "Predictor indicates credential dumping is the likely next step",
			})
		case strings.Contains(next, "lateral-movement") || strings.Contains(next, "T1021"):
			recs = append(recs, &DefenseRecommendation{
				Priority: "IMMEDIATE", Action: "contain",
				Target:     "SSH service",
				Suggestion: "Temporarily restrict SSH access from this host using iptables/nftables",
				Rationale:  "Predictor indicates lateral movement via SSH is imminent",
			})
		case strings.Contains(next, "persistence") || strings.Contains(next, "T1505"):
			recs = append(recs, &DefenseRecommendation{
				Priority: "HIGH", Action: "detect",
				Target:     "System binaries and startup scripts",
				Suggestion: "Audit recent modifications to system binaries and startup scripts",
				Rationale:  "Predictor indicates persistence mechanism installation",
			})
		}
	}

	return recs
}

// blastRecs generates recommendations based on blast radius.
func (de *DefenseEngine) blastRecs(blast *BlastRadius) []*DefenseRecommendation {
	var recs []*DefenseRecommendation

	// Check for critical assets in blast radius
	for _, f := range blast.Files {
		if f.Critical {
			recs = append(recs, &DefenseRecommendation{
				Priority: "CRITICAL", Action: "contain",
				Target:     f.Label,
				Suggestion: fmt.Sprintf("Isolate container/host — K8s secrets at risk via %s", f.Label),
				Rationale:  "Critical credential/config file within blast radius",
			})
		}
	}

	// Network endpoints in blast radius
	if len(blast.NetworkEndpoints) > 0 {
		recs = append(recs, &DefenseRecommendation{
			Priority: "HIGH", Action: "contain",
			Target: "Outbound connections",
			Suggestion: fmt.Sprintf("Block outbound connections from compromised process (%s)",
				blast.CompromisedComm),
			Rationale: fmt.Sprintf("%d network endpoints reachable within blast radius",
				len(blast.NetworkEndpoints)),
		})
	}

	return recs
}

func dedupRecs(recs []*DefenseRecommendation) []*DefenseRecommendation {
	seen := make(map[string]bool)
	var out []*DefenseRecommendation
	for _, r := range recs {
		if !seen[r.Suggestion] {
			seen[r.Suggestion] = true
			out = append(out, r)
		}
	}
	return out
}

// Summary returns a formatted list of recommendations.
func FormatRecommendations(recs []*DefenseRecommendation) string {
	if len(recs) == 0 {
		return "No specific recommendations at this time."
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Defense Recommendations (%d actions):\n", len(recs)))
	for _, r := range recs {
		b.WriteString(fmt.Sprintf("  [%s] [%s] %s\n", r.Priority, r.Action, r.Suggestion))
		b.WriteString(fmt.Sprintf("         Target: %s\n", r.Target))
		b.WriteString(fmt.Sprintf("         Why: %s\n\n", r.Rationale))
	}
	return b.String()
}
