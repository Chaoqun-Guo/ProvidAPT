// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package predict implements a prediction engine for ProvidAPT that
// helps security teams stay ahead of attackers.  It provides:
//
//  1. Intention prediction — match partial attack graphs against
//     MITRE ATT&CK chains to predict the attacker's next move.
//
//  2. Blast radius calculation — real-time assessment of all
//     assets reachable from a compromised process.
//
//  3. Automated defense recommendations — actionable remediation
//     suggestions based on the attack context.
package predict

import (
	"fmt"
	"strings"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ═══════════════════════════════════════════════════════════════
// MITRE ATT&CK chain definitions
// ═══════════════════════════════════════════════════════════════

// ATTACKPhase represents a phase in the attack lifecycle.
type ATTACKPhase struct {
	Phase         string `json:"phase"`          // "initial-access", "execution", etc.
	Technique     string `json:"technique"`      // T1190, T1059, etc.
	TechniqueName string `json:"technique_name"` // "Exploit Public-Facing Application"
	Signal        string `json:"signal"`         // provenance pattern to detect this
}

// ATTACKChain is a complete attack flow.
type ATTACKChain struct {
	Name   string        `json:"name"`
	Phases []ATTACKPhase `json:"phases"`
}

// KnownAttacks returns the known ATT&CK attack chains.
func KnownAttacks() []ATTACKChain {
	return []ATTACKChain{
		{
			Name: "Web Shell Exploitation",
			Phases: []ATTACKPhase{
				{Phase: "initial-access", Technique: "T1190", TechniqueName: "Exploit Public-Facing Application", Signal: "nginx|apache|httpd"},
				{Phase: "execution", Technique: "T1059", TechniqueName: "Command and Scripting Interpreter", Signal: "bash|sh|exec"},
				{Phase: "persistence", Technique: "T1505", TechniqueName: "Server Software Component", Signal: "write|file_create"},
				{Phase: "privilege-escalation", Technique: "T1548", TechniqueName: "Abuse Elevation Control Mechanism", Signal: "sudo|setuid"},
				{Phase: "credential-access", Technique: "T1003", TechniqueName: "OS Credential Dumping", Signal: "shadow|passwd"},
				{Phase: "exfiltration", Technique: "T1048", TechniqueName: "Exfiltration Over Alternative Protocol", Signal: "connect|net"},
			},
		},
		{
			Name: "Living Off the Land",
			Phases: []ATTACKPhase{
				{Phase: "execution", Technique: "T1059", TechniqueName: "Command and Scripting Interpreter", Signal: "bash|sh|powershell"},
				{Phase: "defense-evasion", Technique: "T1218", TechniqueName: "Signed Binary Proxy Execution", Signal: "curl|wget|certutil"},
				{Phase: "execution", Technique: "T1204", TechniqueName: "User Execution", Signal: "exec|file_create"},
				{Phase: "exfiltration", Technique: "T1041", TechniqueName: "Exfiltration Over C2 Channel", Signal: "connect"},
			},
		},
		{
			Name: "Ransomware Deployment",
			Phases: []ATTACKPhase{
				{Phase: "execution", Technique: "T1204", TechniqueName: "User Execution", Signal: "exec"},
				{Phase: "impact", Technique: "T1486", TechniqueName: "Data Encrypted for Impact", Signal: "write|file_modify"},
				{Phase: "impact", Technique: "T1490", TechniqueName: "Inhibit System Recovery", Signal: "shadow|delete"},
			},
		},
		{
			Name: "SSH Lateral Movement",
			Phases: []ATTACKPhase{
				{Phase: "credential-access", Technique: "T1552", TechniqueName: "Unsecured Credentials", Signal: "shadow|ssh|key"},
				{Phase: "lateral-movement", Technique: "T1021", TechniqueName: "Remote Services", Signal: "ssh|scp|connect:22"},
				{Phase: "execution", Technique: "T1059", TechniqueName: "Command and Scripting Interpreter", Signal: "bash|exec"},
			},
		},
	}
}

// ═══════════════════════════════════════════════════════════════
// Intention prediction
// ═══════════════════════════════════════════════════════════════

// PredictionResult describes the predicted next steps.
type PredictionResult struct {
	MatchedChain    string   `json:"matched_chain"`
	CurrentPhase    string   `json:"current_phase"`
	CompletedPhases []string `json:"completed_phases"`
	NextPhases      []string `json:"next_phases"`
	Confidence      float64  `json:"confidence"`
}

// Predictor matches attack subgraphs against ATT&CK chains.
type Predictor struct {
	chains []ATTACKChain
}

// NewPredictor creates an ATT&CK-based predictor.
func NewPredictor() *Predictor {
	return &Predictor{
		chains: KnownAttacks(),
	}
}

// Predict matches the current graph state against known attack chains
// and predicts the attacker's next likely steps.
func (p *Predictor) Predict(graph *provenance.Graph, startNodeID string) []*PredictionResult {
	var results []*PredictionResult

	currentSignals := p.extractSignals(graph, startNodeID)

	for _, chain := range p.chains {
		result := p.matchChain(chain, currentSignals)
		if result != nil {
			results = append(results, result)
		}
	}

	return results
}

// extractSignals extracts attack signals from the graph around a node.
func (p *Predictor) extractSignals(graph *provenance.Graph, startNodeID string) []string {
	signals := make(map[string]bool)

	// Walk all edges from the start node
	for _, e := range graph.Edges() {
		if e.Source != startNodeID && e.Target != startNodeID {
			continue
		}
		src, _ := graph.LookupNode(e.Source)
		if src != nil {
			for _, signal := range extractSignalsFromNode(src) {
				signals[signal] = true
			}
		}
		dst, _ := graph.LookupNode(e.Target)
		if dst != nil {
			for _, signal := range extractSignalsFromNode(dst) {
				signals[signal] = true
			}
		}
	}

	var result []string
	for s := range signals {
		result = append(result, s)
	}
	return result
}

// extractSignalsFromNode extracts attack signals from a single node.
func extractSignalsFromNode(n *provenance.Node) []string {
	var signals []string
	label := strings.ToLower(n.Label)

	// Process-based signals
	switch n.Subtype {
	case "process":
		if strings.Contains(label, "bash") || strings.Contains(label, "sh") {
			signals = append(signals, "bash|sh|exec")
		}
		if strings.Contains(label, "curl") || strings.Contains(label, "wget") {
			signals = append(signals, "curl|wget")
		}
		if strings.Contains(label, "sudo") {
			signals = append(signals, "sudo|setuid")
		}
		if strings.Contains(label, "ssh") || strings.Contains(label, "scp") {
			signals = append(signals, "ssh|scp|connect:22")
		}
		if strings.Contains(label, "nginx") || strings.Contains(label, "apache") || strings.Contains(label, "httpd") {
			signals = append(signals, "nginx|apache|httpd")
		}
		if v, ok := n.Attributes["fileless"]; ok && v.(bool) {
			signals = append(signals, "exec")
		}
		if v, ok := n.Attributes["setuid"]; ok && v.(bool) {
			signals = append(signals, "sudo|setuid")
		}

	case "file":
		if strings.Contains(label, "shadow") || strings.Contains(label, "passwd") {
			signals = append(signals, "shadow|passwd")
		}
		if strings.Contains(label, "ssh") || strings.Contains(label, "key") {
			signals = append(signals, "ssh|key")
		}
		if strings.Contains(label, "delete") {
			signals = append(signals, "shadow|delete")
		}

	case "network":
		if strings.Contains(label, "22") {
			signals = append(signals, "ssh|scp|connect:22")
		}
		signals = append(signals, "connect")
	}

	return signals
}

// matchChain checks how many phases of a chain match current signals.
func (p *Predictor) matchChain(chain ATTACKChain, signals []string) *PredictionResult {
	signalSet := make(map[string]bool)
	for _, s := range signals {
		signalSet[s] = true
	}

	completed := 0
	var completedPhases []string
	var nextPhases []string

	for _, phase := range chain.Phases {
		// Check if any signal matches this phase
		matched := false
		for _, signal := range strings.Split(phase.Signal, ",") {
			if signalSet[signal] {
				matched = true
				break
			}
		}
		if matched {
			completed++
			completedPhases = append(completedPhases, phase.Phase+":"+phase.TechniqueName)
		} else if completed > 0 || len(nextPhases) == 0 {
			// Only suggest next phases if at least one phase is completed
			nextPhases = append(nextPhases, phase.Phase+":"+phase.Technique+" "+phase.TechniqueName)
		}
	}

	if completed == 0 {
		return nil
	}

	currentPhase := chain.Phases[completed-1].Phase
	confidence := float64(completed) / float64(len(chain.Phases))

	return &PredictionResult{
		MatchedChain:    chain.Name,
		CurrentPhase:    currentPhase,
		CompletedPhases: completedPhases,
		NextPhases:      nextPhases,
		Confidence:      confidence,
	}
}

// Summary returns a human-readable prediction summary.
func (pr *PredictionResult) Summary() string {
	if pr == nil {
		return "No prediction"
	}
	return fmt.Sprintf("[%s] Phase: %s (confidence %.0f%%) | Next: %s",
		pr.MatchedChain, pr.CurrentPhase, pr.Confidence*100,
		strings.Join(pr.NextPhases, ", "))
}
