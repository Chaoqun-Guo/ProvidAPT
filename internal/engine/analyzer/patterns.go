// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"fmt"
	"strings"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ═══════════════════════════════════════════════════════════════
// APT anomaly patterns — checked after taint propagation
//
// Each pattern is inspired by academic provenance-based detectors:
//
//   HOLMES (CCS'17)    — Maps low-level events to high-level TTPs
//   Unicorn (NDSS'17)  — Cross-application information flow control
//   NoDoze (NDSS'19)   — Network traffic dependency scoring
//   ProvDetector (ACSAC'20) — Anomalous path detection in provenance
// ═══════════════════════════════════════════════════════════════

// PatternID identifies a specific detection pattern.
type PatternID string

const (
	// PatSensitiveExfil — tainted or untrusted process reads sensitive
	// file AND uses network tools within a short window.
	PatSensitiveExfil PatternID = "SENSITIVE_EXFIL"

	// PatScriptChild — tainted process writes a script file, and that
	// file is later executed (wasGeneratedBy + used chain).
	PatScriptChild PatternID = "SCRIPT_CHILD"

	// PatDeepTaint — a process becomes tainted through ≥3 propagation
	// hops from the initial source, indicating lateral movement.
	PatDeepTaint PatternID = "DEEP_TAINT_CHAIN"

	// PatPrivEsc — tainted process with setuid or capability-change
	// attribute, suggesting privilege escalation.
	PatPrivEsc PatternID = "PRIVILEGE_ESCALATION"

	// PatMemoryAnomaly — tainted process with mprotect RW→RX, fileless
	// execution (memfd_create), or W+X memory regions, suggesting
	// shellcode injection or code-reuse attack.
	// Triggers on-demand memory forensics acquisition + YARA scanning
	// of the process address space.
	PatMemoryAnomaly PatternID = "MEMORY_ANOMALY"
)

// PatternDesc returns a human-readable description of the pattern.
func (id PatternID) String() string {
	switch id {
	case PatSensitiveExfil:
		return "Sensitive file read + network activity — possible exfiltration"
	case PatScriptChild:
		return "File written by low-integrity process and later executed"
	case PatDeepTaint:
		return "Suspicious activity chain exceeding minimum depth threshold"
	case PatPrivEsc:
		return "Privilege escalation via setuid or capability change"
	case PatMemoryAnomaly:
		return "Memory anomaly — mprotect RW→RX or fileless execution on tainted process"
	}
	return string(id)
}

// ═══════════════════════════════════════════════════════════════
// Pattern functions
// ═══════════════════════════════════════════════════════════════

// checkSensitiveExfil looks for processes that both accessed a
// sensitive file and made a network connection.
//
// Signal chain:
//
//	proc:P --used--> file:/etc/shadow      (sensitive read)
//	proc:P --used--> net:external-ip       (network connect)
//	⇒ ALERT: exfiltration behaviour
func checkSensitiveExfil(te *TaintEngine) []*Alert {
	var alerts []*Alert

	// For each tainted process, check if it interacts with both
	// sensitive files and network endpoints.
	for _, id := range te.TaintedProcesses() {
		tn := te.Tainted(id)
		if tn == nil {
			continue
		}
		if tn.Level < TaintMedium {
			continue
		}
		label := te.nodeLabel(id)

		var sensitiveFiles []string
		var netTargets []string

		for _, e := range te.forward[id] {
			tgtNode := te.nodes[e.Target]
			if tgtNode == nil {
				continue
			}

			if tgtNode.Subtype == "file" && te.isSensitivePath(tgtNode.Label) {
				sensitiveFiles = append(sensitiveFiles, tgtNode.Label)
			}
			if tgtNode.Subtype == "network" {
				netTargets = append(netTargets, tgtNode.Label)
			}
		}

		if len(sensitiveFiles) > 0 && len(netTargets) > 0 {
			alerts = append(alerts, &Alert{
				Pattern:  PatSensitiveExfil,
				Severity: SeverityHigh,
				Headline: fmt.Sprintf("%s read %s and connected to %s",
					label,
					sensitiveFiles[0],
					netTargets[0]),
				AlertNodeID: id,
				Reason: fmt.Sprintf(
					"Process %s (taint=%s, depth=%d) accessed sensitive "+
						"files %v and network targets %v",
					id, tn.Level, tn.Depth,
					sensitiveFiles, netTargets),
			})
		}
	}
	return alerts
}

// checkScriptChild looks for: tainted process writes a file (W),
// then another (or the same) process executes/uses that file.
//
// Signal chain:
//
//	proc:P1 --wasGeneratedBy--> file:/tmp/evil.sh   (write)
//	proc:P2 --used--> file:/tmp/evil.sh              (exec/read)
//	⇒ ALERT: script provenance chain
func checkScriptChild(te *TaintEngine) []*Alert {
	var alerts []*Alert
	writtenByTaint := make(map[string]string) // fileID → tainted writer proc ID

	for id, tn := range te.tainted {
		if tn.Level < TaintLow {
			continue
		}
		node := te.nodes[id]
		if node == nil || node.Subtype != "process" {
			continue
		}
		// Find files this tainted process wrote (reverse wasGeneratedBy)
		for _, e := range te.reverse[id] {
			if e.Relation != provenance.ProvWasGeneratedBy {
				continue
			}
			srcNode := te.nodes[e.Source]
			if srcNode != nil && srcNode.Subtype == "file" {
				writtenByTaint[srcNode.ID] = id
			}
		}
	}

	// Now find processes that read those files
	for fileID, writerID := range writtenByTaint {
		for _, e := range te.reverse[fileID] {
			if e.Relation != provenance.ProvUsed {
				continue
			}
			reader := te.nodes[e.Source]
			if reader == nil || reader.Subtype != "process" {
				continue
			}
			wNode := te.nodes[writerID]
			fileNode := te.nodes[fileID]
			wLabel := "?"
			fLabel := "?"
			if wNode != nil {
				wLabel = wNode.Label
			}
			if fileNode != nil {
				fLabel = fileNode.Label
			}

			alerts = append(alerts, &Alert{
				Pattern:  PatScriptChild,
				Severity: SeverityCritical,
				Headline: fmt.Sprintf("%s wrote %s, then %s read it",
					wLabel, fLabel, reader.Label),
				AlertNodeID: reader.ID,
				Reason: fmt.Sprintf(
					"tainted process %s wrote file %s (via wasGeneratedBy), "+
						"later read by process %s (via used)",
					writerID, fileID, reader.ID),
			})
		}
	}
	return alerts
}

// checkDeepTaint flags processes whose taint propagation depth exceeds
// a threshold — indicating multi-stage lateral movement.
//
// A deep chain suggests:
//
//	web server → script → downloader → backdoor → C2
//	(depth 0)  → (1)    → (2)        → (3)     → (4)
func checkDeepTaint(te *TaintEngine, minDepth int) []*Alert {
	var alerts []*Alert
	for id, tn := range te.tainted {
		if tn.Depth < minDepth {
			continue
		}
		node := te.nodes[id]
		if node == nil || node.Subtype != "process" {
			continue
		}

		path := te.PropagationPath(id)
		var pathLabels []string
		for _, p := range path {
			if n := te.nodes[p]; n != nil {
				pathLabels = append(pathLabels, fmt.Sprintf("%s(%s)", n.Label, p))
			} else {
				pathLabels = append(pathLabels, p)
			}
		}

		alerts = append(alerts, &Alert{
			Pattern:  PatDeepTaint,
			Severity: SeverityMedium,
			Headline: fmt.Sprintf("%s taint depth=%d: %s",
				node.Label, tn.Depth, strings.Join(pathLabels, " -> ")),
			AlertNodeID: id,
			Reason: fmt.Sprintf(
				"taint propagation depth=%d from initial source; "+
					"propagation path spans %d nodes",
				tn.Depth, len(path)),
		})
	}
	return alerts
}

// checkPrivEsc looks for tainted processes with the setuid attribute
// or those that have accessed credential files.
func checkPrivEsc(te *TaintEngine) []*Alert {
	var alerts []*Alert
	for id, tn := range te.tainted {
		if tn.Level < TaintMedium {
			continue
		}
		node := te.nodes[id]
		if node == nil || node.Subtype != "process" {
			continue
		}

		// Check if setuid was detected
		if v, ok := node.Attributes["setuid"]; ok {
			if b, isBool := v.(bool); isBool && b {
				alerts = append(alerts, &Alert{
					Pattern:     PatPrivEsc,
					Severity:    SeverityHigh,
					Headline:    fmt.Sprintf("%s executed with setuid", node.Label),
					AlertNodeID: id,
					Reason: fmt.Sprintf(
						"tainted process %s (level=%s) had setuid attribute "+
							"(uid/euid mismatch during exec)",
						id, tn.Level),
				})
			}
		}
	}
	return alerts
}

// checkMemoryAnomaly detects tainted processes with memory-related
// anomalies: mprotect RW->RX, fileless execution, or shellcode
// attributes set by eBPF memory probes.
//
// Signal chain:
//
//	proc:P --used--> memory:rx            (eBPF detected mprotect RW->RX)
//	proc:P --used--> memfd:anonymous      (fileless execution)
//	proc:P [attr shellcode=true]           (already flagged)
//	proc:P [attr fileless=true]            (memfd_create detection)
//	=> ALERT: memory anomaly, triggers on-demand forensics
func checkMemoryAnomaly(te *TaintEngine) []*Alert {
	var alerts []*Alert

	for _, id := range te.TaintedProcesses() {
		tn := te.Tainted(id)
		if tn == nil {
			continue
		}
		node := te.nodes[id]
		if node == nil {
			continue
		}

		var reasons []string
		severity := SeverityMedium

		if v, ok := node.Attributes["shellcode"]; ok {
			if b, isBool := v.(bool); isBool && b {
				reasons = append(reasons, "mprotect RW->RX (可能的 Shellcode 注入)")
				severity = SeverityCritical
			}
		}

		if v, ok := node.Attributes["fileless"]; ok {
			if b, isBool := v.(bool); isBool && b {
				reasons = append(reasons, "无文件执行 (memfd_create)")
				if severity < SeverityHigh {
					severity = SeverityHigh
				}
			}
		}

		if v, ok := node.Attributes["memory_op"]; ok {
			if s, isStr := v.(string); isStr {
				switch s {
				case "mprotect_rx":
					reasons = append(reasons, "memory protection changed RW->RX")
					if severity < SeverityCritical {
						severity = SeverityCritical
					}
				case "memfd_create":
					reasons = append(reasons, "anonymous memory file created (memfd_create)")
					if severity < SeverityHigh {
						severity = SeverityHigh
					}
				}
			}
		}

		if v, ok := node.Attributes["pipe_reader"]; ok {
			if b, isBool := v.(bool); isBool && b {
				reasons = append(reasons, "pipe read - possible fileless chain")
				if severity < SeverityMedium {
					severity = SeverityMedium
				}
			}
		}
		if v, ok := node.Attributes["pipe_writer"]; ok {
			if b, isBool := v.(bool); isBool && b {
				reasons = append(reasons, "pipe write")
			}
		}

		if len(reasons) == 0 {
			continue
		}

		alerts = append(alerts, &Alert{
			Pattern:     PatMemoryAnomaly,
			Severity:    severity,
			Headline:    fmt.Sprintf("%s memory anomaly: %s", node.Label, reasons[0]),
			AlertNodeID: id,
			Reason: fmt.Sprintf("process %s (taint=%s depth=%d): %v",
				id, tn.Level, tn.Depth, reasons),
		})
	}

	return alerts
}

// --- Helpers ----------------------------------------------------

func (te *TaintEngine) nodeLabel(id string) string {
	if n := te.nodes[id]; n != nil {
		return n.Label
	}
	return id
}
