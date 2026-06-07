// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package ai

import "fmt"

// ═══════════════════════════════════════════════════════════════
// Prompt templates
// ═══════════════════════════════════════════════════════════════

// SystemPrompt defines the AI's role as a cybersecurity analyst.
const SystemPrompt = `You are a senior cybersecurity analyst specializing in APT (Advanced Persistent Threat) detection and incident response. You are given a provenance graph that captures system-level events (process execution, file access, network connections) that have been identified as potentially malicious.

Analyze the provenance data and provide:
1. Attack Path Description — Describe the attacker's step-by-step intrusion chain in natural language.
2. Affected Assets — Summarize what systems, files, processes, and network endpoints were impacted.
3. Remediation Recommendations — Provide specific, actionable steps to contain the threat and prevent recurrence.

Be precise and technical. Reference specific PIDs, file paths, and IP addresses from the data.`

// AnalysePrompt builds the full prompt for attack analysis.
func AnalysePrompt(graphJSON string) string {
	return fmt.Sprintf(`Analyze the following provenance graph data from a Linux system monitoring tool. The graph captures process executions, file operations, and network connections that were flagged as suspicious.

Provenance Graph Data (JSON):
%s

Please provide a structured analysis with these sections:

### Attack Path Description
Describe the complete attack chain step by step. For each step, explain what happened, what technique was used, and how it connects to the next step. Include specific process names, PIDs, file paths, and network endpoints.

### Affected Assets
List all compromised or impacted resources organized by category:
- Processes (PID, name)
- Files (path, type of access)
- Network endpoints (IP addresses, ports)
- Credentials or privilege changes

### Remediation Recommendations
Provide specific, ordered remediation steps:
1. Immediate containment actions
2. Eradication steps
3. Recovery procedures
4. Long-term prevention measures

### ATT&CK Techniques
Map each observed behavior to MITRE ATT&CK technique IDs where applicable.`, graphJSON)
}

// QAPrompt builds a prompt for answering a specific question about the graph.
func QAPrompt(graphJSON string, question string) string {
	return fmt.Sprintf(`Given the following provenance graph data, answer the analyst's question concisely and accurately.

Provenance Graph Data (JSON):
%s

Analyst Question: %s

Provide a direct answer based ONLY on the data shown above. If the data does not contain enough information to answer, state that clearly.`, graphJSON, question)
}
