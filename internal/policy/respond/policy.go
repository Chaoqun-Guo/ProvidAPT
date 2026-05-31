package respond

import (
	"fmt"
	"log"
	"strings"
)

// ═══════════════════════════════════════════════════════════════
// Response policy engine — YAML-configured action rules
// ═══════════════════════════════════════════════════════════════

// ResponseRule defines a single response action in rules.yaml.
type ResponseRule struct {
	// Name — human-readable rule name.
	Name string `yaml:"name"`

	// Condition — when this rule triggers.
	// Format: "on_risk_score > 90" or "on_event = memfd_create"
	Condition string `yaml:"condition"`

	// Action — what to do.
	Action string `yaml:"action"`

	// Target — what to act on (optional).
	Target string `yaml:"target,omitempty"`

	// Parameters for the action.
	Params map[string]string `yaml:"params,omitempty"`
}

// ResponsePolicy manages YAML-configured response rules.
type ResponsePolicy struct {
	// Rules — ordered list of response rules.
	Rules []ResponseRule `yaml:"rules"`
}

// DefaultResponsePolicy returns built-in response rules.
func DefaultResponsePolicy() *ResponsePolicy {
	return &ResponsePolicy{
		Rules: []ResponseRule{
			{
				Name:      "High-risk process isolation",
				Condition: "on_risk_score > 90",
				Action:    "isolate_process_tree",
				Params:    map[string]string{"level": "FULL_ISOLATION"},
			},
			{
				Name:      "Suspicious network block",
				Condition: "on_event = net_connect AND taint = true",
				Action:    "block_network",
				Params:    map[string]string{"level": "NETWORK_ONLY"},
			},
			{
				Name:      "Malicious file quarantine",
				Condition: "on_event = file_write AND taint = true",
				Action:    "quarantine_file",
				Params:    map[string]string{"level": "lock"},
			},
			{
				Name:      "Memory execution response",
				Condition: "on_event = mprotect_rx OR on_event = memfd_create",
				Action:    "isolate_process_tree",
				Params:    map[string]string{"level": "FULL_ISOLATION"},
			},
			{
				Name:      "Sensitive file access block",
				Condition: "on_path CONTAINS /etc/shadow AND uid != 0",
				Action:    "block_process",
				Params:    map[string]string{"duration": "3600s"},
			},
		},
	}
}

// Evaluate checks all rules against a set of conditions and
// returns the matching response actions.
func (rp *ResponsePolicy) Evaluate(riskScore float64, eventType string, tainted bool, path string, uid uint32) []ResponseRule {
	var matches []ResponseRule
	for _, rule := range rp.Rules {
		if matchRule(rule, riskScore, eventType, tainted, path, uid) {
			matches = append(matches, rule)
			log.Printf("[policy] TRIGGERED: %s (action=%s)", rule.Name, rule.Action)
		}
	}
	return matches
}

// matchRule checks if a single rule's condition matches.
func matchRule(rule ResponseRule, riskScore float64, eventType string, tainted bool, path string, uid uint32) bool {
	cond := rule.Condition

	// Check "on_risk_score > X"
	if strings.Contains(cond, "on_risk_score >") {
		var threshold float64
		if _, err := fmt.Sscanf(cond, "on_risk_score > %f", &threshold); err == nil {
			if riskScore <= threshold {
				return false
			}
		}
	}

	// Check "on_event = X"
	if strings.Contains(cond, "on_event =") {
		var expectedEvent string
		if _, err := fmt.Sscanf(cond, "on_event = %s", &expectedEvent); err == nil {
			parts := strings.Split(expectedEvent, "|")
			found := false
			for _, p := range parts {
				if strings.EqualFold(eventType, p) {
					found = true
					break
				}
			}
			if !found {
				// Check for OR conditions
				if !strings.Contains(cond, "OR") {
					return false
				}
			}
		}
	}

	// Check "AND taint = true"
	if strings.Contains(cond, "taint = true") && !tainted {
		return false
	}

	// Check "on_path CONTAINS X"
	if strings.Contains(cond, "on_path CONTAINS") {
		var expectedPath string
		if _, err := fmt.Sscanf(cond, "on_path CONTAINS %s", &expectedPath); err == nil {
			if !strings.Contains(path, expectedPath) {
				return false
			}
		}
	}

	// Check "uid != 0"
	if strings.Contains(cond, "uid != 0") && uid == 0 {
		return false
	}

	return true
}

// ExecuteResponse runs the action for a matched rule.
func ExecuteResponse(rule ResponseRule, blocker *CausalBlocker, quarantine *FileQuarantineManager, pid uint32, comm string, files []string) {
	switch rule.Action {
	case "isolate_process_tree":
		level := BlockAll
		if l, ok := rule.Params["level"]; ok {
			switch l {
			case "NETWORK_ONLY":
				level = BlockNetwork
			case "SENSITIVE":
				level = BlockSensitive
			}
		}
		blocker.BlockProcess(pid, comm, level)

	case "block_network":
		blocker.BlockProcess(pid, comm, BlockNetwork)

	case "block_process":
		blocker.BlockProcess(pid, comm, BlockAll)

	case "quarantine_file":
		qLevel := QuarantineLock
		if l, ok := rule.Params["level"]; ok {
			switch l {
			case "move":
				qLevel = QuarantineMove
			case "delete":
				qLevel = QuarantineDelete
			}
		}
		if len(files) > 0 {
			quarantine.QuarantineFilesByPID(pid, files, qLevel)
		}
	}
}
