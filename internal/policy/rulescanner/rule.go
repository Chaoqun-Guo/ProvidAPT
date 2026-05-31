// Package detect implements a streaming detection engine for
// ProvidAPT v2.  It supports YAML-based custom detection rules
// (Sigma-inspired) and real-time graph scanning.
package rulescanner

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
)

// ═══════════════════════════════════════════════════════════════
// YAML Rule Definition
// ═══════════════════════════════════════════════════════════════

// Rule is a single detection rule (Sigma-inspired format).
type Rule struct {
	Title       string   `yaml:"title"`
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Author      string   `yaml:"author,omitempty"`
	Date        string   `yaml:"date,omitempty"`
	Level       string   `yaml:"level"` // low, medium, high, critical
	Tags        []string `yaml:"tags,omitempty"`
	Detection   Detection `yaml:"detection"`
}

// Detection contains the selection criteria.
type Detection struct {
	Selection Selection `yaml:",inline"` // inline YAML keys
	Condition  string   `yaml:"condition"`
}

// Selection is a set of AND-conditions.
type Selection struct {
	// EventType matches event type IDs (e.g., [10, 11]).
	EventType []uint32 `yaml:"EventType,omitempty"`

	// TargetPath matches file path patterns.
	TargetPath string `yaml:"TargetPath,omitempty"`

	// Comm matches process name.
	Comm string `yaml:"Comm,omitempty"`

	// UID matches user ID ("0", "!=0", ">1000").
	UID string `yaml:"UID,omitempty"`

	// PID matches process ID.
	PID string `yaml:"PID,omitempty"`

	// TargetIP matches destination IP.
	TargetIP string `yaml:"TargetIP,omitempty"`

	// TargetPort matches destination port.
	TargetPort string `yaml:"TargetPort,omitempty"`

	// Flags matches event flags (e.g., "setuid").
	Flags string `yaml:"Flags,omitempty"`
}

// ─── Rule loading ───────────────────────────────────────────

// LoadRule parses a single YAML rule.
func LoadRule(data []byte) (*Rule, error) {
	var rule Rule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("parse rule: %w", err)
	}
	if rule.Title == "" {
		return nil, fmt.Errorf("rule missing title")
	}
	if rule.Level == "" {
		rule.Level = "medium"
	}
	return &rule, nil
}

// LoadRuleFile loads a rule from a YAML file.
func LoadRuleFile(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rule file: %w", err)
	}
	return LoadRule(data)
}

// LoadAllRules loads all .yaml files from a directory.
func LoadAllRules(dir string) ([]*Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir: %w", err)
	}
	var rules []*Rule
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yaml") && !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		path := dir + "/" + e.Name()
		rule, err := LoadRuleFile(path)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", e.Name(), err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// ─── Matching ───────────────────────────────────────────────

// Match checks if an event matches this rule's selection.
func (r *Rule) Match(evt *pb.Event) bool {
	return r.matchSelection(r.Detection.Selection, evt)
}

// matchSelection checks if an event matches a single selection (AND logic).
func (r *Rule) matchSelection(sel Selection, evt *pb.Event) bool {
	// EventType check
	if len(sel.EventType) > 0 {
		found := false
		for _, et := range sel.EventType {
			if evt.Type == et {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// TargetPath check (file path)
	if sel.TargetPath != "" {
		if !patternMatch(sel.TargetPath, evt.Pathname) {
			return false
		}
	}

	// Comm check (process name)
	if sel.Comm != "" {
		if !patternMatch(sel.Comm, evt.Comm) {
			return false
		}
	}

	// UID check
	if sel.UID != "" {
		if !compareField(sel.UID, uint64(evt.Uid)) {
			return false
		}
	}

	// PID check
	if sel.PID != "" {
		if !compareField(sel.PID, uint64(evt.Pid)) {
			return false
		}
	}

	// TargetPort check
	if sel.TargetPort != "" {
		if !compareField(sel.TargetPort, uint64(evt.Dport)) {
			return false
		}
	}

	// TargetIP check
	if sel.TargetIP != "" {
		ipStr := intToIP(evt.Daddr)
		if !patternMatch(sel.TargetIP, ipStr) {
			return false
		}
	}

	// Flags check (e.g., "setuid")
	if sel.Flags != "" {
		if sel.Flags == "setuid" && evt.Flags&1 == 0 {
			return false
		}
	}

	return true
}

// ─── Field comparison ───────────────────────────────────────

// compareField compares a field string with a value.
// Supports: "1000", "!=0", ">1000", "<100", ">=5", "<=10".
func compareField(field string, value uint64) bool {
	field = strings.TrimSpace(field)

	switch {
	case strings.HasPrefix(field, "!="):
		var cmp uint64
		fmt.Sscanf(field[2:], "%d", &cmp)
		return value != cmp

	case strings.HasPrefix(field, ">="):
		var cmp uint64
		fmt.Sscanf(field[2:], "%d", &cmp)
		return value >= cmp

	case strings.HasPrefix(field, "<="):
		var cmp uint64
		fmt.Sscanf(field[2:], "%d", &cmp)
		return value <= cmp

	case strings.HasPrefix(field, ">"):
		var cmp uint64
		fmt.Sscanf(field[1:], "%d", &cmp)
		return value > cmp

	case strings.HasPrefix(field, "<"):
		var cmp uint64
		fmt.Sscanf(field[1:], "%d", &cmp)
		return value < cmp

	default:
		var cmp uint64
		fmt.Sscanf(field, "%d", &cmp)
		return value == cmp
	}
}

// ─── Pattern matching ───────────────────────────────────────

// patternMatch supports basic wildcard matching: "prefix*" and "*suffix".
func patternMatch(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return len(value) >= len(prefix) && value[:len(prefix)] == prefix
	}
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return len(value) >= len(suffix) && value[len(value)-len(suffix):] == suffix
	}
	return pattern == value
}

// ─── Helpers ────────────────────────────────────────────────

func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF)
}
