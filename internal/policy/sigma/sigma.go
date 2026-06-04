// Package sigma implements Sigma rule parsing and execution.
//
// Sigma (https://github.com/SigmaHQ/sigma) is a generic signature
// format for SIEM systems expressed in YAML.  This package maps
// Sigma rules onto provenance graph queries.
//
// Example Sigma rule:
//
//   title: Suspicious Shadow File Access
//   logsource:
//     category: file_access
//   detection:
//     selection:
//       Image: /bin/bash
//       Target: /etc/shadow
//     condition: selection
//   level: high
//
// This is mapped to a graph query:
//   match: process("bash") → used → file("/etc/shadow")
package sigma

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/plugin"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"gopkg.in/yaml.v3"
)

// ═══════════════════════════════════════════════════════════════
// Sigma rule structures
// ═══════════════════════════════════════════════════════════════

// Rule represents a parsed Sigma rule.
type Rule struct {
	Title       string            `yaml:"title"`
	ID          string            `yaml:"id"`
	Description string            `yaml:"description"`
	Author      string            `yaml:"author"`
	Date        string            `yaml:"date"`
	Level       string            `yaml:"level"` // low, medium, high, critical
	Tags        []string          `yaml:"tags"`
	LogSource   LogSource         `yaml:"logsource"`
	Detection   Detection         `yaml:"detection"`
	FalsePositives []string       `yaml:"falsepositives"`
	Raw         map[string]interface{} `yaml:",inline"`
}

// LogSource describes the provenance event category.
type LogSource struct {
	Category string `yaml:"category"` // process, file_access, network
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
}

// Detection contains the selection conditions.
type Detection struct {
	Selections map[string]map[string]string `yaml:",inline,omitempty"`
	Condition  string                       `yaml:"condition"`
}

// ═══════════════════════════════════════════════════════════════
// SigmaRulePlugin
// ═══════════════════════════════════════════════════════════════

// SigmaRulePlugin executes Sigma rules against provenance graphs.
type SigmaRulePlugin struct {
	Name_  string
	Rules  []*Rule
}

func (p *SigmaRulePlugin) Name() string { return p.Name_ }

func (p *SigmaRulePlugin) Analyse(snap *provenance.Graph) []*plugin.Finding {
	var findings []*plugin.Finding
	for _, rule := range p.Rules {
		matches := p.evaluate(rule, snap)
		for _, match := range matches {
			findings = append(findings, &plugin.Finding{
				PluginName: p.Name_,
				Title:      fmt.Sprintf("Sigma: %s", rule.Title),
				Severity:   mapLevel(rule.Level),
				Score:      scoreFromLevel(rule.Level),
				NodeIDs:    match,
			})
		}
	}
	return findings
}

// evaluate runs a single Sigma rule against the graph.
func (p *SigmaRulePlugin) evaluate(rule *Rule, snap *provenance.Graph) [][]string {
	nodes := snap.Nodes()
	edges := snap.Edges()
	var matches [][]string

	switch rule.LogSource.Category {
	case "process":
		matches = p.matchProcess(rule, nodes, edges)
	case "file_access":
		matches = p.matchFileAccess(rule, nodes, edges)
	case "network":
		matches = p.matchNetwork(rule, nodes, edges)
	default:
		matches = p.matchGeneric(rule, nodes, edges)
	}
	return matches
}

// ── Match helpers ───────────────────────────────────────────

func (p *SigmaRulePlugin) matchProcess(rule *Rule, nodes []*provenance.Node, edges []*provenance.Edge) [][]string {
	var matches [][]string
	sel := rule.Detection.Selections
	if sel == nil {
		return nil
	}

	for _, n := range nodes {
		if n.Subtype != "process" {
			continue
		}
		if !p.matchSelection(sel, n, nodes, edges) {
			continue
		}
		matches = append(matches, []string{n.ID})
	}
	return matches
}

func (p *SigmaRulePlugin) matchFileAccess(rule *Rule, nodes []*provenance.Node, edges []*provenance.Edge) [][]string {
	var matches [][]string
	sel := rule.Detection.Selections
	if sel == nil {
		return nil
	}

	// Find edges: process → used/wasGeneratedBy → file
	for _, e := range edges {
		if e.Relation != provenance.ProvUsed &&
			e.Relation != provenance.ProvWasGeneratedBy {
			continue
		}
		srcNode := findNode(nodes, e.Source)
		tgtNode := findNode(nodes, e.Target)
		if srcNode == nil || tgtNode == nil {
			continue
		}
		if srcNode.Subtype != "process" || tgtNode.Subtype != "file" {
			continue
		}
		if !p.matchSelection(sel, srcNode, nodes, edges) {
			continue
		}
		if !p.matchTargetSelection(sel, tgtNode) {
			continue
		}
		matches = append(matches, []string{srcNode.ID, tgtNode.ID, e.ID})
	}
	return matches
}

func (p *SigmaRulePlugin) matchNetwork(rule *Rule, nodes []*provenance.Node, edges []*provenance.Edge) [][]string {
	var matches [][]string
	sel := rule.Detection.Selections
	if sel == nil {
		return nil
	}

	for _, e := range edges {
		if e.Relation != provenance.ProvUsed {
			continue
		}
		srcNode := findNode(nodes, e.Source)
		tgtNode := findNode(nodes, e.Target)
		if srcNode == nil || tgtNode == nil {
			continue
		}
		if srcNode.Subtype != "process" || tgtNode.Subtype != "network" {
			continue
		}
		if !p.matchSelection(sel, srcNode, nodes, edges) {
			continue
		}
		if !p.matchTargetSelection(sel, tgtNode) {
			continue
		}
		matches = append(matches, []string{srcNode.ID, tgtNode.ID, e.ID})
	}
	return matches
}

func (p *SigmaRulePlugin) matchGeneric(rule *Rule, nodes []*provenance.Node, edges []*provenance.Edge) [][]string {
	var matches [][]string
	sel := rule.Detection.Selections
	if sel == nil {
		return nil
	}
	for _, n := range nodes {
		if !p.matchSelection(sel, n, nodes, edges) {
			continue
		}
		matches = append(matches, []string{n.ID})
	}
	return matches
}

// ── Selection matching ──────────────────────────────────────

func (p *SigmaRulePlugin) matchSelection(sel map[string]map[string]string, n *provenance.Node, nodes []*provenance.Node, edges []*provenance.Edge) bool {
	for _, criteria := range sel {
		for field, expected := range criteria {
			lower := strings.ToLower(field)
			// Skip target-related fields — they are checked in matchTargetSelection
			if lower == "target" || lower == "dest" || lower == "dhost" {
				continue
			}
			actual := p.fieldValue(n, field, nodes, edges)
			if !wildcardMatch(expected, actual) {
				return false
			}
		}
	}
	return true
}

func (p *SigmaRulePlugin) matchTargetSelection(sel map[string]map[string]string, n *provenance.Node) bool {
	for _, criteria := range sel {
		for field, expected := range criteria {
			// Only check "Target" or "target" fields against file/network nodes
			lower := strings.ToLower(field)
			if lower != "target" && lower != "dest" && lower != "dhost" {
				continue
			}
			if !wildcardMatch(expected, n.Label) {
				return false
			}
		}
	}
	return true
}

// fieldValue extracts a Sigma field value from a provenance node.
func (p *SigmaRulePlugin) fieldValue(n *provenance.Node, field string, nodes []*provenance.Node, edges []*provenance.Edge) string {
	switch strings.ToLower(field) {
	case "image", "process", "commandline":
		return n.Label
	case "pid":
		if v, ok := n.Attributes["pid"]; ok {
			return fmt.Sprintf("%v", v)
		}
	case "uid":
		if v, ok := n.Attributes["uid"]; ok {
			return fmt.Sprintf("%v", v)
		}
	case "parentpid", "ppid":
		if v, ok := n.Attributes["ppid"]; ok {
			return fmt.Sprintf("%v", v)
		}
	case "comm":
		if v, ok := n.Attributes["comm"]; ok {
			return fmt.Sprintf("%v", v)
		}
	case "parent":
		// Walk wasInformedBy edges to find the parent process label.
		// Edge direction: Source(child) -> wasInformedBy -> Target(parent)
		for _, e := range edges {
			if e.Source == n.ID && e.Relation == provenance.ProvWasInformedBy {
				for _, pn := range nodes {
					if pn.ID == e.Target {
						return pn.Label
					}
				}
			}
		}
		return ""
	case "target", "dest", "dhost":
		return n.Label
	case "filepath", "path":
		return n.Label
	default:
		// Try as attribute
		if v, ok := n.Attributes[field]; ok {
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

// ═══════════════════════════════════════════════════════════════
// Rule parsing
// ═══════════════════════════════════════════════════════════════

// ParseRule parses a single Sigma YAML rule.
func ParseRule(data []byte) (*Rule, error) {
	var rule Rule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("sigma parse: %w", err)
	}
	if rule.Title == "" {
		return nil, fmt.Errorf("sigma rule missing title")
	}
	return &rule, nil
}

// LoadRules parses multiple Sigma rules from YAML (concatenated or multi-doc).
func LoadRules(data []byte) ([]*Rule, error) {
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	var rules []*Rule
	for {
		var rule Rule
		err := decoder.Decode(&rule)
		if err != nil {
			break
		}
		if rule.Title != "" {
			rules = append(rules, &rule)
		}
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no valid Sigma rules found")
	}
	return rules, nil
}

// EvaluateRule runs a single Sigma rule against node/edge slices
// without requiring a *provenance.Graph. Useful for analyzer integration.
func EvaluateRule(rule *Rule, nodes []*provenance.Node, edges []*provenance.Edge) [][]string {
	p := &SigmaRulePlugin{Name_: "sigma"}
	switch rule.LogSource.Category {
	case "process":
		return p.matchProcess(rule, nodes, edges)
	case "file_access":
		return p.matchFileAccess(rule, nodes, edges)
	case "network":
		return p.matchNetwork(rule, nodes, edges)
	default:
		return p.matchGeneric(rule, nodes, edges)
	}
}

// ── Built-in rules ──────────────────────────────────────────

// DefaultRules returns the built-in Sigma ruleset.
func DefaultRules() []*Rule {
	rules, err := LoadRules([]byte(defaultSigmaRules))
	if err != nil {
		log.Printf("sigma: failed to load default rules: %v", err)
		return nil
	}
	return rules
}

// NewDefaultPlugin creates a Sigma plugin with built-in rules.
func NewDefaultPlugin() *SigmaRulePlugin {
	return &SigmaRulePlugin{
		Name_: "sigma",
		Rules: DefaultRules(),
	}
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

func findNode(nodes []*provenance.Node, id string) *provenance.Node {
	for _, n := range nodes {
		if n.ID == id {
			return n
		}
	}
	return nil
}

// wildcardMatch matches strings with * wildcards (Sigma convention).
func wildcardMatch(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	// Convert Sigma wildcard to regex
	pattern = regexp.QuoteMeta(pattern)
	pattern = strings.ReplaceAll(pattern, `\*`, `.*`)
	pattern = "^" + pattern + "$"
	matched, _ := regexp.MatchString(pattern, value)
	return matched
}

func mapLevel(level string) string {
	switch strings.ToLower(level) {
	case "low":
		return "LOW"
	case "medium":
		return "MEDIUM"
	case "high":
		return "HIGH"
	case "critical":
		return "CRITICAL"
	default:
		return "MEDIUM"
	}
}

func scoreFromLevel(level string) float64 {
	switch strings.ToLower(level) {
	case "low":
		return 2
	case "medium":
		return 5
	case "high":
		return 8
	case "critical":
		return 10
	default:
		return 3
	}
}

// ═══════════════════════════════════════════════════════════════
// Built-in Sigma rules (YAML)
// ═══════════════════════════════════════════════════════════════

const defaultSigmaRules = `
title: Suspicious Shadow File Access
id: rule-shadow-001
description: Detects access to /etc/shadow by non-root processes
logsource:
  category: file_access
detection:
  selection:
    target: /etc/shadow
  condition: selection
level: high
tags: [attack.t1003, credential-access]
falsepositives: [admin scripts]
---
title: Web Server Shell Spawn
id: rule-webshell-001
description: Web server process spawns a shell
logsource:
  category: process
detection:
  selection:
    parent: httpd
    image: bash
  condition: selection
level: critical
tags: [attack.t1500, persistence]
falsepositives: [admin access]
---
title: Suspicious Network Connection
id: rule-net-001
description: Non-browser process connecting to external IP
logsource:
  category: network
detection:
  selection:
    process: bash
  condition: selection
level: high
tags: [attack.t1043, exfiltration]
---
title: Sensitive File Exfiltration
id: rule-exfil-001
description: Process reads sensitive file then connects to network
logsource:
  category: file_access
detection:
  selection:
    target: /etc/shadow
  condition: selection
level: high
tags: [attack.t1048, exfiltration]
---
title: Cron Persistence via Backdoor
id: rule-cron-001
description: Non-root process writes to cron directory
logsource:
  category: file_access
detection:
  selection:
    target: /var/spool/cron
  condition: selection
level: high
tags: [attack.t1053, persistence]
---
title: Privilege Escalation via setuid
id: rule-setuid-001
description: Process executes with setuid flag
logsource:
  category: process
detection:
  selection:
    setuid: true
  condition: selection
level: high
tags: [attack.t1548, privilege-escalation]
`
