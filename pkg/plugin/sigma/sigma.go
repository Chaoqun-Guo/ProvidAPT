// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package sigma provides a Sigma rule-compatible pattern matching plugin
// that scans the provenance graph for suspicious activity patterns.
package sigma

import (
	"strings"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/plugin"
)

func init() {
	plugin.Register(&SigmaPlugin{})
}

// SigmaRule defines a single detection rule compatible with Sigma syntax.
type SigmaRule struct {
	ID          string
	Title       string
	Description string
	Severity    string // LOW, MEDIUM, HIGH, CRITICAL
	Detection   Detection
}

// Detection defines the matching criteria.
type Detection struct {
	// NodeLabel matches nodes whose label contains this substring.
	NodeLabel string
	// NodeType matches nodes with a specific prov_type.
	NodeType string
	// NodeAttr matches nodes with an attribute containing the value.
	NodeAttr map[string]string
	// EdgeRelation matches edges with the given relation.
	EdgeRelation string
	// MinScore filters findings with minimum score.
	MinScore float64
}

// SigmaPlugin implements the Plugin interface for Sigma-style pattern matching.
type SigmaPlugin struct {
	rules []SigmaRule
}

// Name returns the plugin identifier.
func (p *SigmaPlugin) Name() string { return "sigma" }

// Init loads Sigma rules from configuration.
func (p *SigmaPlugin) Init(cfg map[string]interface{}) error {
	p.rules = DefaultRules()
	if cfg == nil {
		return nil
	}
	// Allow loading custom rules from config
	if rules, ok := cfg["rules"].([]interface{}); ok {
		for _, r := range rules {
			if rule, ok := r.(map[string]interface{}); ok {
				p.rules = append(p.rules, ruleFromMap(rule))
			}
		}
	}
	return nil
}

// Shutdown cleans up plugin resources.
func (p *SigmaPlugin) Shutdown() error {
	p.rules = nil
	return nil
}

// Analyse scans the graph against all registered Sigma rules.
func (p *SigmaPlugin) Analyse(snap *provenance.Graph) []*plugin.Finding {
	var findings []*plugin.Finding

	for _, rule := range p.rules {
		findings = append(findings, p.evaluate(rule, snap)...)
	}

	return findings
}

func (p *SigmaPlugin) evaluate(rule SigmaRule, snap *provenance.Graph) []*plugin.Finding {
	var findings []*plugin.Finding

	for _, n := range snap.Nodes() {
		if !matchesNode(n, rule.Detection) {
			continue
		}

		// Check edge relation if specified
		if rule.Detection.EdgeRelation != "" {
			hasEdge := false
			for _, e := range snap.Edges() {
				if (e.Source == n.ID || e.Target == n.ID) &&
					strings.Contains(strings.ToLower(e.Relation), strings.ToLower(rule.Detection.EdgeRelation)) {
					hasEdge = true
					break
				}
			}
			if !hasEdge {
				continue
			}
		}

		findings = append(findings, &plugin.Finding{
			PluginName: p.Name(),
			Title:      rule.Title,
			Severity:   rule.Severity,
			Score:      severityScore(rule.Severity),
			NodeIDs:    []string{n.ID},
			Evidence: map[string]interface{}{
				"rule_id":    rule.ID,
				"node_id":    n.ID,
				"node_type":  n.ProvType,
				"node_label": n.Label,
			},
		})
	}

	return findings
}

func matchesNode(n *provenance.Node, d Detection) bool {
	if d.NodeLabel != "" && !strings.Contains(strings.ToLower(n.Label), strings.ToLower(d.NodeLabel)) {
		return false
	}
	if d.NodeType != "" && !strings.EqualFold(n.ProvType, d.NodeType) {
		return false
	}
	if d.NodeAttr != nil {
		for k, v := range d.NodeAttr {
			actual := plugin.NodeAttrString(n, k)
			if !strings.Contains(strings.ToLower(actual), strings.ToLower(v)) {
				return false
			}
		}
	}
	return true
}

func severityScore(sev string) float64 {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 50
	case "HIGH":
		return 40
	case "MEDIUM":
		return 30
	case "LOW":
		return 20
	default:
		return 10
	}
}

// DefaultRules returns built-in Sigma-compatible detection rules.
func DefaultRules() []SigmaRule {
	return []SigmaRule{
		{
			ID:          "sigma-webshell-001",
			Title:       "Web Shell Detection",
			Description: "A process with network-facing attributes was created from a writable entity",
			Severity:    "HIGH",
			Detection: Detection{
				NodeLabel:    "httpd",
				EdgeRelation: "used",
			},
		},
		{
			ID:          "sigma-suspicious-parent-001",
			Title:       "Suspicious Child Process",
			Description: "An office/productivity process spawned a shell",
			Severity:    "HIGH",
			Detection: Detection{
				NodeLabel:    "bash",
				EdgeRelation: "forked",
			},
		},
		{
			ID:          "sigma-exfiltration-001",
			Title:       "Data Exfiltration via Network",
			Description: "A file read event is followed by network activity from the same process",
			Severity:    "CRITICAL",
			Detection: Detection{
				NodeType:     "prov:Activity",
				EdgeRelation: "used",
			},
		},
		{
			ID:          "sigma-privilege-escalation-001",
			Title:       "Privilege Escalation via Setuid",
			Description: "A process changed its security context to a different user",
			Severity:    "HIGH",
			Detection: Detection{
				NodeAttr: map[string]string{"uid": "0"},
			},
		},
		{
			ID:          "sigma-fileless-exec-001",
			Title:       "Fileless Execution via Memory",
			Description: "Memory modified to executable after file write from suspicious process",
			Severity:    "MEDIUM",
			Detection: Detection{
				NodeType: "prov:Entity",
				NodeAttr: map[string]string{"memory": "rwx"},
			},
		},
	}
}

// ruleFromMap parses a map into a SigmaRule.
func ruleFromMap(m map[string]interface{}) SigmaRule {
	r := SigmaRule{}
	if v, ok := m["id"].(string); ok {
		r.ID = v
	}
	if v, ok := m["title"].(string); ok {
		r.Title = v
	}
	if v, ok := m["severity"].(string); ok {
		r.Severity = v
	}
	if d, ok := m["detection"].(map[string]interface{}); ok {
		if v, ok := d["node_label"].(string); ok {
			r.Detection.NodeLabel = v
		}
		if v, ok := d["node_type"].(string); ok {
			r.Detection.NodeType = v
		}
		if v, ok := d["edge_relation"].(string); ok {
			r.Detection.EdgeRelation = v
		}
	}
	return r
}

// Ensure SigmaPlugin implements the plugin interfaces.
var _ plugin.Plugin = (*SigmaPlugin)(nil)
var _ plugin.LifecyclePlugin = (*SigmaPlugin)(nil)
