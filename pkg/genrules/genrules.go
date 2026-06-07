// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package genrules generates Prometheus alerting rule YAML files
// from ProvidAPT's metrics and detection patterns.
package genrules

import (
	"fmt"
	"os"
	"time"
)

// Rule represents a single Prometheus alerting rule.
type Rule struct {
	Alert       string            `yaml:"alert"`
	Expr        string            `yaml:"expr"`
	For         string            `yaml:"for,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

// Group is a Prometheus rule group.
type Group struct {
	Name  string `yaml:"name"`
	Rules []Rule `yaml:"rules"`
}

// RulesFile is the top-level Prometheus rules YAML structure.
type RulesFile struct {
	Groups []Group `yaml:"groups"`
}

// DefaultRules returns the full set of recommended alerting rules.
func DefaultRules() []Rule {
	return []Rule{
		{
			Alert: "ProvidAPTDown",
			Expr:  "up{job=\"providapt\"} == 0",
			For:   "1m",
			Labels: map[string]string{
				"severity": "critical",
			},
			Annotations: map[string]string{
				"summary":     "ProvidAPT daemon is down",
				"description": "ProvidAPT job {{ $labels.instance }} has been unreachable for over 1 minute.",
			},
		},
		{
			Alert: "ProvidAPTCriticalAlert",
			Expr:  "rate(providapt_alerts_triggered_total{severity=\"CRITICAL\"}[5m]) > 0",
			For:   "1m",
			Labels: map[string]string{
				"severity": "critical",
			},
			Annotations: map[string]string{
				"summary":     "Critical APT alert triggered",
				"description": "ProvidAPT detected a critical-severity alert on {{ $labels.instance }}.",
			},
		},
		{
			Alert: "ProvidAPTHighAlertRate",
			Expr:  "rate(providapt_alerts_triggered_total[5m]) > 5",
			For:   "2m",
			Labels: map[string]string{
				"severity": "warning",
			},
			Annotations: map[string]string{
				"summary":     "High APT alert rate",
				"description": "ProvidAPT is generating >5 alerts/second on {{ $labels.instance }}.",
			},
		},
		{
			Alert: "ProvidAPTEventsDropped",
			Expr:  "rate(providapt_events_dropped_total[5m]) > 0",
			For:   "1m",
			Labels: map[string]string{
				"severity": "warning",
			},
			Annotations: map[string]string{
				"summary":     "Events being dropped",
				"description": "ProvidAPT is dropping events on {{ $labels.instance }} — possible ring buffer overflow.",
			},
		},
		{
			Alert: "ProvidAPTHighMemory",
			Expr:  "providapt_memory_usage_bytes > 1e9",
			For:   "5m",
			Labels: map[string]string{
				"severity": "warning",
			},
			Annotations: map[string]string{
				"summary":     "ProvidAPT memory usage exceeds 1 GB",
				"description": "ProvidAPT is using {{ $value | humanize }} on {{ $labels.instance }}.",
			},
		},
		{
			Alert: "ProvidAPTHighCPU",
			Expr:  "providapt_cpu_usage_ratio > 0.9",
			For:   "5m",
			Labels: map[string]string{
				"severity": "warning",
			},
			Annotations: map[string]string{
				"summary":     "ProvidAPT CPU usage exceeds 90%",
				"description": "ProvidAPT CPU ratio is {{ $value }} on {{ $labels.instance }}.",
			},
		},
		{
			Alert: "ProvidAPTPipelineBackpressure",
			Expr:  "rate(providapt_pipeline_backpressure_events_total[5m]) > 0",
			For:   "1m",
			Labels: map[string]string{
				"severity": "warning",
			},
			Annotations: map[string]string{
				"summary":     "Pipeline backpressure detected",
				"description": "ProvidAPT pipeline is experiencing backpressure on {{ $labels.instance }}.",
			},
		},
		{
			Alert: "ProvidAPTGracefulShutdownCheck",
			Expr:  "providapt_uptime_seconds < 60",
			For:   "0m",
			Labels: map[string]string{
				"severity": "info",
			},
			Annotations: map[string]string{
				"summary":     "ProvidAPT recently started",
				"description": "ProvidAPT has been running for less than 60 seconds on {{ $labels.instance }}.",
			},
		},
	}
}

// Generate produces a Prometheus rules YAML string from the given rules.
func Generate(rules []Rule) string {
	out := "# ProvidAPT Prometheus alerting rules\n"
	out += "# Generated " + time.Now().UTC().Format(time.RFC3339) + "\n"
	out += "#\n"

	groups := map[string][]Rule{
		"providapt_alerts":  nil,
		"providapt_health":  nil,
		"providapt_resources": nil,
	}

	for _, r := range rules {
		switch r.Labels["severity"] {
		case "critical":
			groups["providapt_alerts"] = append(groups["providapt_alerts"], r)
		case "warning":
			groups["providapt_health"] = append(groups["providapt_health"], r)
		default:
			groups["providapt_resources"] = append(groups["providapt_resources"], r)
		}
	}

	for _, name := range []string{"providapt_alerts", "providapt_health", "providapt_resources"} {
		rs := groups[name]
		if len(rs) == 0 {
			continue
		}
		out += "\n---\n"
		out += "# yaml-language-server: $schema=https://prometheus.io/schema/rule.json\n"
		out += fmt.Sprintf("# Group: %s\n", name)
		out += "groups:\n"
		out += fmt.Sprintf("  - name: %s\n", name)
		out += "    interval: 30s\n"
		out += "    rules:\n"
		for _, r := range rs {
			out += fmt.Sprintf("      - alert: %s\n", r.Alert)
			out += fmt.Sprintf("        expr: %s\n", r.Expr)
			if r.For != "" {
				out += fmt.Sprintf("        for: %s\n", r.For)
			}
			if len(r.Labels) > 0 {
				out += "        labels:\n"
				for k, v := range r.Labels {
					out += fmt.Sprintf("          %s: %s\n", k, v)
				}
			}
			if len(r.Annotations) > 0 {
				out += "        annotations:\n"
				for k, v := range r.Annotations {
					out += fmt.Sprintf("          %s: \"%s\"\n", k, v)
				}
			}
		}
	}
	return out
}

// WriteFile generates rules and writes them to a file.
func WriteFile(path string, rules []Rule) error {
	data := Generate(rules)
	return os.WriteFile(path, []byte(data), 0644)
}
