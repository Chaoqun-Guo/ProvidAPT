// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/genrules"
)

func TestGenrulesIntegrationDefaultRules(t *testing.T) {
	rules := genrules.DefaultRules()
	if len(rules) < 9 {
		t.Errorf("expected at least 9 default rules, got %d", len(rules))
	}
	required := []string{"ProvidaptNoEvents", "ProvidaptBackpressure", "ProvidaptCriticalAlert"}
	for _, alert := range required {
		found := false
		for _, rule := range rules {
			if rule.Alert == alert {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("default rules missing required alert %q", alert)
		}
	}

	// Verify all rules have required fields
	for _, r := range rules {
		if r.Alert == "" {
			t.Error("rule missing Alert")
		}
		if r.Expr == "" {
			t.Errorf("rule %q missing Expr", r.Alert)
		}
		if r.Labels == nil || r.Labels["severity"] == "" {
			t.Errorf("rule %q missing severity label", r.Alert)
		}
	}
}

func TestGenrulesIntegrationGenerateYAML(t *testing.T) {
	output := genrules.Generate(genrules.DefaultRules())

	if !strings.HasPrefix(output, "#") {
		t.Error("expected YAML comment header")
	}
	if !strings.Contains(output, "groups:") {
		t.Error("output missing groups:")
	}
	if !strings.Contains(output, "rules:") {
		t.Error("output missing rules:")
	}

	// Check all alert names appear
	for _, r := range genrules.DefaultRules() {
		if !strings.Contains(output, r.Alert) {
			t.Errorf("output missing rule %q", r.Alert)
		}
	}
}

func TestGenrulesIntegrationWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "providapt-rules.yml")

	if err := genrules.WriteFile(path, genrules.DefaultRules()); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("written file is empty")
	}
}

func TestGenrulesIntegrationCustomRule(t *testing.T) {
	rules := []genrules.Rule{
		{
			Alert: "IntegrationTestAlert",
			Expr:  "up == 0",
			For:   "1m",
			Labels: map[string]string{
				"severity": "critical",
			},
			Annotations: map[string]string{
				"summary": "Integration test alert",
			},
		},
	}

	output := genrules.Generate(rules)
	if !strings.Contains(output, "IntegrationTestAlert") {
		t.Error("output missing custom alert name")
	}
	if !strings.Contains(output, "severity: critical") {
		t.Error("output missing severity label")
	}
}

func TestGenrulesIntegrationCategorization(t *testing.T) {
	rules := []genrules.Rule{
		{Alert: "CritAlert", Expr: "a > 0", Labels: map[string]string{"severity": "critical"}},
		{Alert: "WarnAlert", Expr: "b > 0", Labels: map[string]string{"severity": "warning"}},
		{Alert: "InfoAlert", Expr: "c > 0", Labels: map[string]string{"severity": "info"}},
	}

	output := genrules.Generate(rules)

	if !strings.Contains(output, "providapt_alerts") {
		t.Error("expected critical group 'providapt_alerts'")
	}
	if !strings.Contains(output, "providapt_health") {
		t.Error("expected warning group 'providapt_health'")
	}
	if !strings.Contains(output, "providapt_resources") {
		t.Error("expected info group 'providapt_resources'")
	}
}
