// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package genrules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultRulesCount(t *testing.T) {
	rules := DefaultRules()
	if len(rules) != 8 {
		t.Errorf("expected 8 default rules, got %d", len(rules))
	}
}

func TestDefaultRulesHaveRequiredFields(t *testing.T) {
	for _, r := range DefaultRules() {
		if r.Alert == "" {
			t.Error("rule missing Alert")
		}
		if r.Expr == "" {
			t.Errorf("rule %q missing Expr", r.Alert)
		}
		if r.Labels == nil {
			t.Errorf("rule %q missing Labels", r.Alert)
		}
		if r.Annotations == nil {
			t.Errorf("rule %q missing Annotations", r.Alert)
		}
		if _, ok := r.Labels["severity"]; !ok {
			t.Errorf("rule %q missing severity label", r.Alert)
		}
	}
}

func TestGenerateContainsAllAlerts(t *testing.T) {
	rules := DefaultRules()
	output := Generate(rules)

	for _, r := range rules {
		if !strings.Contains(output, r.Alert) {
			t.Errorf("output missing alert %q", r.Alert)
		}
		if !strings.Contains(output, r.Expr) {
			t.Errorf("output missing expr for %q", r.Alert)
		}
	}
}

func TestGenerateYAMLStructure(t *testing.T) {
	output := Generate(DefaultRules())

	// Check top-level structure
	if !strings.Contains(output, "groups:") {
		t.Error("output missing 'groups:'")
	}
	if !strings.Contains(output, "rules:") {
		t.Error("output missing 'rules:'")
	}
	if !strings.Contains(output, "interval: 30s") {
		t.Error("output missing default interval")
	}
}

func TestGenerateGroupsBySeverity(t *testing.T) {
	output := Generate(DefaultRules())

	// Should have at least critical and warning groups
	if !strings.Contains(output, "providapt_alerts") {
		t.Error("output missing 'providapt_alerts' group")
	}
	if !strings.Contains(output, "providapt_health") {
		t.Error("output missing 'providapt_health' group")
	}
}

func TestGenerateEmptyRules(t *testing.T) {
	output := Generate(nil)
	if !strings.HasPrefix(output, "# ProvidAPT") {
		t.Errorf("expected comment header, got %q", output[:20])
	}
}

func TestGenerateCustomRule(t *testing.T) {
	rules := []Rule{
		{
			Alert: "TestAlert",
			Expr:  "up == 0",
			For:   "1m",
			Labels: map[string]string{
				"severity": "critical",
			},
			Annotations: map[string]string{
				"summary": "Test alert",
			},
		},
	}
	output := Generate(rules)
	if !strings.Contains(output, "TestAlert") {
		t.Error("output missing custom alert name")
	}
	if !strings.Contains(output, "up == 0") {
		t.Error("output missing custom expr")
	}
}

func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yml")

	err := WriteFile(path, DefaultRules())
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("written file is empty")
	}
	if !strings.Contains(string(data), "ProvidAPTDown") {
		t.Error("written file missing alert content")
	}
}

func TestGenerateHeader(t *testing.T) {
	output := Generate(nil)
	if !strings.HasPrefix(output, "#") {
		t.Error("expected header comment")
	}
}
