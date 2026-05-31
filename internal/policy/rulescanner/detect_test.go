package rulescanner

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
)

// ─── Rule parsing tests ─────────────────────────────────────

const testRule = `
title: Test Rule
id: rule-test-001
description: A test rule
level: high
tags: [attack.test, test]
detection:
  EventType: [10]
  TargetPath: /etc/shadow
`

func TestLoadRule(t *testing.T) {
	rule, err := LoadRule([]byte(testRule))
	if err != nil {
		t.Fatalf("LoadRule: %v", err)
	}
	if rule.Title != "Test Rule" {
		t.Errorf("Title = %q", rule.Title)
	}
	if rule.Level != "high" {
		t.Errorf("Level = %q", rule.Level)
	}
	if rule.Detection.Selection.EventType == nil {
		t.Fatal("no selection parsed")
	}
}

func TestLoadRuleMissingTitle(t *testing.T) {
	_, err := LoadRule([]byte(`level: high`))
	if err == nil {
		t.Error("expected error for missing title")
	}
}

func TestLoadDefaultRules(t *testing.T) {
	rules, err := LoadDefaultRules()
	if err != nil {
		t.Fatalf("LoadDefaultRules: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("no default rules loaded")
	}
	t.Logf("Loaded %d built-in rules:", len(rules))
	for _, r := range rules {
		t.Logf("  %s [%s] — %s", r.ID, r.Level, r.Title)
	}
}

// ─── Rule matching tests ────────────────────────────────────

func TestMatchEventType(t *testing.T) {
	rule := &Rule{Detection: Detection{
		Selection: Selection{EventType: []uint32{11, 12}},
	}}
	if !rule.Match(&pb.Event{Type: 11}) {
		t.Error("should match type 11")
	}
	if !rule.Match(&pb.Event{Type: 12}) {
		t.Error("should match type 12")
	}
	if rule.Match(&pb.Event{Type: 10}) {
		t.Error("should not match type 10")
	}
}

func TestMatchTargetPath(t *testing.T) {
	rule := &Rule{Detection: Detection{
		Selection: Selection{TargetPath: "/etc/passwd"},
	}}
	if !rule.Match(&pb.Event{Pathname: "/etc/passwd"}) {
		t.Error("should match exact path")
	}
	if rule.Match(&pb.Event{Pathname: "/etc/hosts"}) {
		t.Error("should not match different path")
	}
}

func TestMatchWildcardPath(t *testing.T) {
	rule := &Rule{Detection: Detection{
		Selection: Selection{TargetPath: "/tmp/*"},
	}}
	if !rule.Match(&pb.Event{Pathname: "/tmp/evil.sh"}) {
		t.Error("should match /tmp/evil.sh")
	}
	if !rule.Match(&pb.Event{Pathname: "/tmp/payload.bin"}) {
		t.Error("should match /tmp/payload.bin")
	}
	if rule.Match(&pb.Event{Pathname: "/etc/passwd"}) {
		t.Error("should not match /etc/passwd")
	}
}

func TestMatchUID(t *testing.T) {
	rule := &Rule{Detection: Detection{
		Selection: Selection{UID: "!=0"},
	}}
	if !rule.Match(&pb.Event{Uid: 1000}) {
		t.Error("!=0 should match uid 1000")
	}
	if rule.Match(&pb.Event{Uid: 0}) {
		t.Error("!=0 should not match uid 0")
	}
}

func TestMatchComm(t *testing.T) {
	rule := &Rule{Detection: Detection{
		Selection: Selection{Comm: "bash"},
	}}
	if !rule.Match(&pb.Event{Comm: "bash"}) {
		t.Error("should match bash")
	}
	if rule.Match(&pb.Event{Comm: "python3"}) {
		t.Error("should not match python3")
	}
}

func TestMatchAllConditions(t *testing.T) {
	rule := &Rule{Detection: Detection{
		Selection: Selection{
			EventType:  []uint32{11},
			TargetPath: "/etc/passwd",
			UID:        "!=0",
		},
	}}

	// All conditions met
	if !rule.Match(&pb.Event{Type: 11, Pathname: "/etc/passwd", Uid: 1000}) {
		t.Error("should match all conditions")
	}

	// Wrong UID
	if rule.Match(&pb.Event{Type: 11, Pathname: "/etc/passwd", Uid: 0}) {
		t.Error("should not match root UID")
	}

	// Wrong path
	if rule.Match(&pb.Event{Type: 11, Pathname: "/etc/hosts", Uid: 1000}) {
		t.Error("should not match wrong path")
	}
}

// ─── Field comparison tests ─────────────────────────────────

func TestCompareField(t *testing.T) {
	tests := []struct {
		field string
		value uint64
		want  bool
	}{
		{"0", 0, true},
		{"1000", 1000, true},
		{"1000", 999, false},
		{"!=0", 100, true},
		{"!=0", 0, false},
		{">100", 200, true},
		{">100", 50, false},
		{"<100", 50, true},
		{"<100", 200, false},
		{">=10", 10, true},
		{">=10", 5, false},
		{"<=10", 5, true},
		{"<=10", 20, false},
	}
	for _, tt := range tests {
		got := compareField(tt.field, tt.value)
		if got != tt.want {
			t.Errorf("compareField(%q, %d) = %v", tt.field, tt.value, got)
		}
	}
}

// ─── Scanner tests ──────────────────────────────────────────

func TestNewScanner(t *testing.T) {
	rules, _ := LoadDefaultRules()
	s := NewScanner(rules, ScannerConfig{})
	if s == nil {
		t.Fatal("NewScanner returned nil")
	}
	if s.Input() == nil {
		t.Error("Input channel is nil")
	}
}

func TestScannerMatchAndAlert(t *testing.T) {
	rules, _ := LoadDefaultRules()
	s := NewScanner(rules, ScannerConfig{BufferSize: 100, FlushInterval: 50 * time.Millisecond})
	s.Start()
	defer s.Stop()

	// Send a matching event
	s.Input() <- &pb.Event{
		Type: 10, Pid: 100, Uid: 1000,
		Comm: "cat", Pathname: "/etc/shadow",
	}

	// Read alert
	select {
	case alert := <-s.Alerts():
		if alert.RuleID != "rule-shadow-001" {
			t.Errorf("RuleID = %s", alert.RuleID)
		}
		if alert.Severity != "critical" {
			t.Errorf("Severity = %s", alert.Severity)
		}
		t.Logf("Alert: %s", alert.String())

	case <-time.After(time.Second):
		t.Fatal("timeout waiting for alert")
	}
}

func TestScannerNonMatch(t *testing.T) {
	rules, _ := LoadDefaultRules()
	s := NewScanner(rules, ScannerConfig{})
	s.Start()
	defer s.Stop()

	// Send a non-matching event
	s.Input() <- &pb.Event{
		Type: 10, Pid: 0, Uid: 0,
		Comm: "systemd", Pathname: "/var/log/syslog",
	}

	// No alert should be triggered for this
	time.Sleep(50 * time.Millisecond)
	stats := s.Stats()
	if stats["events_matched"].(int64) > 0 {
		t.Error("non-match should not trigger alert")
	}
}

func TestScannerStats(t *testing.T) {
	rules, _ := LoadDefaultRules()
	s := NewScanner(rules, ScannerConfig{})
	stats := s.Stats()
	if stats["rules_loaded"] != 6 {
		t.Errorf("rules = %d", stats["rules_loaded"])
	}
}

func TestScannerMultipleEvents(t *testing.T) {
	rules, _ := LoadDefaultRules()
	s := NewScanner(rules, ScannerConfig{BufferSize: 100})
	s.Start()
	defer s.Stop()

	// Send multiple events
	events := []*pb.Event{
		{Type: 11, Pathname: "/etc/passwd", Uid: 1000},
		{Type: 20, Comm: "bash"},
		{Type: 2, Comm: "bash", Pid: 2000},
	}
	for _, evt := range events {
		s.Input() <- evt
	}

	time.Sleep(100 * time.Millisecond)
	stats := s.Stats()
	t.Logf("Processed: %d, Matched: %d", stats["events_processed"], stats["events_matched"])
	if stats["events_matched"].(int64) < 1 {
		t.Error("expected at least 1 match")
	}
}

// ─── Alert tests ────────────────────────────────────────────

func TestAlertString(t *testing.T) {
	a := &Alert{
		RuleID: "test-rule", Title: "Test Alert",
		Severity: "high", RiskScore: 7.5,
		SubgraphDesc: "PID 100 (bash) wrote /etc/passwd",
		Timestamp: time.Now(),
	}
	s := a.String()
	if !strings.Contains(s, "HIGH") {
		t.Errorf("alert string: %s", s)
	}
	t.Logf("Alert string:\n%s", s)
}

func TestAlertConsoleLine(t *testing.T) {
	a := &Alert{
		Title: "Test Alert", Severity: "critical",
		SubgraphDesc: "PID 100 (bash) EXEC /bin/sh",
	}
	line := a.ConsoleLine()
	if !strings.Contains(line, "🔴") {
		t.Errorf("critical alert missing emoji: %s", line)
	}
}

func TestAlertMarkdown(t *testing.T) {
	a := &Alert{
		Title: "Test Alert", Severity: "high",
		SubgraphDesc: "test event", Tags: []string{"attack.test"},
		Timestamp: time.Now(),
	}
	md := a.Markdown()
	if !strings.Contains(md, "ProvidAPT Alert") {
		t.Errorf("markdown: %s", md)
	}
}

func TestScoreCalculation(t *testing.T) {
	tests := []struct {
		level string
		want  float64
	}{
		{"critical", 10.0},
		{"high", 7.5},
		{"medium", 5.0},
		{"low", 2.5},
		{"unknown", 3.0},
	}
	s := &Scanner{}
	for _, tt := range tests {
		got := s.calcScore(tt.level)
		if got != tt.want {
			t.Errorf("calcScore(%q) = %.1f", tt.level, got)
		}
	}
}

// ─── YAML parsing tests ─────────────────────────────────────

func TestYAMLUnmarshalRule(t *testing.T) {
	var rule Rule
	err := yaml.Unmarshal([]byte(testRule), &rule)
	if err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}
	if rule.Title != "Test Rule" {
		t.Errorf("Title = %q", rule.Title)
	}
}

func TestDefaultRulesYAMLFormat(t *testing.T) {
	rules, err := ParseMultiRules([]byte(DefaultRulesYAML))
	if err != nil {
		t.Fatalf("ParseMultiRules: %v", err)
	}
	if len(rules) != 6 {
		t.Errorf("expected 6 rules, got %d", len(rules))
	}
	for _, r := range rules {
		if r.ID == "" {
			t.Error("rule missing ID")
		}
		if r.Level == "" {
			t.Error("rule missing level")
		}
	}
}

// ─── Integration test ──────────────────────────────────────

func TestDetectIntegration(t *testing.T) {
	// Load rules
	rules, _ := LoadDefaultRules()
	t.Logf("Loaded %d rules", len(rules))

	// Create scanner
	s := NewScanner(rules, ScannerConfig{BufferSize: 100})
	s.Start()
	defer s.Stop()

	// Simulate an attack: non-root modifies /etc/passwd
	go func() {
		s.Input() <- &pb.Event{Type: 11, Pid: 100, Uid: 1000,
			Comm: "vi", Pathname: "/etc/passwd"}
		s.Input() <- &pb.Event{Type: 11, Pid: 100, Uid: 1000,
			Comm: "vi", Pathname: "/etc/shadow"}
	}()

	// Collect alerts
	time.Sleep(200 * time.Millisecond)
	stats := s.Stats()

	t.Logf("=== Detection Integration ===")
	t.Logf("Events: %d", stats["events_processed"])
	t.Logf("Matches: %d", stats["events_matched"])
	t.Logf("Alerts: %d", stats["alerts_triggered"])

	if stats["events_matched"].(int64) == 0 {
		t.Error("expected at least 1 match in integration test")
	}
}
