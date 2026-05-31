package rulescanner

import (
	"fmt"
	"strings"
	"time"
	"gopkg.in/yaml.v3"

	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
)

// ═══════════════════════════════════════════════════════════════
// Alert structure
// ═══════════════════════════════════════════════════════════════

// Alert is triggered when a rule matches an event.
type Alert struct {
	RuleID      string    `json:"rule_id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"` // critical, high, medium, low
	Description string    `json:"description"`
	Tags        []string  `json:"tags,omitempty"`
	RiskScore   float64   `json:"risk_score"`

	// Source event
	Event *pb.Event `json:"event"`

	// Subgraph reference
	SubgraphID   string `json:"subgraph_id"`
	SubgraphDesc string `json:"subgraph_desc"`

	// Tracking
	Timestamp time.Time `json:"timestamp"`
}

// String returns a human-readable alert representation.
func (a *Alert) String() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("🚨 [%s] %s\n", strings.ToUpper(a.Severity), a.Title))
	b.WriteString(fmt.Sprintf("   Rule: %s\n", a.RuleID))
	b.WriteString(fmt.Sprintf("   Score: %.1f\n", a.RiskScore))
	b.WriteString(fmt.Sprintf("   Event: %s\n", a.SubgraphDesc))
	b.WriteString(fmt.Sprintf("   Time: %s\n", a.Timestamp.Format(time.RFC3339)))
	if len(a.Tags) > 0 {
		b.WriteString(fmt.Sprintf("   Tags: %s\n", strings.Join(a.Tags, ", ")))
	}
	b.WriteString(fmt.Sprintf("   Subgraph: %s\n", a.SubgraphID))
	return b.String()
}

// ConsoleLine returns a single-line console output.
func (a *Alert) ConsoleLine() string {
	emoji := "⚠"
	switch a.Severity {
	case "critical":
		emoji = "🔴"
	case "high":
		emoji = "🚨"
	case "medium":
		emoji = "⚠"
	case "low":
		emoji = "ℹ"
	}
	return fmt.Sprintf("%s [%s] %s — %s", emoji, a.Severity, a.Title, a.SubgraphDesc)
}

// Markdown returns a Markdown-formatted alert.
func (a *Alert) Markdown() string {
	return fmt.Sprintf("## 🚨 ProvidAPT Alert\n\n"+
		"**Rule:** %s  \n"+
		"**Severity:** `%s`  \n"+
		"**Score:** %.1f  \n"+
		"**Event:** `%s`  \n"+
		"**Time:** %s  \n"+
		"**Subgraph:** `%s`  \n",
		a.Title, strings.ToUpper(a.Severity), a.RiskScore,
		a.SubgraphDesc, a.Timestamp.Format(time.RFC3339), a.SubgraphID)
}

// ─── Built-in rules (YAML) ──────────────────────────────────

// DefaultRulesYAML returns the built-in detection rules.
const DefaultRulesYAML = `
- title: "Non-root modifies /etc/passwd"
  id: "rule-passwd-001"
  description: "Detects non-root processes writing to /etc/passwd"
  level: high
  tags: [attack.t1098, persistence]
  detection:
    EventType: [11, 12]
    TargetPath: /etc/passwd
    UID: "!=0"

- title: "Shadow File Access"
  id: "rule-shadow-001"
  description: "Detects access to /etc/shadow by any process"
  level: critical
  tags: [attack.t1003, credential-access]
  detection:
    EventType: [10, 11, 12]
    TargetPath: /etc/shadow

- title: "Web Shell Execution"
  id: "rule-webshell-001"
  description: "Web server process spawns an interactive shell"
  level: critical
  tags: [attack.t1505, persistence]
  detection:
    EventType: [2]
    Comm: bash
    PID: ">1000"

- title: "Suspicious Network Connection"
  id: "rule-net-001"
  description: "Non-browser process connects to external endpoint"
  level: high
  tags: [attack.t1043, c2]
  detection:
    EventType: [20]
    Comm: bash

- title: "C2 Beaconing via Curl"
  id: "rule-c2-curl-001"
  description: "Curl makes outbound connections from suspicious context"
  level: high
  tags: [attack.t1043, c2]
  detection:
    EventType: [20]
    Comm: curl
    TargetPort: "443"

- title: "Fileless Payload Download"
  id: "rule-fileless-001"
  description: "Network tool writes executable to temp directory"
  level: high
  tags: [attack.t1204, execution]
  detection:
    EventType: [11, 12]
    TargetPath: /tmp/*
    Comm: "curl"
`

// LoadDefaultRules parses the built-in rules.
func LoadDefaultRules() ([]*Rule, error) {
	return ParseMultiRules([]byte(DefaultRulesYAML))
}

// ParseMultiRules parses a multi-document YAML rule set.
func ParseMultiRules(data []byte) ([]*Rule, error) {
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
	return rules, nil
}
