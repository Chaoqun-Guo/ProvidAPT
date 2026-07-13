// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package rulescanner

import (
	"fmt"
	"strings"
	"time"

	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
	"gopkg.in/yaml.v3"
)

// Alert structure
// Alert is triggered when a rule matches an event.
type Alert struct {
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"` // critical, high, medium, low
	Description string   `json:"description"`
	Tags        []string `json:"tags,omitempty"`
	RiskScore   float64  `json:"risk_score"`

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
	fmt.Fprintf(&b, "ALERT [%s] %s\n", strings.ToUpper(a.Severity), a.Title)
	fmt.Fprintf(&b, "   Rule: %s\n", a.RuleID)
	fmt.Fprintf(&b, "   Score: %.1f\n", a.RiskScore)
	fmt.Fprintf(&b, "   Event: %s\n", a.SubgraphDesc)
	fmt.Fprintf(&b, "   Time: %s\n", a.Timestamp.Format(time.RFC3339))
	if len(a.Tags) > 0 {
		fmt.Fprintf(&b, "   Tags: %s\n", strings.Join(a.Tags, ", "))
	}
	fmt.Fprintf(&b, "   Subgraph: %s\n", a.SubgraphID)
	return b.String()
}

// ConsoleLine returns a single-line console output.
func (a *Alert) ConsoleLine() string {
	label := "\u2139\ufe0f"
	switch a.Severity {
	case "critical":
		label = "\U0001F534"
	case "high":
		label = "\U0001F6A8"
	case "medium":
		label = "\u26A0\ufe0f"
	case "low":
		label = "\u2139\ufe0f"
	}
	return fmt.Sprintf("%s [%s] %s - %s", label, a.Severity, a.Title, a.SubgraphDesc)
}

// Markdown returns a Markdown-formatted alert.
func (a *Alert) Markdown() string {
	return fmt.Sprintf("## ProvidAPT Alert\n\n"+
		"**Rule:** %s  \n"+
		"**Severity:** `%s`  \n"+
		"**Score:** %.1f  \n"+
		"**Event:** `%s`  \n"+
		"**Time:** %s  \n"+
		"**Subgraph:** `%s`  \n",
		a.Title, strings.ToUpper(a.Severity), a.RiskScore,
		a.SubgraphDesc, a.Timestamp.Format(time.RFC3339), a.SubgraphID)
}

// Built-in rules (YAML)

// DefaultRulesYAML returns the built-in detection rules.
const DefaultRulesYAML = `
---
title: "Non-root modifies /etc/passwd"
id: "rule-passwd-001"
description: "Detects non-root processes writing to /etc/passwd"
level: high
tags: [attack.t1098, persistence]
detection:
  EventType: [11, 12]
  TargetPath: /etc/passwd
  UID: "!=0"

---
title: "Shadow File Access"
id: "rule-shadow-001"
description: "Detects access to /etc/shadow by any process"
level: critical
tags: [attack.t1003, credential-access]
detection:
  EventType: [10, 11, 12]
  TargetPath: /etc/shadow

---
title: "Web Shell Execution"
id: "rule-webshell-001"
description: "Web server process spawns an interactive shell"
level: critical
tags: [attack.t1505, persistence]
detection:
  EventType: [2]
  Comm: bash
  PID: ">1000"

---
title: "Suspicious Network Connection"
id: "rule-net-001"
description: "Non-browser process connects to external endpoint"
level: high
tags: [attack.t1043, c2]
detection:
  EventType: [20]
  Comm: bash

---
title: "C2 Beaconing via Curl"
id: "rule-c2-curl-001"
description: "Curl makes outbound connections from suspicious context"
level: high
tags: [attack.t1043, c2]
detection:
  EventType: [20]
  Comm: curl
  TargetPort: "443"

---
title: "Fileless Payload Download"
id: "rule-fileless-001"
description: "Network tool writes executable to temp directory"
level: high
tags: [attack.t1204, execution]
detection:
  EventType: [11, 12]
  TargetPath: /tmp/*
  Comm: "curl"

---
title: "Reverse Shell Detection"
id: "rule-revshell-001"
description: "Process spawns with reverse shell indicators (bash -i, /dev/tcp)"
level: critical
tags: [attack.t1059, execution, reverse-shell]
detection:
  EventType: [2]
  Comm: bash
  Flags: "reverse_shell"

---
title: "SSH Key Tampering"
id: "rule-sshkey-001"
description: "Unauthorized modification of SSH authorized_keys"
level: critical
tags: [attack.t1098, persistence, credential-access]
detection:
  EventType: [11, 12]
  TargetPath: /root/.ssh/authorized_keys*
  UID: "!=0"

---
title: "Container Escape Attempt"
id: "rule-cescape-001"
description: "Process writes to cgroup release_agent or uses nsenter from container"
level: critical
tags: [attack.t1611, container-escape, privilege-escalation]
detection:
  EventType: [11, 12]
  TargetPath: /sys/fs/cgroup*/release_agent*

---
title: "Suspicious SUID Bit Set"
id: "rule-suid-001"
description: "Non-root process sets SUID bit on a file"
level: high
tags: [attack.t1548, privilege-escalation]
detection:
  EventType: [13]
  Flags: "setuid"
  UID: "!=0"

---
title: "Memfd Exec -Process Hollowing"
id: "rule-memfd-001"
description: "Process executes from memfd (fileless execution indicator)"
level: critical
tags: [attack.t1620, defense-evasion, fileless]
detection:
  EventType: [2]
  TargetPath: /memfd:*

---
title: "Defense Evasion -Log Clearing"
id: "rule-logs-001"
description: "Process clears system logs or audit trails"
level: high
tags: [attack.t1070, defense-evasion, log-clear]
detection:
  EventType: [11, 12, 14]
  TargetPath: /var/log/*
  Comm: "*rm*"

---
title: "Credential Dumping -LSASS Access"
id: "rule-creddump-001"
description: "Non-LSASS process accesses LSASS memory or minidump"
level: critical
tags: [attack.t1003, credential-access, lsass]
detection:
  EventType: [10, 11]
  TargetPath: /proc/*/mem
  Comm: "*minikatz*"

---
title: "Lateral Movement -SSH from Non-Standard Context"
id: "rule-lateral-001"
description: "SSH client executed from non-interactive context (web/app server)"
level: high
tags: [attack.t1021, lateral-movement]
detection:
  EventType: [2]
  Comm: ssh
  PID: ">1000"

---
title: "PowerShell Encoded Command"
id: "rule-ps-001"
description: "PowerShell launched with encoded command or obfuscation"
level: high
tags: [attack.t1059, execution, powershell]
detection:
  EventType: [2]
  Comm: "*powershell*"
  Flags: "encoded"

---
title: "Kernel Module Loading by Non-Root"
id: "rule-kmod-001"
description: "Non-root process attempts to load a kernel module"
level: critical
tags: [attack.t1014, kernel-module, rootkit]
detection:
  EventType: [14]
  Comm: "*insmod*"
  UID: "!=0"

---
title: "Ransomware Indicators -Mass File Operations"
id: "rule-ransom-001"
description: "Process rapidly creates, renames, or deletes many files in user directories"
level: high
tags: [attack.t1486, ransomware, impact]
detection:
  EventType: [11, 12, 13, 14]
  TargetPath: /home/*/*
  Comm: "*encrypt*"

---
title: "C2 Beacon -Suspicious Domain Connection"
id: "rule-c2-dns-001"
description: "Process connects to dynamically-resolving or suspicious domains (DGA indicator)"
level: medium
tags: [attack.t1043, c2, beacon]
detection:
  EventType: [20]
  TargetPort: "443"
  Comm: "*python*"
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
