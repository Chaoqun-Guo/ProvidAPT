// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/audit"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/clioutput"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
)

func cmdAudit(cfgPath, catFilter, sinceDuration string, limit int) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		clioutput.Fatalf("Config load failed: %v", err)
	}

	auditDir := cfg.Output.Dir
	if auditDir == "" {
		auditDir = "/var/log/providapt"
	}

	store, err := audit.New(auditDir)
	if err != nil {
		clioutput.Fatalf("Audit store open failed: %v", err)
	}
	defer store.Close()

	// Parse category filter.
	var cat audit.Category
	switch catFilter {
	case "security":
		cat = audit.CatSecurity
	case "admin":
		cat = audit.CatAdmin
	case "system":
		cat = audit.CatSystem
	case "integrity":
		cat = audit.CatIntegrity
	case "", "all":
		cat = ""
	default:
		clioutput.Fatalf("Unknown category %q (use: security, admin, system, integrity, all)", catFilter)
	}

	// Parse since duration (supports days: "7d" = 168h).
	var since time.Time
	if sinceDuration != "" {
		d, err := parseDurationDays(sinceDuration)
		if err != nil {
			clioutput.Fatalf("Invalid duration %q: %v", sinceDuration, err)
		}
		since = time.Now().Add(-d)
	}

	entries, err := store.Query(cat, since, limit)
	if err != nil {
		clioutput.Fatalf("Audit query failed: %v", err)
	}

	if clioutput.IsJSONMode() {
		clioutput.PrintJSON(entries)
		return
	}

	if len(entries) == 0 {
		clioutput.Printf("%s\n", clioutput.Infof("No audit entries found"))
		return
	}

	fmt.Println(clioutput.Bold("Audit Log"))
	fmt.Println()

	t := clioutput.NewTable("Time", "Category", "Severity", "Source", "Message")
	for _, e := range entries {
		ts := e.Timestamp.Format(time.RFC3339)
		sev := severityColor(e.Severity)
		t.AddRow(ts, string(e.Category), sev, e.Source, truncate(e.Message, 80))
	}
	t.Render()

	fmt.Printf("\n%d entries shown\n", len(entries))
}

func severityColor(s string) string {
	switch s {
	case "CRITICAL":
		return clioutput.Errf("%s", s)
	case "WARNING":
		return clioutput.Warnf("%s", s)
	default:
		return s
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// parseDurationDays extends time.ParseDuration with day support:
// "7d" → 168h, "30d" → 720h.
func parseDurationDays(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		var days int
		if _, err := fmt.Sscanf(daysStr, "%d", &days); err != nil {
			return 0, fmt.Errorf("invalid days: %q", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
