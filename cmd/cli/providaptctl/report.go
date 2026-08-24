// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/clioutput"
)

// MITRE ATT&CK technique mapping for ProvidAPT alert patterns.
var mitreMapping = map[string]struct {
	Tactic    string
	Technique string
	TID       string
}{
	"SENSITIVE_EXFIL":      {"TA0010", "Exfiltration Over C2 Channel", "T1041"},
	"SCRIPT_CHILD":         {"TA0002", "Command and Scripting Interpreter", "T1059"},
	"DEEP_TAINT_CHAIN":     {"TA0008", "Lateral Movement", "T1563"},
	"PRIVILEGE_ESCALATION": {"TA0004", "Exploitation for Privilege Escalation", "T1068"},
	"MEMORY_ANOMALY":       {"TA0005", "Process Injection", "T1055"},
	"SIGMA:webshell":       {"TA0003", "Web Shell", "T1505"},
}

type mitreEntry struct {
	Tactic     string         `json:"tactic"`
	Technique  string         `json:"technique"`
	TID        string         `json:"tid"`
	Count      int            `json:"count"`
	Severities map[string]int `json:"severities"`
}

// cmdReport generates a MITRE ATT&CK heatmap HTML report from alerts.
func cmdReport(outDir, outputPath string) {
	clioutput.Printf("Generating MITRE ATT&CK heatmap report...\n")

	alerts, err := loadAllAlerts(outDir)
	if err != nil {
		clioutput.Fatalf("Failed to load alerts: %v", err)
	}

	if len(alerts) == 0 {
		clioutput.Printf("%s\n", clioutput.Warnf("No alerts found in %s", outDir))
		return
	}

	// Aggregate by MITRE technique
	agg := make(map[string]*mitreEntry)
	for _, a := range alerts {
		pattern := a.Pattern
		mapped, ok := mitreMapping[pattern]
		if !ok {
			// Fallback: use pattern as technique name
			mapped = struct {
				Tactic    string
				Technique string
				TID       string
			}{
				Tactic:    "TA0XXX",
				Technique: pattern,
				TID:       "T0000",
			}
		}

		key := mapped.TID
		if _, exists := agg[key]; !exists {
			agg[key] = &mitreEntry{
				Tactic:     mapped.Tactic,
				Technique:  mapped.Technique,
				TID:        mapped.TID,
				Severities: make(map[string]int),
			}
		}
		agg[key].Count++
		agg[key].Severities[a.Severity.String()]++
	}

	// Sort by count descending
	entries := make([]*mitreEntry, 0, len(agg))
	for _, e := range agg {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})

	// Write output
	if outputPath == "" {
		outputPath = filepath.Join(outDir, "mitre-heatmap.html")
	}

	html := generateHeatmapHTML(entries, len(alerts))
	if err := os.WriteFile(outputPath, []byte(html), 0644); err != nil {
		clioutput.Fatalf("Failed to write report: %v", err)
	}

	clioutput.Printf("%s\n", clioutput.Okf("Report generated: %s", outputPath))
	clioutput.Printf("  Total alerts: %d\n", len(alerts))
	clioutput.Printf("  MITRE techniques: %d\n", len(entries))
}

type alertRecord struct {
	Pattern  string
	Severity severityInt
}

type severityInt int

func (s severityInt) String() string {
	switch s {
	case 10:
		return "INFO"
	case 20:
		return "LOW"
	case 30:
		return "MEDIUM"
	case 40:
		return "HIGH"
	case 50:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func loadAllAlerts(dir string) ([]alertRecord, error) {
	// Try alerts.ndjson first, then alerts.json
	paths := []string{
		filepath.Join(dir, "alerts.ndjson"),
		filepath.Join(dir, "alerts.json"),
	}

	for _, path := range paths {
		records, err := readAlertFile(path)
		if err == nil && len(records) > 0 {
			return records, nil
		}
	}
	return nil, nil
}

func readAlertFile(path string) ([]alertRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var records []alertRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var raw map[string]interface{}
		if err := json.Unmarshal(line, &raw); err != nil {
			continue
		}

		rec := alertRecord{}
		if p, ok := raw["pattern"].(string); ok {
			rec.Pattern = p
		}
		if s, ok := raw["severity"].(string); ok {
			switch strings.ToUpper(s) {
			case "CRITICAL":
				rec.Severity = 50
			case "HIGH":
				rec.Severity = 40
			case "MEDIUM":
				rec.Severity = 30
			case "LOW":
				rec.Severity = 20
			default:
				rec.Severity = 10
			}
		}
		if sev, ok := raw["severity"].(float64); ok {
			rec.Severity = severityInt(sev)
		}
		records = append(records, rec)
	}
	return records, scanner.Err()
}

func generateHeatmapHTML(entries []*mitreEntry, totalAlerts int) string {
	var b strings.Builder

	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ProvidAPT - MITRE ATT&CK Heatmap</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 40px; }
  h1 { color: #58a6ff; margin-bottom: 8px; font-size: 28px; }
  .subtitle { color: #8b949e; margin-bottom: 32px; font-size: 14px; }
  table { border-collapse: collapse; width: 100%; max-width: 900px; }
  th { text-align: left; padding: 10px 16px; border-bottom: 2px solid #30363d; color: #8b949e; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
  td { padding: 12px 16px; border-bottom: 1px solid #21262d; }
  .heat-cell { text-align: center; font-weight: bold; border-radius: 4px; min-width: 60px; }
  .tactic { color: #58a6ff; font-family: monospace; font-size: 13px; }
  .technique { color: #c9d1d9; }
  .tid { color: #8b949e; font-family: monospace; font-size: 12px; }
  .sev-bar { display: flex; gap: 4px; margin-top: 4px; }
  .sev-seg { height: 4px; border-radius: 2px; flex: 1; }
  .footer { margin-top: 32px; color: #8b949e; font-size: 12px; border-top: 1px solid #21262d; padding-top: 16px; }
  .summary-cards { display: flex; gap: 16px; margin-bottom: 32px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px 24px; }
  .card-value { font-size: 32px; font-weight: bold; color: #58a6ff; }
  .card-label { font-size: 12px; color: #8b949e; margin-top: 4px; }
</style>
</head>
<body>
<h1>ProvidAPT - MITRE ATT&CK Heatmap</h1>
<p class="subtitle">Generated ` + time.Now().Format("2006-01-02 15:04:05") + `</p>

<div class="summary-cards">
  <div class="card"><div class="card-value">` + fmt.Sprintf("%d", totalAlerts) + `</div><div class="card-label">Total Alerts</div></div>
  <div class="card"><div class="card-value">` + fmt.Sprintf("%d", len(entries)) + `</div><div class="card-label">Techniques Mapped</div></div>
</div>

<table>
<tr><th>Tactic</th><th>Technique</th><th>ID</th><th>Count</th><th>Severity</th><th>Heat</th></tr>
`)

	maxCount := 1
	for _, e := range entries {
		if e.Count > maxCount {
			maxCount = e.Count
		}
	}

	for _, e := range entries {
		pct := float64(e.Count) / float64(maxCount) * 100
		color := heatColor(pct)

		critical := e.Severities["CRITICAL"]
		high := e.Severities["HIGH"]
		medium := e.Severities["MEDIUM"]

		b.WriteString(fmt.Sprintf(`<tr>
  <td class="tactic">%s</td>
  <td class="technique">%s</td>
  <td class="tid">%s</td>
  <td><strong>%d</strong></td>
  <td>
    <div class="sev-bar">
      <div class="sev-seg" style="background:%s;flex:%.1f"></div>
      <div class="sev-seg" style="background:%s;flex:%.1f"></div>
      <div class="sev-seg" style="background:%s;flex:%.1f"></div>
    </div>
  </td>
  <td class="heat-cell" style="background:%s;color:%s">%.0f</td>
</tr>
`,
			html.EscapeString(e.Tactic),
			html.EscapeString(e.Technique),
			html.EscapeString(e.TID),
			e.Count,
			"#f85149", float64(critical)+1,
			"#d29922", float64(high)+1,
			"#58a6ff", float64(medium)+1,
			color, textColor(pct), pct,
		))
	}

	b.WriteString(`</table>
<div class="footer">
  <p>Legend: severity bar shows CRITICAL (red) | HIGH (yellow) | MEDIUM (blue)</p>
  <p>ProvidAPT - Provenance-driven APT Detection</p>
</div>
</body>
</html>`)

	return b.String()
}

func heatColor(pct float64) string {
	switch {
	case pct >= 80:
		return "#f85149"
	case pct >= 50:
		return "#d29922"
	case pct >= 20:
		return "#58a6ff"
	default:
		return "#21262d"
	}
}

func textColor(pct float64) string {
	if pct >= 50 {
		return "#ffffff"
	}
	return "#c9d1d9"
}
