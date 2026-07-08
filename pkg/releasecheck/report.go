// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package releasecheck

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WriteReport writes the release check report as JSON or Markdown.
// The output format is selected by file extension: .json writes structured
// JSON, everything else writes Markdown suitable for release evidence.
func WriteReport(path string, report Report) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}

	var data []byte
	var err error
	if strings.EqualFold(filepath.Ext(path), ".json") {
		data, err = json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal report: %w", err)
		}
		data = append(data, '\n')
	} else {
		data = []byte(RenderMarkdown(report))
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

// RenderMarkdown renders a human-readable evidence report.
func RenderMarkdown(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# ProvidAPT Release Readiness Report\n\n")
	fmt.Fprintf(&b, "| Field | Value |\n")
	fmt.Fprintf(&b, "|---|---|\n")
	fmt.Fprintf(&b, "| Generated At | %s |\n", report.GeneratedAt.Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprintf(&b, "| Config Path | `%s` |\n", escapePipe(report.ConfigPath))
	if report.EvidencePath != "" {
		fmt.Fprintf(&b, "| Evidence Path | `%s` |\n", escapePipe(report.EvidencePath))
	}
	if report.WaiverPath != "" {
		fmt.Fprintf(&b, "| Waiver Path | `%s` |\n", escapePipe(report.WaiverPath))
	}
	if report.ChecksumsPath != "" {
		fmt.Fprintf(&b, "| Checksums Path | `%s` |\n", escapePipe(report.ChecksumsPath))
	}
	fmt.Fprintf(&b, "| Version | `%s` |\n", escapePipe(report.Version))
	fmt.Fprintf(&b, "| Commit | `%s` |\n", escapePipe(report.Commit))
	fmt.Fprintf(&b, "| Build Date | `%s` |\n", escapePipe(report.BuildDate))
	fmt.Fprintf(&b, "| Summary | %s |\n", escapePipe(report.Summary()))
	fmt.Fprintf(&b, "| Release Ready | %t |\n", report.ReleaseReady)
	fmt.Fprintf(&b, "| Commercial Ready | %t |\n\n", report.CommercialReady)

	fmt.Fprintf(&b, "## Checks\n\n")
	fmt.Fprintf(&b, "| Status | Check | Message | Fix Suggestion | Waiver |\n")
	fmt.Fprintf(&b, "|---|---|---|---|---|\n")
	for _, check := range report.Checks {
		fmt.Fprintf(&b, "| %s | `%s` | %s | %s | %s |\n",
			strings.ToUpper(check.Status),
			escapePipe(check.Name),
			escapePipe(check.Message),
			escapePipe(check.FixSuggestion),
			escapePipe(formatWaiver(check.Waiver)),
		)
	}
	return b.String()
}

func formatWaiver(waiver *Waiver) string {
	if waiver == nil {
		return ""
	}
	parts := []string{
		fmt.Sprintf("approved by %s", waiver.ApprovedBy),
		fmt.Sprintf("reason: %s", waiver.Reason),
	}
	if waiver.Expires != "" {
		parts = append(parts, fmt.Sprintf("expires: %s", waiver.Expires))
	}
	return strings.Join(parts, "; ")
}

func escapePipe(value string) string {
	value = strings.ReplaceAll(value, "\r\n", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.ReplaceAll(value, "|", "\\|")
}
