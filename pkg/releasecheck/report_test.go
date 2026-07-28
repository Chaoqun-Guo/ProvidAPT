// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package releasecheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenderMarkdown(t *testing.T) {
	report := Report{
		GeneratedAt:     time.Date(2026, 7, 8, 1, 2, 3, 0, time.UTC),
		ConfigPath:      "/etc/providapt/providapt.toml",
		Version:         "1.2.2",
		Commit:          "abc123",
		BuildDate:       "2026-07-08T00:00:00Z",
		ReleaseReady:    true,
		CommercialReady: true,
		Passed:          1,
		Checks: []Check{{
			Name:    "config_valid",
			Status:  StatusPass,
			Message: "configuration loads",
		}},
	}

	out := RenderMarkdown(report)
	if !strings.Contains(out, "# ProvidAPT Release Evidence") {
		t.Fatalf("missing title: %s", out)
	}
	if !strings.Contains(out, "## Release Gates") {
		t.Fatalf("missing release gate section: %s", out)
	}
	if !strings.Contains(out, "| PASS | `config_valid` | configuration loads |  |  |") {
		t.Fatalf("missing check row: %s", out)
	}
}

func TestWriteReportJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "report.json")
	report := Report{Version: "1.2.2", Checks: []Check{{Name: "config_valid", Status: StatusPass}}}
	if err := WriteReport(path, report); err != nil {
		t.Fatalf("WriteReport json: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode json report: %v", err)
	}
	if decoded.Version != "1.2.2" {
		t.Fatalf("version = %q", decoded.Version)
	}
}

func TestWriteReportMarkdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.md")
	report := Report{Version: "1.2.2", Checks: []Check{{Name: "config_valid", Status: StatusPass}}}
	if err := WriteReport(path, report); err != nil {
		t.Fatalf("WriteReport markdown: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ProvidAPT Release Evidence") {
		t.Fatalf("unexpected markdown report: %s", string(data))
	}
}
