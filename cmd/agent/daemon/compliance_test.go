//go:build linux

package main

import (
	"os"
	"strings"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/api"
)

func TestWriteComplianceHTMLReportUsesReadableSeparators(t *testing.T) {
	dir := t.TempDir()
	path, err := writeComplianceHTMLReport(dir, api.ComplianceStatus{
		Tenant:         "prod",
		ReadinessScore: 92,
		ReadinessGrade: "A",
		SIEM: api.SIEMStatus{
			Provider:   "splunk",
			LastStatus: "forwarded",
			Endpoint:   "https://siem.example.com/services/collector",
		},
	})
	if err != nil {
		t.Fatalf("writeComplianceHTMLReport returned error: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "92 / 100 - Grade A") {
		t.Fatalf("readiness row missing readable separator: %s", text)
	}
	if !strings.Contains(text, "splunk - forwarded -&gt; https://siem.example.com/services/collector") {
		t.Fatalf("SIEM row missing readable route: %s", text)
	}
}

func TestWriteComplianceReportBundleWritesJSONAndHTML(t *testing.T) {
	artifacts, err := writeComplianceReportBundle(t.TempDir(), api.ComplianceStatus{
		Tenant:         "prod",
		ReadinessScore: 87,
		ReadinessGrade: "B",
	})
	if err != nil {
		t.Fatalf("writeComplianceReportBundle returned error: %v", err)
	}
	for kind, path := range artifacts {
		if path == "" {
			t.Fatalf("%s artifact path is empty", kind)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s artifact missing at %s: %v", kind, path, err)
		}
	}
}
