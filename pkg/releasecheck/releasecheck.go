// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package releasecheck validates the operational settings expected before a
// commercial ProvidAPT handoff or release candidate sign-off.
package releasecheck

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/config"
)

const (
	StatusPass   = "pass"
	StatusWarn   = "warn"
	StatusWaived = "waived"
	StatusFail   = "fail"
)

// Options controls release readiness checks.
type Options struct {
	ConfigPath    string
	EvidencePath  string
	WaiverPath    string
	ChecksumsPath string
	SBOMPaths     []string
	Version       string
	Commit        string
	BuildDate     string
}

// Waiver records a reviewed release readiness exception.
type Waiver struct {
	Check      string `json:"check"`
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approved_by"`
	Expires    string `json:"expires,omitempty"`
}

// Check records one release readiness check outcome.
type Check struct {
	Name          string  `json:"name"`
	Status        string  `json:"status"`
	Message       string  `json:"message"`
	FixSuggestion string  `json:"fix_suggestion,omitempty"`
	Waiver        *Waiver `json:"waiver,omitempty"`
}

// Report aggregates release readiness checks.
type Report struct {
	GeneratedAt     time.Time `json:"generated_at"`
	ConfigPath      string    `json:"config_path"`
	EvidencePath    string    `json:"evidence_path,omitempty"`
	WaiverPath      string    `json:"waiver_path,omitempty"`
	ChecksumsPath   string    `json:"checksums_path,omitempty"`
	SBOMPaths       []string  `json:"sbom_paths,omitempty"`
	Version         string    `json:"version"`
	Commit          string    `json:"commit"`
	BuildDate       string    `json:"build_date"`
	Checks          []Check   `json:"checks"`
	Passed          int       `json:"passed"`
	Warnings        int       `json:"warnings"`
	Waived          int       `json:"waived"`
	Failed          int       `json:"failed"`
	ReleaseReady    bool      `json:"release_ready"`
	CommercialReady bool      `json:"commercial_ready"`
}

// Run executes all release readiness checks.
func Run(opts Options) Report {
	report := Report{
		GeneratedAt:   time.Now().UTC(),
		ConfigPath:    opts.ConfigPath,
		EvidencePath:  opts.EvidencePath,
		WaiverPath:    opts.WaiverPath,
		ChecksumsPath: opts.ChecksumsPath,
		SBOMPaths:     opts.SBOMPaths,
		Version:       opts.Version,
		Commit:        opts.Commit,
		BuildDate:     opts.BuildDate,
	}

	cfg, configLoaded := checkConfig(&report, opts.ConfigPath)
	checkVersionMetadata(&report, opts.Version, opts.Commit, opts.BuildDate)
	if configLoaded {
		checkCommercialConfig(&report, cfg)
	}
	checkReleaseEvidence(&report, opts.EvidencePath)
	checkChecksums(&report, opts.ChecksumsPath)
	checkSBOMs(&report, opts.SBOMPaths)
	applyWaivers(&report, opts.WaiverPath)

	report.ReleaseReady = report.Failed == 0
	report.CommercialReady = report.Failed == 0 && report.Warnings == 0
	return report
}

// Summary returns a compact human-readable report summary.
func (r Report) Summary() string {
	state := "not ready"
	if r.CommercialReady {
		state = "commercial ready"
	} else if r.ReleaseReady {
		state = "ready with warnings"
	}
	return fmt.Sprintf("%s: %d passed, %d warnings, %d waived, %d failed", state, r.Passed, r.Warnings, r.Waived, r.Failed)
}

// HasFailures reports whether any release-blocking issue exists.
func (r Report) HasFailures() bool {
	return r.Failed > 0
}

func checkConfig(report *Report, path string) (*config.Config, bool) {
	if strings.TrimSpace(path) == "" {
		add(report, Check{
			Name:          "config_path",
			Status:        StatusFail,
			Message:       "config path is empty",
			FixSuggestion: "Pass -config with the intended ProvidAPT configuration file.",
		})
		return nil, false
	}

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			add(report, Check{
				Name:          "config_file",
				Status:        StatusWarn,
				Message:       "config file not found; defaults and environment overrides will be used",
				FixSuggestion: "Provide the customer or release configuration with -config before final sign-off.",
			})
		} else {
			add(report, Check{
				Name:          "config_file",
				Status:        StatusFail,
				Message:       fmt.Sprintf("cannot stat config file: %v", err),
				FixSuggestion: "Fix filesystem permissions or provide a readable config path.",
			})
			return nil, false
		}
	}

	cfg, err := config.Load(path)
	if err != nil {
		add(report, Check{
			Name:          "config_valid",
			Status:        StatusFail,
			Message:       err.Error(),
			FixSuggestion: "Run providaptctl -config-check and fix the reported configuration error.",
		})
		return nil, false
	}

	add(report, Check{
		Name:    "config_valid",
		Status:  StatusPass,
		Message: "configuration loads and validates",
	})
	return cfg, true
}

func checkCommercialConfig(report *Report, cfg *config.Config) {
	if strings.TrimSpace(cfg.Output.Dir) == "" {
		add(report, Check{
			Name:          "output_dir",
			Status:        StatusFail,
			Message:       "output.dir is empty",
			FixSuggestion: "Set output.dir to a persistent writable directory.",
		})
	} else {
		add(report, Check{
			Name:    "output_dir",
			Status:  StatusPass,
			Message: fmt.Sprintf("output directory configured: %s", cfg.Output.Dir),
		})
	}

	if cfg.SupportBundle.RedactArchives {
		add(report, Check{Name: "support_redaction", Status: StatusPass, Message: "support bundle archive redaction is enabled"})
	} else {
		add(report, Check{
			Name:          "support_redaction",
			Status:        StatusWarn,
			Message:       "support bundle archive redaction is disabled",
			FixSuggestion: "Enable support_bundle.redact_archives for customer-facing support exports unless explicitly waived.",
		})
	}

	if cfg.SupportBundle.RetainArchives > 0 {
		add(report, Check{Name: "support_retention", Status: StatusPass, Message: fmt.Sprintf("retains %d support bundle archives", cfg.SupportBundle.RetainArchives)})
	} else {
		add(report, Check{
			Name:          "support_retention",
			Status:        StatusWarn,
			Message:       "support bundle archive retention is disabled",
			FixSuggestion: "Set support_bundle.retain_archives to a positive value for supportability.",
		})
	}

	if cfg.API.AuthEnabled {
		add(report, Check{Name: "api_auth", Status: StatusPass, Message: "API authentication is enabled"})
	} else {
		add(report, Check{
			Name:          "api_auth",
			Status:        StatusWarn,
			Message:       "API authentication is disabled",
			FixSuggestion: "Enable api.auth_enabled for shared, demo, or customer environments.",
		})
	}

	if hasWildcard(cfg.API.CORSOrigins) {
		add(report, Check{
			Name:          "cors_origins",
			Status:        StatusWarn,
			Message:       "CORS allows all origins",
			FixSuggestion: "Restrict api.cors_origins to the customer console or SOC domains.",
		})
	} else {
		add(report, Check{Name: "cors_origins", Status: StatusPass, Message: "CORS origins are restricted"})
	}

	if cfg.Storage.Encrypt {
		add(report, Check{Name: "storage_encryption", Status: StatusPass, Message: "storage encryption is enabled"})
	} else {
		add(report, Check{
			Name:          "storage_encryption",
			Status:        StatusWarn,
			Message:       "storage encryption is disabled",
			FixSuggestion: "Enable storage.encrypt and configure storage.key_file for customer deployments unless storage encryption is handled below the application layer.",
		})
	}

	if strings.TrimSpace(cfg.License.Path) == "" {
		add(report, Check{
			Name:          "license_path",
			Status:        StatusWarn,
			Message:       "license.path is not configured",
			FixSuggestion: "Set license.path to the release license fixture or customer license before delivery.",
		})
	} else {
		add(report, Check{Name: "license_path", Status: StatusPass, Message: fmt.Sprintf("license path configured: %s", cfg.License.Path)})
	}
}

func checkVersionMetadata(report *Report, version, commit, date string) {
	if isUnset(version, "dev", "") || isUnset(commit, "none", "") || isUnset(date, "unknown", "") {
		add(report, Check{
			Name:          "version_metadata",
			Status:        StatusWarn,
			Message:       fmt.Sprintf("version=%q commit=%q build_date=%q", version, commit, date),
			FixSuggestion: "Build release binaries with version, commit, and build date ldflags populated.",
		})
		return
	}
	add(report, Check{
		Name:    "version_metadata",
		Status:  StatusPass,
		Message: fmt.Sprintf("version=%s commit=%s build_date=%s", version, commit, date),
	})
}

func checkReleaseEvidence(report *Report, path string) {
	if strings.TrimSpace(path) == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		status := StatusWarn
		message := fmt.Sprintf("release evidence file unavailable: %v", err)
		add(report, Check{
			Name:          "release_evidence",
			Status:        status,
			Message:       message,
			FixSuggestion: "Create or provide docs/project/release-evidence-v1.2.2.md before commercial sign-off.",
		})
		return
	}

	text := string(data)
	if strings.Contains(text, "_pending_") || strings.Contains(text, "_fill") {
		add(report, Check{
			Name:          "release_evidence",
			Status:        StatusWarn,
			Message:       "release evidence contains pending placeholders",
			FixSuggestion: "Fill release evidence status, links, commit SHA, build host, and accepted limitations before sign-off.",
		})
		return
	}

	add(report, Check{Name: "release_evidence", Status: StatusPass, Message: "release evidence file has no pending placeholders"})
}

func add(report *Report, check Check) {
	report.Checks = append(report.Checks, check)
	switch check.Status {
	case StatusPass:
		report.Passed++
	case StatusWarn:
		report.Warnings++
	case StatusFail:
		report.Failed++
	}
}

func hasWildcard(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "*" {
			return true
		}
	}
	return false
}

func isUnset(value string, unset ...string) bool {
	trimmed := strings.TrimSpace(value)
	for _, candidate := range unset {
		if trimmed == candidate {
			return true
		}
	}
	return false
}
