// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package supplychain

import "path/filepath"

// Risk factors and their base scores.
const (
	// RiskFactorUntrustedWriter is assigned when a downloader writes a binary.
	RiskFactorUntrustedWriter = 60.0
	// RiskFactorUnsignedPackage is assigned when package signatures fail.
	RiskFactorUnsignedPackage = 50.0
	// RiskFactorNoSBOM is assigned when a binary is absent from SBOM documents.
	RiskFactorNoSBOM = 30.0
	// RiskFactorTamperedAfterInstall is assigned for post-install tampering.
	RiskFactorTamperedAfterInstall = 70.0
	// RiskFactorUntrustedRepo is assigned for non-official package repositories.
	RiskFactorUntrustedRepo = 40.0
	// RiskFactorKnownVulnerability is assigned for known vulnerable versions.
	RiskFactorKnownVulnerability = 25.0
	// RiskFactorSuspiciousOrigin is assigned for unknown writes to system paths.
	RiskFactorSuspiciousOrigin = 35.0
)

// AssessBinary performs a complete supply-chain risk assessment on a binary.
// It combines signals from the monitor, SBOM store, and tamper detector.
func AssessBinary(
	filePath string,
	monitor *PackageManagerMonitor,
	sbomStore *SBOMStore,
	detector *IllegalSourceDetector,
) *SupplyChainRisk {
	if !IsInWatchedDir(filePath) {
		return &SupplyChainRisk{
			FilePath:  filePath,
			RiskScore: 0,
			RiskLevel: "low",
		}
	}

	var alerts []SupplyChainAlert
	var suspectChain []string
	score := 0.0
	pkg := monitor.ResolvePackage(filePath)

	if pkg == nil {
		entry := sbomStore.ResolveByPath(filePath)
		if entry == nil {
			score += RiskFactorNoSBOM
			alerts = append(alerts, SupplyChainAlert{
				Severity:   "MEDIUM",
				BinaryPath: filePath,
				Reason:     "No record in SBOM or package manager metadata",
			})
			suspectChain = append(suspectChain, "unknown_origin")
		}
	} else {
		if !pkg.SigningVerified {
			score += RiskFactorUnsignedPackage
			alerts = append(alerts, SupplyChainAlert{
				Severity:   "HIGH",
				BinaryPath: filePath,
				Reason:     "Package signature verification failed",
			})
			suspectChain = append(suspectChain, "unsigned:"+pkg.PackageManager)
		}

		if pkg.SourceRepo != "" && pkg.SourceRepo != "official" {
			score += RiskFactorUntrustedRepo
			alerts = append(alerts, SupplyChainAlert{
				Severity:   "HIGH",
				BinaryPath: filePath,
				Reason:     "Package came from non-official repository: " + pkg.SourceRepo,
			})
			suspectChain = append(suspectChain, "untrusted_repo")
		}
	}

	if detector != nil {
		detector.mu.Lock()
		writerComm, hasWriter := detector.writtenBy[filePath]
		detector.mu.Unlock()

		if hasWriter {
			if IsUntrustedWriter(writerComm) {
				score += RiskFactorUntrustedWriter
				alerts = append(alerts, SupplyChainAlert{
					Severity:      "CRITICAL",
					BinaryPath:    filePath,
					SourceProcess: writerComm,
					Reason:        "Written to a system directory by downloader: " + writerComm,
				})
				suspectChain = append(suspectChain, writerComm)
			} else if !isPackageManagerComm(writerComm) {
				score += RiskFactorSuspiciousOrigin
				alerts = append(alerts, SupplyChainAlert{
					Severity:      "MEDIUM",
					BinaryPath:    filePath,
					SourceProcess: writerComm,
					Reason:        "Written by non-package-manager process: " + writerComm,
				})
				suspectChain = append(suspectChain, writerComm)
			}
		}

		tamperRisk := detector.CheckTampered(filePath, "")
		if tamperRisk != nil {
			score += RiskFactorTamperedAfterInstall
			alerts = append(alerts, tamperRisk.Alerts...)
			suspectChain = append(suspectChain, "tampered")
		}
	}

	score = clampScore(score)

	return &SupplyChainRisk{
		FilePath:     filePath,
		RiskScore:    score,
		RiskLevel:    riskLevel(score),
		PackageInfo:  pkg,
		Alerts:       alerts,
		SuspectChain: suspectChain,
	}
}

// BatchAssess performs risk assessment on multiple binary paths.
func BatchAssess(
	paths []string,
	monitor *PackageManagerMonitor,
	sbomStore *SBOMStore,
	detector *IllegalSourceDetector,
) map[string]*SupplyChainRisk {
	results := make(map[string]*SupplyChainRisk, len(paths))
	for _, p := range paths {
		results[p] = AssessBinary(p, monitor, sbomStore, detector)
	}
	return results
}

// SummariseRisks returns a compact summary of all assessed risks.
func SummariseRisks(risks map[string]*SupplyChainRisk) map[string]int {
	summary := map[string]int{
		"total":    0,
		"low":      0,
		"medium":   0,
		"high":     0,
		"critical": 0,
	}
	for _, r := range risks {
		summary["total"]++
		summary[r.RiskLevel]++
	}
	return summary
}

// PathPriority returns a priority score for scanning/assessment order.
// Shared libraries and binaries in standard paths are scanned first.
func PathPriority(filePath string) int {
	dir := filepath.Dir(filePath)
	switch dir {
	case "/usr/bin", "/usr/sbin":
		return 10
	case "/usr/local/bin":
		return 8
	case "/opt":
		return 6
	case "/usr/lib", "/usr/lib64":
		return 7
	default:
		return 1
	}
}

func clampScore(s float64) float64 {
	if s > 100 {
		return 100
	}
	if s < 0 {
		return 0
	}
	return s
}
