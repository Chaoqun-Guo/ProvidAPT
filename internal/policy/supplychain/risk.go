package supplychain

import "path/filepath"

// Risk factors and their base scores.
const (
	// RiskFactorUntrustedWriter — binary written by curl/wget/other downloader.
	RiskFactorUntrustedWriter = 60.0
	// RiskFactorUnsignedPackage — package not cryptographically signed.
	RiskFactorUnsignedPackage = 50.0
	// RiskFactorNoSBOM — binary not found in any SBOM document.
	RiskFactorNoSBOM = 30.0
	// RiskFactorTamperedAfterInstall — package modified by non-pm process.
	RiskFactorTamperedAfterInstall = 70.0
	// RiskFactorUntrustedRepo — package from non-official repository.
	RiskFactorUntrustedRepo = 40.0
	// RiskFactorKnownVulnerability — well-known CVE in package version.
	RiskFactorKnownVulnerability = 25.0
	// RiskFactorSuspiciousOrigin — written to system dir by unknown process.
	RiskFactorSuspiciousOrigin = 35.0
)

// AssessBinary performs a complete supply-chain risk assessment on a binary.
// It combines signals from the monitor (package info), SBOM store (known
// artifacts), and detector (tamper/untrusted checks).
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

	// 1. Check if binary is known via package manager.
	if pkg == nil {
		// Not from any package manager.
		entry := sbomStore.ResolveByPath(filePath)
		if entry == nil {
			score += RiskFactorNoSBOM
			alerts = append(alerts, SupplyChainAlert{
				Severity:   "MEDIUM",
				BinaryPath: filePath,
				Reason:     "SBOM 及包管理器均无记录",
			})
			suspectChain = append(suspectChain, "unknown_origin")
		}
	} else {
		// From a package manager — check signature.
		if !pkg.SigningVerified {
			score += RiskFactorUnsignedPackage
			alerts = append(alerts, SupplyChainAlert{
				Severity:   "HIGH",
				BinaryPath: filePath,
				Reason:     "包签名验证失败",
			})
			suspectChain = append(suspectChain, "unsigned:"+pkg.PackageManager)
		}

		// Check for non-official repo.
		if pkg.SourceRepo != "" && pkg.SourceRepo != "official" {
			score += RiskFactorUntrustedRepo
			alerts = append(alerts, SupplyChainAlert{
				Severity:   "HIGH",
				BinaryPath: filePath,
				Reason:     "来自非官方仓库: " + pkg.SourceRepo,
			})
			suspectChain = append(suspectChain, "untrusted_repo")
		}
	}

	// 2. Check the write record.
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
					Reason:        "由下载工具写入系统目录: " + writerComm,
				})
				suspectChain = append(suspectChain, writerComm)
			} else if !isPackageManagerComm(writerComm) {
				score += RiskFactorSuspiciousOrigin
				alerts = append(alerts, SupplyChainAlert{
					Severity:      "MEDIUM",
					BinaryPath:    filePath,
					SourceProcess: writerComm,
					Reason:        "由非包管理器进程写入: " + writerComm,
				})
				suspectChain = append(suspectChain, writerComm)
			}
		}
	}

	// 3. Check for tampering after install.
	tamperRisk := detector.CheckTampered(filePath, "")
	if tamperRisk != nil {
		score += RiskFactorTamperedAfterInstall
		alerts = append(alerts, tamperRisk.Alerts...)
		suspectChain = append(suspectChain, "tampered")
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
		"total":   0,
		"low":     0,
		"medium":  0,
		"high":    0,
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
	switch {
	case dir == "/usr/bin" || dir == "/usr/sbin":
		return 10
	case dir == "/usr/local/bin":
		return 8
	case dir == "/opt":
		return 6
	case dir == "/usr/lib" || dir == "/usr/lib64":
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
