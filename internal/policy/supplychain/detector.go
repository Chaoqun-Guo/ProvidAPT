// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package supplychain

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Detection pattern IDs for supply-chain threats.
const (
	PatUntrustedInstall  = "SC-001" // curl/wget writes to /usr/bin
	PatTamperedPackage   = "SC-002" // package modified after install
	PatUnsignedPackage   = "SC-003" // package signature verification failed
	PatUnmatchedSBOM     = "SC-004" // binary not found in any SBOM
	PatSuspiciousOrigin  = "SC-005" // written by non-package-manager to system dir
)

// IllegalSourceDetector checks each binary's provenance chain to determine
// whether it was installed through official package management or via
// untrusted channels (curl -> /usr/bin).
type IllegalSourceDetector struct {
	mu              sync.Mutex
	monitor         *PackageManagerMonitor
	sbomStore       *SBOMStore
	alerts          []SupplyChainAlert
	writtenBy       map[string]string        // file path -> writing process comm
	writeTimestamps map[string]time.Time     // file path -> last write time
	bindings        map[string]string        // file path -> package name
	alertCh         chan SupplyChainAlert
}

// NewIllegalSourceDetector creates a supply-chain risk detector.
func NewIllegalSourceDetector(monitor *PackageManagerMonitor, sbomStore *SBOMStore) *IllegalSourceDetector {
	return &IllegalSourceDetector{
		monitor:         monitor,
		sbomStore:       sbomStore,
		writtenBy:       make(map[string]string),
		writeTimestamps: make(map[string]time.Time),
		bindings:        make(map[string]string),
		alertCh:         make(chan SupplyChainAlert, 1024),
	}
}

// AlertChan returns the alert channel.
func (isd *IllegalSourceDetector) AlertChan() <-chan SupplyChainAlert {
	return isd.alertCh
}

// RecordWrite records that a process wrote to a file path.
// This is called for every file_create / file_modify event on system paths.
func (isd *IllegalSourceDetector) RecordWrite(pid uint32, comm string, filePath string) {
	if !IsInWatchedDir(filePath) {
		return
	}

	isd.mu.Lock()
	isd.writtenBy[filePath] = comm
	isd.writeTimestamps[filePath] = time.Now()

	// Check if this is an untrusted write (curl/wget direct to system dir).
	if IsUntrustedWriter(comm) {
		isd.mu.Unlock()
		isd.raiseAlert(SupplyChainAlert{
			ID:            fmt.Sprintf("SC-%d", time.Now().UnixNano()),
			Severity:      "CRITICAL",
			BinaryPath:    filePath,
			SourceProcess: comm,
			Reason:        fmt.Sprintf("非法来源: %s 直接写入系统目录 %s", comm, filePath),
			DetectedAt:    time.Now(),
		})
		return
	}
	isd.mu.Unlock()

	// Check if this is outside a package manager session.
	session := isd.monitor.SessionByPID(pid)
	if session == nil && IsInWatchedDir(filePath) {
		isd.raiseAlert(SupplyChainAlert{
			ID:            fmt.Sprintf("SC-%d", time.Now().UnixNano()),
			Severity:      "MEDIUM",
			BinaryPath:    filePath,
			SourceProcess: comm,
			Reason:        fmt.Sprintf("可疑来源: %s 写入 %s (非包管理器进程)", comm, filePath),
			DetectedAt:    time.Now(),
		})
	}
}

// OnBinaryExecution checks the provenance of a binary before execution.
// Returns a SupplyChainRisk if the binary has a supply-chain issue.
func (isd *IllegalSourceDetector) OnBinaryExecution(filePath string, pid uint32) *SupplyChainRisk {
	if !IsInWatchedDir(filePath) {
		return nil
	}

	var alerts []SupplyChainAlert
	suspectChain := []string{}

	isd.mu.Lock()
	writerComm, hasWriteRecord := isd.writtenBy[filePath]
	pkg := isd.monitor.ResolvePackage(filePath)
	isd.mu.Unlock()

	// ── Check 1: Was the binary written by an untrusted process? ──
	if hasWriteRecord && IsUntrustedWriter(writerComm) {
		alert := SupplyChainAlert{
			ID:            fmt.Sprintf("SC-%d", time.Now().UnixNano()),
			Severity:      "CRITICAL",
			BinaryPath:    filePath,
			SourceProcess: writerComm,
			Reason:        fmt.Sprintf("供应链高风险: %s 由 %s 写入系统目录", filePath, writerComm),
			DetectedAt:    time.Now(),
		}
		alerts = append(alerts, alert)
		suspectChain = append(suspectChain, writerComm)
		isd.raiseAlert(alert)
	}

	// ── Check 2: No package info at all in a system directory ──
	if pkg == nil && !hasWriteRecord {
		// Check if SBOM knows about it.
		entry := isd.sbomStore.ResolveByPath(filePath)
		if entry == nil {
			alert := SupplyChainAlert{
				ID:            fmt.Sprintf("SC-%d", time.Now().UnixNano()),
				Severity:      "MEDIUM",
				BinaryPath:    filePath,
				Reason:        fmt.Sprintf("SBOM 中不存在: %s 未在任何已知软件清单中", filePath),
				DetectedAt:    time.Now(),
			}
			alerts = append(alerts, alert)
			suspectChain = append(suspectChain, "unknown")
			isd.raiseAlert(alert)
		}
	}

	// ── Check 3: Unsigned package ──
	if pkg != nil && !pkg.SigningVerified {
		alert := SupplyChainAlert{
			ID:            fmt.Sprintf("SC-%d", time.Now().UnixNano()),
			Severity:      "CRITICAL",
			BinaryPath:    filePath,
			SourceProcess: pkg.PackageManager,
			PackageInfo:   pkg,
			Reason:        fmt.Sprintf("未签名包: %s %s (签名验证失败)", pkg.Name, pkg.Version),
			DetectedAt:    time.Now(),
		}
		alerts = append(alerts, alert)
		suspectChain = append(suspectChain, "unsigned:"+pkg.PackageManager)
		isd.raiseAlert(alert)
	}

	if len(alerts) == 0 {
		return nil
	}

	return &SupplyChainRisk{
		FilePath:     filePath,
		RiskScore:    calculateRiskScore(alerts),
		RiskLevel:    riskLevel(calculateRiskScore(alerts)),
		PackageInfo:  pkg,
		Alerts:       alerts,
		SuspectChain: suspectChain,
	}
}

// CheckTampered checks whether a known package file has been modified
// since installation by a non-package-manager process.
func (isd *IllegalSourceDetector) CheckTampered(filePath string, packageManager string) *SupplyChainRisk {
	isd.mu.Lock()
	writerComm, hasWriteRecord := isd.writtenBy[filePath]
	writeTime := isd.writeTimestamps[filePath]
	pkg := isd.monitor.ResolvePackage(filePath)
	isd.mu.Unlock()

	if !hasWriteRecord || pkg == nil {
		return nil
	}

	// If the writer is the same package manager that installed it, it's fine.
	// e.g., dpkg re-writing a config file during update.
	if writerComm == packageManager {
		return nil
	}

	// If the writer is in the untrusted list and happened after install -> tampered.
	if IsUntrustedWriter(writerComm) || (IsInWatchedDir(filePath) && !isPackageManagerComm(writerComm)) {
		alert := SupplyChainAlert{
			ID:            fmt.Sprintf("SC-TAMP-%d", time.Now().UnixNano()),
			Severity:      "CRITICAL",
			BinaryPath:    filePath,
			SourceProcess: writerComm,
			PackageInfo:   pkg,
			Reason:        fmt.Sprintf("包被篡改: %s %s 被 %s 修改 (而非包管理器)", pkg.Name, pkg.Version, writerComm),
			DetectedAt:    writeTime,
		}
		isd.raiseAlert(alert)

		return &SupplyChainRisk{
			FilePath:     filePath,
			RiskScore:    70,
			RiskLevel:    "critical",
			PackageInfo:  pkg,
			Alerts:       []SupplyChainAlert{alert},
			SuspectChain: []string{writerComm, "tamper"},
		}
	}

	return nil
}

// raiseAlert sends an alert to both the internal slice and the channel.
func (isd *IllegalSourceDetector) raiseAlert(alert SupplyChainAlert) {
	isd.mu.Lock()
	isd.alerts = append(isd.alerts, alert)
	isd.mu.Unlock()

	// Non-blocking send to channel.
	select {
	case isd.alertCh <- alert:
	default:
	}
}

// Alerts returns all supply-chain alerts.
func (isd *IllegalSourceDetector) Alerts() []SupplyChainAlert {
	isd.mu.Lock()
	defer isd.mu.Unlock()
	out := make([]SupplyChainAlert, len(isd.alerts))
	copy(out, isd.alerts)
	return out
}

// ClearAlerts removes all alerts (for testing/reset).
func (isd *IllegalSourceDetector) ClearAlerts() {
	isd.mu.Lock()
	defer isd.mu.Unlock()
	isd.alerts = nil
}

// Stats returns detector statistics.
func (isd *IllegalSourceDetector) Stats() map[string]interface{} {
	isd.mu.Lock()
	defer isd.mu.Unlock()
	severityCounts := map[string]int{}
	for _, a := range isd.alerts {
		severityCounts[a.Severity]++
	}
	return map[string]interface{}{
		"total_alerts":       len(isd.alerts),
		"tracked_writes":     len(isd.writtenBy),
		"package_bindings":   len(isd.bindings),
		"severity_breakdown": severityCounts,
	}
}

// ─── Helpers ────────────────────────────────────────────────────

func isPackageManagerComm(comm string) bool {
	_, ok := packageManagers[comm]
	return ok
}

func riskLevel(score float64) string {
	switch {
	case score >= 60:
		return "critical"
	case score >= 40:
		return "high"
	case score >= 20:
		return "medium"
	default:
		return "low"
	}
}

func calculateRiskScore(alerts []SupplyChainAlert) float64 {
	var score float64
	for _, a := range alerts {
		switch a.Severity {
		case "CRITICAL":
			score += 60
		case "HIGH":
			score += 40
		case "MEDIUM":
			score += 20
		default:
			score += 5
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

// NodeAttributesForRisk returns node.attrs key-value pairs that should be
// set on a provenance graph node for a given supply-chain risk.
func NodeAttributesForRisk(risk *SupplyChainRisk) map[string]string {
	attrs := make(map[string]string)

	if risk == nil {
		attrs["supply_chain_risk"] = "low"
		return attrs
	}

	attrs["supply_chain_risk"] = risk.RiskLevel

	if risk.PackageInfo != nil {
		attrs["package_name"] = risk.PackageInfo.Name
		attrs["package_version"] = risk.PackageInfo.Version
		attrs["package_manager"] = risk.PackageInfo.PackageManager
		attrs["source_repo"] = risk.PackageInfo.SourceRepo
		if risk.PackageInfo.ArtifactHash != "" {
			attrs["artifact_hash"] = risk.PackageInfo.ArtifactHash
		}
		if risk.PackageInfo.SigningVerified {
			attrs["signing_verified"] = "true"
		} else {
			attrs["signing_verified"] = "false"
		}
	}

	if len(risk.SuspectChain) > 0 {
		attrs["suspect_chain"] = strings.Join(risk.SuspectChain, " -> ")
	}

	return attrs
}

// DescribePath returns a human-readable description of a file's provenance.
func DescribePath(filePath string) string {
	binName := filepath.Base(filePath)
	return fmt.Sprintf("binary=%s path=%s", binName, filePath)
}
