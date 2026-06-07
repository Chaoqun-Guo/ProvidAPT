// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package supplychain implements supply-chain provenance tracking for ProvidAPT v2.2.
//
// It provides three capabilities:
//  1. Package manager monitoring — track apt/yum/pip writes to system directories
//  2. SBOM association — import SPDX/CycloneDX and bind package info to graph nodes
//  3. Illegal source detection — flag binaries written by untrusted processes
package supplychain

import "time"

// PackageInfo describes a software package's provenance metadata.
type PackageInfo struct {
	Name            string `json:"name"`             // "nginx", "openssl"
	Version         string `json:"version"`          // "1.24.0-1"
	Architecture    string `json:"architecture"`     // "amd64"
	SourceRepo      string `json:"source_repo"`      // "official", "ppa:deadsnakes", URL
	PackageManager  string `json:"package_manager"`  // "apt", "yum", "pip", "npm"
	SigningKey      string `json:"signing_key"`      // GPG key fingerprint
	SigningVerified bool   `json:"signing_verified"` // signature check result
	ArtifactHash    string `json:"artifact_hash"`    // SHA256 of installed binary
}

// PmSession tracks an active package manager process tree.
type PmSession struct {
	PID       uint32    `json:"pid"`
	Manager   string    `json:"manager"`   // "apt", "dpkg", "pip"
	StartTime time.Time `json:"start_time"`
	ChildPIDs []uint32  `json:"child_pids"` // dpkg sub-processes
	Installed []string  `json:"installed"`  // files written during session
}

// SBOMDocument represents an imported Software Bill of Materials.
type SBOMDocument struct {
	ID        string      `json:"id"`         // "spdx://nginx-1.24.0"
	Format    string      `json:"format"`     // "spdx", "cyclonedx"
	Packages  []SBOMEntry `json:"packages"`
	CreatedAt time.Time   `json:"created_at"`
	Source    string      `json:"source"`     // origin description
}

// SBOMEntry is a single package entry from an SBOM.
type SBOMEntry struct {
	Name       string            `json:"name"`
	Version    string            `json:"version"`
	Supplier   string            `json:"supplier"`   // vendor / organisation
	License    string            `json:"license"`
	Checksums  map[string]string `json:"checksums"`  // algorithm -> hex hash
	Purl       string            `json:"purl"`        // Package URL
	SourceRepo string            `json:"source_repo"`
}

// SupplyChainAlert is raised when a supply-chain risk is detected.
type SupplyChainAlert struct {
	ID            string       `json:"id"`
	Severity      string       `json:"severity"`       // "MEDIUM", "HIGH", "CRITICAL"
	BinaryPath    string       `json:"binary_path"`
	SourceProcess string       `json:"source_process"` // writing process comm
	PackageInfo   *PackageInfo `json:"package_info"`   // nil if untracked
	Reason        string       `json:"reason"`
	DetectedAt    time.Time    `json:"detected_at"`
}

// SupplyChainRisk is the full risk assessment for a binary.
type SupplyChainRisk struct {
	FilePath     string              `json:"file_path"`
	RiskScore    float64             `json:"risk_score"`
	RiskLevel    string              `json:"risk_level"` // "low","medium","high","critical"
	PackageInfo  *PackageInfo        `json:"package_info"`
	Alerts       []SupplyChainAlert  `json:"alerts"`
	SuspectChain []string            `json:"suspect_chain"` // comm chain
}
