// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package hwaccel provides hardware acceleration interfaces for
// ProvidAPT in large-scale data centre deployments.
//
// It supports:
//  1. SmartNIC offloading — move socket-level provenance to the NIC
//  2. GPU graph clustering — parallel analysis of large provenance graphs
//  3. NVMe optimisation — RocksDB tuning for NVMe storage
package hwaccel

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// ═══════════════════════════════════════════════════════════════
// SmartNIC offloading
// ═══════════════════════════════════════════════════════════════

// SmartNICInfo describes a detected SmartNIC.
type SmartNICInfo struct {
	Present    bool     `json:"present"`
	Driver     string   `json:"driver"`
	Model      string   `json:"model"`
	BPFSupport bool     `json:"bpf_support"`
	Interfaces []string `json:"interfaces"`
}

// SmartNICConfig controls which events to offload.
type SmartNICConfig struct {
	// OffloadSocketEvents — if true, socket events are captured on the NIC.
	OffloadSocketEvents bool

	// OffloadNetworkEvents — if true, all network events use NIC.
	OffloadNetworkEvents bool

	// NicInterface — specific NIC interface to use.
	NicInterface string
}

// DetectSmartNIC probes for SmartNIC capabilities.
func DetectSmartNIC() *SmartNICInfo {
	info := &SmartNICInfo{}

	// Check for Netronome/Bluefield via PCI vendor IDs
	pciDevices, err := os.ReadDir("/sys/bus/pci/devices")
	if err != nil {
		return info
	}

	for _, dev := range pciDevices {
		vendorPath := fmt.Sprintf("/sys/bus/pci/devices/%s/vendor", dev.Name())
		vendorData, err := os.ReadFile(vendorPath)
		if err != nil {
			continue
		}
		vendor := strings.TrimSpace(string(vendorData))

		// Netronome (0x19ee) or NVIDIA BlueField (0x15b3)
		if vendor == "0x19ee" || vendor == "0x15b3" {
			info.Present = true
			if vendor == "0x19ee" {
				info.Driver = "nfp"
				info.Model = "Netronome Agilio"
			} else {
				info.Driver = "mlx5"
				info.Model = "NVIDIA BlueField"
			}
			info.BPFSupport = true
			info.Interfaces = append(info.Interfaces, dev.Name())
		}
	}

	if info.Present {
		log.Printf("[hwaccel] SmartNIC detected: %s (%s, bpf=%v)",
			info.Model, info.Driver, info.BPFSupport)
	} else {
		log.Printf("[hwaccel] no SmartNIC detected, using software mode")
	}

	return info
}

// OffloadConfig returns the configuration for offloading to the NIC.
func OffloadConfig(nic *SmartNICInfo) *SmartNICConfig {
	cfg := &SmartNICConfig{
		OffloadSocketEvents:  nic.BPFSupport,
		OffloadNetworkEvents: nic.Present,
	}
	if len(nic.Interfaces) > 0 {
		cfg.NicInterface = nic.Interfaces[0]
	}
	return cfg
}

// ApplyOffload applies the SmartNIC offload configuration.
// In production, this would use tools like:
//   - nfp-net for Netronome
//   - mlxconfig for Mellanox/NVIDIA
//   - bpftool to load eBPF programs onto the NIC
func ApplyOffload(cfg *SmartNICConfig) error {
	if cfg == nil || !cfg.OffloadSocketEvents {
		return nil
	}

	if cfg.NicInterface == "" {
		return fmt.Errorf("no NIC interface specified")
	}

	// Check for offload tools
	tools := []string{"ethtool", "bpftool"}
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("%s not found: %w", tool, err)
		}
	}

	// Enable hardware offload features (simplified — real deployment
	// would use the vendor-specific toolchain)
	iface := cfg.NicInterface
	cmds := []string{
		fmt.Sprintf("ethtool -K %s gro on gso on tso on", iface),
		fmt.Sprintf("ethtool -K %s ntuple on", iface),
	}

	for _, cmd := range cmds {
		parts := strings.Split(cmd, " ")
		if err := exec.Command(parts[0], parts[1:]...).Run(); err != nil {
			log.Printf("[hwaccel] offload cmd warning: %v", err)
		}
	}

	log.Printf("[hwaccel] SmartNIC offload applied to %s", iface)
	return nil
}

// IsAvailable returns true if SmartNIC offloading is configured.
func IsAvailable(nicInfo *SmartNICInfo) bool {
	return nicInfo != nil && nicInfo.Present && nicInfo.BPFSupport
}
