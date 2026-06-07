// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package heal

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// ═══════════════════════════════════════════════════════════════
// Firewall integration
// ═══════════════════════════════════════════════════════════════

// FirewallResult summarises the firewall actions taken.
type FirewallResult struct {
	RulesAdded int      `json:"rules_added"`
	IPsBlocked []string `json:"ips_blocked"`
	Errors     []string `json:"errors,omitempty"`
	DryRun     bool     `json:"dry_run"`
	Backend    string   `json:"backend"` // "iptables" or "nftables"
}

// BlockC2IPs extracts C2 IPs from the impact report and blocks them.
// Auto-detects iptables vs nftables.
func BlockC2IPs(report *ImpactReport, dryRun bool) *FirewallResult {
	result := &FirewallResult{DryRun: dryRun}

	if len(report.C2Addresses) == 0 {
		return result
	}

	// Detect firewall backend
	switch {
	case cmdExists("nft"):
		result.Backend = "nftables"
		blockWithNFTables(report, result)
	case cmdExists("iptables"):
		result.Backend = "iptables"
		blockWithIPTables(report, result)
	default:
		result.Errors = append(result.Errors, "no firewall backend found (nft/iptables)")
	}

	return result
}

// blockWithIPTables adds iptables DROP rules for each C2 IP.
func blockWithIPTables(report *ImpactReport, result *FirewallResult) {
	for _, c2 := range report.C2Addresses {
		ip := extractIP(c2.Address)
		if ip == "" {
			continue
		}

		rules := []string{
			fmt.Sprintf("iptables -A OUTPUT -d %s -j DROP", ip),
			fmt.Sprintf("iptables -A INPUT -s %s -j DROP", ip),
			fmt.Sprintf("iptables -A FORWARD -d %s -j DROP", ip),
		}

		for _, rule := range rules {
			if result.DryRun {
				log.Printf("[heal] DRY-RUN: %s", rule)
			} else {
				parts := strings.Split(rule, " ")
				cmd := exec.Command(parts[0], parts[1:]...)
				if output, err := cmd.CombinedOutput(); err != nil {
					result.Errors = append(result.Errors,
						fmt.Sprintf("iptables fail: %v\n%s", err, string(output)))
				}
			}
		}
		result.RulesAdded += len(rules)
		result.IPsBlocked = append(result.IPsBlocked, ip)
		log.Printf("[heal] blocked C2 IP: %s (iptables)", ip)
	}
}

// blockWithNFTables adds nftables drop rules for each C2 IP.
func blockWithNFTables(report *ImpactReport, result *FirewallResult) {
	for _, c2 := range report.C2Addresses {
		ip := extractIP(c2.Address)
		if ip == "" {
			continue
		}

		// Check if the set exists
		checkCmd := exec.Command("nft", "list", "set", "ip", "filter", "providapt_c2")
		if checkCmd.Run() != nil {
			// Create the set
			createCmd := fmt.Sprintf("nft add set ip filter providapt_c2 { type ipv4_addr; }")
			if result.DryRun {
				log.Printf("[heal] DRY-RUN: %s", createCmd)
			} else {
				parts := strings.Split(createCmd, " ")
				if output, err := exec.Command(parts[0], parts[1:]...).CombinedOutput(); err != nil {
					result.Errors = append(result.Errors,
						fmt.Sprintf("nft create set: %v\n%s", err, string(output)))
				}
			}

			// Add rule referencing the set
			ruleCmd := fmt.Sprintf("nft add rule ip filter OUTPUT drop ip daddr @providapt_c2")
			if result.DryRun {
				log.Printf("[heal] DRY-RUN: %s", ruleCmd)
			} else {
				parts := strings.Split(ruleCmd, " ")
				exec.Command(parts[0], parts[1:]...).Run()
			}
		}

		// Add IP to the set
		addCmd := fmt.Sprintf("nft add element ip filter providapt_c2 { %s }", ip)
		if result.DryRun {
			log.Printf("[heal] DRY-RUN: %s", addCmd)
		} else {
			parts := strings.Split(addCmd, " ")
			if output, err := exec.Command(parts[0], parts[1:]...).CombinedOutput(); err != nil {
				result.Errors = append(result.Errors,
					fmt.Sprintf("nft add element: %v\n%s", err, string(output)))
			}
		}

		result.RulesAdded++
		result.IPsBlocked = append(result.IPsBlocked, ip)
		log.Printf("[heal] blocked C2 IP: %s (nftables)", ip)
	}
}

// extractIP attempts to extract an IP address from a network node label.
func extractIP(label string) string {
	// Labels might be "192.168.1.1", "10.0.0.1:443", etc.
	if strings.Contains(label, ":") {
		parts := strings.SplitN(label, ":", 2)
		return parts[0]
	}
	return label
}
