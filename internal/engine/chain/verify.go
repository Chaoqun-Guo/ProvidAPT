// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════
// Integrity verification
// ═══════════════════════════════════════════════════════════════

// VerifyReport is the output of a full integrity check.
type VerifyReport struct {
	TotalRecords    int      `json:"total_records"`
	ChainIntact     bool     `json:"chain_intact"`
	HMACValid       bool     `json:"hmac_valid"`
	Gaps            int      `json:"gaps"`
	Breakpoints     []int64  `json:"breakpoints"`
	FirstRecord     string   `json:"first_hash"`
	LatestRecord    string   `json:"latest_hash"`
	AnchorsFound    int      `json:"anchors_found"`
	AnchorsMatched  int      `json:"anchors_matched"`
	Issues          []string `json:"issues"`
}

// Verify performs a full integrity check on the chain store.
func (cs *ChainStore) Verify() *VerifyReport {
	report := &VerifyReport{}
	cs.mu.Lock()
	defer cs.mu.Unlock()

	report.TotalRecords = len(cs.records)
	if len(cs.records) == 0 {
		report.ChainIntact = true
		report.HMACValid = true
		return report
	}

	report.FirstRecord = cs.records[0].ChainHash
	report.LatestRecord = cs.records[len(cs.records)-1].ChainHash

	// Verify each record
	allHMACValid := true
	for i, rec := range cs.records {
		// Check HMAC
		mac := hmac.New(sha256.New, cs.hmacKey)
		mac.Write([]byte(rec.ChainHash))
		expected := hex.EncodeToString(mac.Sum(nil))
		if rec.HMAC != expected {
			report.Issues = append(report.Issues,
				fmt.Sprintf("record %d: HMAC mismatch", rec.Index))
			allHMACValid = false
		}

		// Check chain hash
		chainInput := fmt.Sprintf("%d:%d:%s:%s", rec.Index, rec.Timestamp, rec.DataHash, rec.PrevHash)
		chainHash := sha256.Sum256([]byte(chainInput))
		if rec.ChainHash != hex.EncodeToString(chainHash[:]) {
			report.Issues = append(report.Issues,
				fmt.Sprintf("record %d: hash mismatch", rec.Index))
		}

		// Check linkage
		if i > 0 && rec.PrevHash != cs.records[i-1].ChainHash {
			report.Gaps++
			report.Breakpoints = append(report.Breakpoints, rec.Index)
			report.Issues = append(report.Issues,
				fmt.Sprintf("gap at record %d: prev_hash mismatch", rec.Index))
		}
	}

	report.ChainIntact = report.Gaps == 0 && len(report.Issues) == 0
	report.HMACValid = allHMACValid

	return report
}

// Summary returns a human-readable verification summary.
func (vr *VerifyReport) Summary() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Chain Integrity Verification\n"))
	b.WriteString(strings.Repeat("=", 40) + "\n")
	b.WriteString(fmt.Sprintf("Records:     %d\n", vr.TotalRecords))
	b.WriteString(fmt.Sprintf("Chain:       %s\n", statusStr(vr.ChainIntact)))
	b.WriteString(fmt.Sprintf("HMAC:        %s\n", statusStr(vr.HMACValid)))
	b.WriteString(fmt.Sprintf("Gaps:        %d\n", vr.Gaps))
	b.WriteString(fmt.Sprintf("First hash:  %s\n", truncate(vr.FirstRecord, 16)))
	b.WriteString(fmt.Sprintf("Latest hash: %s\n", truncate(vr.LatestRecord, 16)))

	if len(vr.Issues) > 0 {
		b.WriteString("\nIssues:\n")
		for _, issue := range vr.Issues {
			b.WriteString(fmt.Sprintf("  ⚠ %s\n", issue))
		}
	}

	if vr.ChainIntact && vr.HMACValid {
		b.WriteString("\n✓ Chain integrity verified — no tampering detected\n")
	} else {
		b.WriteString("\n✗ Tampering detected! Investigate immediately.\n")
	}

	return b.String()
}

func statusStr(ok bool) string {
	if ok {
		return "✓ INTACT"
	}
	return "✗ BROKEN"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
