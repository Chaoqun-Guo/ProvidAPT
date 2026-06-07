// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package netfinger

import (
	"log"
	"sync"
)

// ═══════════════════════════════════════════════════════════════
// Distributed index — RocksDB fingerprint persistence
// ═══════════════════════════════════════════════════════════════

// FingerprintIndex stores TCP fingerprints with indexing for
// cross-machine stitching at the management center.
//
// RocksDB Key Schema:
//   fp:<flow_id>             → TCPFingerprint JSON
//   idx:fp:src:<ip>:<ts>     → flow_id (reverse index by source IP)
//   idx:fp:dst:<ip>:<ts>     → flow_id (reverse index by dest IP)
type FingerprintIndex struct {
	mu         sync.Mutex
	entries    map[string]*TCPFingerprint // flow_id → fingerprint
	srcIndex   map[string][]string        // src_ip → flow_ids
	dstIndex   map[string][]string        // dst_ip → flow_ids
}

// NewFingerprintIndex creates a distributed index.
func NewFingerprintIndex() *FingerprintIndex {
	return &FingerprintIndex{
		entries:  make(map[string]*TCPFingerprint),
		srcIndex: make(map[string][]string),
		dstIndex: make(map[string][]string),
	}
}

// Store persists a fingerprint to the index.
// In production, this writes to RocksDB under the "fp:" prefix.
func (fi *FingerprintIndex) Store(fp *TCPFingerprint) error {
	fi.mu.Lock()
	defer fi.mu.Unlock()

	fi.entries[fp.FlowID] = fp
	fi.srcIndex[fp.SrcIP] = append(fi.srcIndex[fp.SrcIP], fp.FlowID)
	fi.dstIndex[fp.DstIP] = append(fi.dstIndex[fp.DstIP], fp.FlowID)

	log.Printf("[index] stored fingerprint %s (%s → %s)", fp.FlowID[:16], fp.SrcIP, fp.DstIP)
	return nil
}

// GetByFlowID retrieves a fingerprint by its flow ID.
func (fi *FingerprintIndex) GetByFlowID(flowID string) *TCPFingerprint {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	return fi.entries[flowID]
}

// GetBySrcIP returns all fingerprints from a source IP.
func (fi *FingerprintIndex) GetBySrcIP(ip string) []*TCPFingerprint {
	fi.mu.Lock()
	defer fi.mu.Unlock()

	flowIDs := fi.srcIndex[ip]
	out := make([]*TCPFingerprint, 0, len(flowIDs))
	for _, fid := range flowIDs {
		if fp, ok := fi.entries[fid]; ok {
			out = append(out, fp)
		}
	}
	return out
}

// GetByDstIP returns all fingerprints to a destination IP.
func (fi *FingerprintIndex) GetByDstIP(ip string) []*TCPFingerprint {
	fi.mu.Lock()
	defer fi.mu.Unlock()

	flowIDs := fi.dstIndex[ip]
	out := make([]*TCPFingerprint, 0, len(flowIDs))
	for _, fid := range flowIDs {
		if fp, ok := fi.entries[fid]; ok {
			out = append(out, fp)
		}
	}
	return out
}

// StitchByFlowID attempts to match an outbound fingerprint with an
// inbound one from a different agent.  In production, this is done
// at the management center by querying the global RocksDB.
func (fi *FingerprintIndex) StitchByFlowID(localAgentID string, fp *TCPFingerprint) string {
	// Look for a matching fingerprint with reversed src/dst
	reverseID := FlowID(fp.DstIP, fp.DstPort, fp.SrcIP, fp.SrcPort, 6, fp.ISN, fp.Timestamp)

	fi.mu.Lock()
	remote, ok := fi.entries[reverseID]
	fi.mu.Unlock()

	if ok && remote != nil {
		log.Printf("[stitch] matched flow %s: %s → %s", fp.FlowID[:16], localAgentID, fp.DstIP)
		return remote.FlowID
	}
	return ""
}

// Count returns the number of stored fingerprints.
func (fi *FingerprintIndex) Count() int {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	return len(fi.entries)
}
