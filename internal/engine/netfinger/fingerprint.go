// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package netfinger implements TCP fingerprinting for ProvidAPT v2.1.
//
// Extracts TCP initial sequence numbers (ISN) and timestamp options
// from eBPF hooks at tcp_v4_connect and tcp_v4_do_rcv, and generates
// unique flow identifiers for cross-machine connection stitching.
package netfinger

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// TCP fingerprint
// ═══════════════════════════════════════════════════════════════

// TCPFingerprint uniquely identifies a TCP connection across machines.
type TCPFingerprint struct {
	// Flow key (5-tuple)
	SrcIP   string `json:"src_ip"`
	SrcPort uint32 `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort uint32 `json:"dst_port"`
	Protocol uint32 `json:"protocol"` // 6=TCP

	// Fingerprint fields (from eBPF)
	ISN         uint32 `json:"isn"`          // Initial Sequence Number
	Timestamp   uint32 `json:"timestamp"`    // TCP TSval from SYN
	TimestampECR uint32 `json:"timestamp_ecr"` // TSecr from SYN-ACK

	// Derived
	FlowID    string `json:"flow_id"`    // SHA256 of (5-tuple + ISN + TS)
	CreatedAt time.Time `json:"created_at"`
}

// FlowID computes a unique identifier for a TCP flow.
// This is used for cross-machine stitching: if machine A's curl connects
// to machine B's sshd, both will observe the same ISN and timestamp,
// producing the same FlowID.
func FlowID(srcIP string, srcPort uint32, dstIP string, dstPort uint32,
	protocol uint32, isn uint32, ts uint32) string {

	input := fmt.Sprintf("%s:%d-%s:%d-%d-%d-%d",
		srcIP, srcPort, dstIP, dstPort, protocol, isn, ts)
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])[:32] // 32 hex chars
}

// NewFingerprint creates a TCP fingerprint from observed values.
func NewFingerprint(srcIP string, srcPort uint32, dstIP string, dstPort uint32,
	isn uint32, ts uint32, tsECR uint32) *TCPFingerprint {

	fp := &TCPFingerprint{
		SrcIP:        srcIP,
		SrcPort:      srcPort,
		DstIP:        dstIP,
		DstPort:      dstPort,
		Protocol:     6,
		ISN:          isn,
		Timestamp:    ts,
		TimestampECR: tsECR,
		CreatedAt:    time.Now(),
	}
	fp.FlowID = FlowID(srcIP, srcPort, dstIP, dstPort, 6, isn, ts)
	return fp
}

// String returns a human-readable fingerprint summary.
func (fp *TCPFingerprint) String() string {
	return fmt.Sprintf("[TCP] %s:%d → %s:%d | ISN=%d TS=%d | FlowID=%s",
		fp.SrcIP, fp.SrcPort, fp.DstIP, fp.DstPort,
		fp.ISN, fp.Timestamp, fp.FlowID[:16])
}

// ═══════════════════════════════════════════════════════════════
// Fingerprint store (in-memory)
// ═══════════════════════════════════════════════════════════════

// FingerprintStore maintains TCP fingerprints for stitching.
type FingerprintStore struct {
	mu        sync.Mutex
	outbound  map[string]*TCPFingerprint // FlowID → fingerprint (outgoing)
	inbound   map[string]*TCPFingerprint // FlowID → fingerprint (incoming)
	matched   []*StitchedFlow
}

// StitchedFlow represents a cross-machine connection.
type StitchedFlow struct {
	FlowID       string `json:"flow_id"`
	Outbound     *TCPFingerprint `json:"outbound,omitempty"` // client side
	Inbound      *TCPFingerprint `json:"inbound,omitempty"`  // server side
	MatchedAt    time.Time `json:"matched_at"`
	MachineA     string `json:"machine_a,omitempty"`
	MachineB     string `json:"machine_b,omitempty"`
}

// NewFingerprintStore creates a fingerprint store.
func NewFingerprintStore() *FingerprintStore {
	return &FingerprintStore{
		outbound: make(map[string]*TCPFingerprint),
		inbound:  make(map[string]*TCPFingerprint),
	}
}

// RecordOutbound records an outgoing connection fingerprint.
// Called by the eBPF hook at tcp_v4_connect.
func (fs *FingerprintStore) RecordOutbound(fp *TCPFingerprint, agentID string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.outbound[fp.FlowID] = fp
	log.Printf("[finger] OUT %s (agent=%s)", fp, agentID)

	// Check if we already have a matching inbound
	if inbound, ok := fs.inbound[fp.FlowID]; ok {
		stitch := &StitchedFlow{
			FlowID:    fp.FlowID,
			Outbound:  fp,
			Inbound:   inbound,
			MatchedAt: time.Now(),
			MachineA:  agentID,
			MachineB:  "remote",
		}
		fs.matched = append(fs.matched, stitch)
		log.Printf("[finger] STITCHED %s (outbound %s → inbound remote)", fp.FlowID[:16], fp.DstIP)
	}
}

// RecordInbound records an incoming connection fingerprint.
// Called by the eBPF hook at tcp_v4_do_rcv.
func (fs *FingerprintStore) RecordInbound(fp *TCPFingerprint, agentID string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.inbound[fp.FlowID] = fp
	log.Printf("[finger] IN %s (agent=%s)", fp, agentID)

	// Check if we already have a matching outbound
	if outbound, ok := fs.outbound[fp.FlowID]; ok {
		stitch := &StitchedFlow{
			FlowID:    fp.FlowID,
			Outbound:  outbound,
			Inbound:   fp,
			MatchedAt: time.Now(),
			MachineA:  "remote",
			MachineB:  agentID,
		}
		fs.matched = append(fs.matched, stitch)
		log.Printf("[finger] STITCHED %s (remote → inbound %s)", fp.FlowID[:16], fp.SrcIP)
	}
}

// StitchedFlows returns all cross-machine stitched connections.
func (fs *FingerprintStore) StitchedFlows() []*StitchedFlow {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	out := make([]*StitchedFlow, len(fs.matched))
	copy(out, fs.matched)
	return out
}

// Stats returns fingerprint store statistics.
func (fs *FingerprintStore) Stats() map[string]interface{} {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return map[string]interface{}{
		"outbound_fingerprints": len(fs.outbound),
		"inbound_fingerprints":  len(fs.inbound),
		"stitched_flows":        len(fs.matched),
	}
}
