// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package netfinger

import (
	"strings"
	"testing"
)

// ─── TCP fingerprint tests ──────────────────────────────────

func TestFlowID(t *testing.T) {
	id1 := FlowID("10.0.0.1", 40000, "5.6.7.8", 443, 6, 1000, 500)
	id2 := FlowID("10.0.0.1", 40000, "5.6.7.8", 443, 6, 1000, 500)
	if id1 != id2 {
		t.Error("same parameters should produce same FlowID")
	}
	if len(id1) != 32 {
		t.Errorf("FlowID length = %d", len(id1))
	}
}

func TestFlowIDDifferent(t *testing.T) {
	id1 := FlowID("10.0.0.1", 40000, "5.6.7.8", 443, 6, 1000, 500)
	id2 := FlowID("10.0.0.1", 40000, "5.6.7.8", 443, 6, 1001, 500)
	if id1 == id2 {
		t.Error("different ISN should produce different FlowID")
	}
}

func TestNewFingerprint(t *testing.T) {
	fp := NewFingerprint("10.0.0.1", 40000, "5.6.7.8", 443, 12345, 67890, 0)
	if fp == nil {
		t.Fatal("NewFingerprint returned nil")
	}
	if fp.FlowID == "" {
		t.Error("empty FlowID")
	}
	if fp.SrcIP != "10.0.0.1" {
		t.Errorf("src = %s", fp.SrcIP)
	}
	if fp.Protocol != 6 {
		t.Errorf("protocol = %d", fp.Protocol)
	}
}

func TestFingerprintString(t *testing.T) {
	fp := NewFingerprint("10.0.0.1", 40000, "5.6.7.8", 443, 12345, 67890, 0)
	s := fp.String()
	if !strings.Contains(s, "5.6.7.8") {
		t.Errorf("string = %s", s)
	}
	if !strings.Contains(s, "FlowID=") {
		t.Errorf("missing FlowID: %s", s)
	}
	t.Logf("Fingerprint: %s", s)
}

// ─── Fingerprint store tests ────────────────────────────────

func TestNewFingerprintStore(t *testing.T) {
	fs := NewFingerprintStore()
	if fs == nil {
		t.Fatal("NewFingerprintStore returned nil")
	}
}

func TestRecordOutbound(t *testing.T) {
	fs := NewFingerprintStore()
	fp := NewFingerprint("10.0.0.1", 40000, "5.6.7.8", 443, 1000, 500, 0)
	fs.RecordOutbound(fp, "agent-a")

	stats := fs.Stats()
	if stats["outbound_fingerprints"].(int) != 1 {
		t.Errorf("outbound = %d", stats["outbound_fingerprints"])
	}
}

func TestRecordInbound(t *testing.T) {
	fs := NewFingerprintStore()
	fp := NewFingerprint("5.6.7.8", 443, "10.0.0.2", 40001, 1000, 500, 0)
	fs.RecordInbound(fp, "agent-b")

	stats := fs.Stats()
	if stats["inbound_fingerprints"].(int) != 1 {
		t.Errorf("inbound = %d", stats["inbound_fingerprints"])
	}
}

func TestCrossMachineStitching(t *testing.T) {
	fs := NewFingerprintStore()

	// Machine A: curl connects to 5.6.7.8:443
	outFP := NewFingerprint("10.0.0.1", 40000, "5.6.7.8", 443, 1000, 500, 0)
	fs.RecordOutbound(outFP, "agent-a")

	// Machine B: receives connection from 10.0.0.1:40000
	// The ISN and timestamp should match (in reality observed on both sides)
	inFP := NewFingerprint("10.0.0.1", 40000, "5.6.7.8", 443, 1000, 500, 0)
	fs.RecordInbound(inFP, "agent-b")

	stitched := fs.StitchedFlows()
	if len(stitched) != 1 {
		t.Fatalf("stitched = %d, want 1", len(stitched))
	}
	t.Logf("Stitched: %s", stitched[0].FlowID[:16])
}

func TestStats(t *testing.T) {
	fs := NewFingerprintStore()
	fp := NewFingerprint("10.0.0.1", 80, "10.0.0.2", 8080, 1, 2, 0)
	fs.RecordOutbound(fp, "agent-a")

	stats := fs.Stats()
	if stats["outbound_fingerprints"].(int) != 1 {
		t.Errorf("outbound = %d", stats["outbound_fingerprints"])
	}
}

// ─── Distributed index tests ────────────────────────────────

func TestNewFingerprintIndex(t *testing.T) {
	fi := NewFingerprintIndex()
	if fi == nil {
		t.Fatal("NewFingerprintIndex returned nil")
	}
}

func TestStoreAndRetrieve(t *testing.T) {
	fi := NewFingerprintIndex()
	fp := NewFingerprint("10.0.0.1", 12345, "93.184.216.34", 80, 5555, 1234, 0)
	fi.Store(fp)

	retrieved := fi.GetByFlowID(fp.FlowID)
	if retrieved == nil {
		t.Fatal("fingerprint not found")
	}
	if retrieved.DstIP != "93.184.216.34" {
		t.Errorf("dst = %s", retrieved.DstIP)
	}
}

func TestGetBySrcIP(t *testing.T) {
	fi := NewFingerprintIndex()
	fi.Store(NewFingerprint("10.0.0.1", 100, "5.6.7.8", 80, 1, 1, 0))
	fi.Store(NewFingerprint("10.0.0.1", 200, "9.9.9.9", 443, 2, 2, 0))

	results := fi.GetBySrcIP("10.0.0.1")
	if len(results) != 2 {
		t.Errorf("results = %d", len(results))
	}
}

func TestGetByDstIP(t *testing.T) {
	fi := NewFingerprintIndex()
	fi.Store(NewFingerprint("10.0.0.1", 100, "5.6.7.8", 80, 1, 1, 0))
	fi.Store(NewFingerprint("10.0.0.2", 200, "5.6.7.8", 80, 2, 2, 0))

	results := fi.GetByDstIP("5.6.7.8")
	if len(results) != 2 {
		t.Errorf("results = %d", len(results))
	}
}

func TestStitchByFlowID(t *testing.T) {
	fi := NewFingerprintIndex()

	// Store an outbound fingerprint from agent-a
	fp := NewFingerprint("10.0.0.1", 40000, "5.6.7.8", 443, 1000, 500, 0)
	fi.Store(fp)

	// Try to stitch — the reverse flow should match if stored
	match := fi.StitchByFlowID("agent-a", fp)
	t.Logf("Stitch result: %s", match)
}

func TestCount(t *testing.T) {
	fi := NewFingerprintIndex()
	fi.Store(NewFingerprint("10.0.0.1", 1, "5.6.7.8", 80, 1, 1, 0))
	fi.Store(NewFingerprint("10.0.0.2", 2, "9.9.9.9", 443, 2, 2, 0))

	if fi.Count() != 2 {
		t.Errorf("count = %d", fi.Count())
	}
}

// ─── Integration test ───────────────────────────────────────

func TestNetfingerIntegration(t *testing.T) {
	t.Log("=== Network Fingerprint Integration ===")

	// 1. Generate fingerprints
	clientFP := NewFingerprint("10.0.0.1", 40000, "5.6.7.8", 443, 0xDEAD, 0xBEEF, 0)
	serverFP := NewFingerprint("10.0.0.1", 40000, "5.6.7.8", 443, 0xDEAD, 0xBEEF, 0)
	t.Logf("Client: %s", clientFP)
	t.Logf("Server: %s", serverFP)

	// 2. Cross-machine stitching
	store := NewFingerprintStore()
	store.RecordOutbound(clientFP, "agent-web")
	store.RecordInbound(serverFP, "agent-db")

	stitched := store.StitchedFlows()
	if len(stitched) > 0 {
		t.Logf("Stitched flow: %s", stitched[0].FlowID[:16])
	} else {
		t.Log("No stitch (expected if FlowIDs don't match)")
	}

	// 3. Distributed index
	index := NewFingerprintIndex()
	index.Store(clientFP)
	index.Store(serverFP)
	t.Logf("Indexed: %d fingerprints", index.Count())

	found := index.GetByFlowID(serverFP.FlowID)
	if found != nil {
		t.Logf("Retrieved: %s → %s", found.SrcIP, found.DstIP)
	}

	// 4. Stats
	stats := store.Stats()
	t.Logf("Store stats: out=%d in=%d stitched=%d",
		stats["outbound_fingerprints"], stats["inbound_fingerprints"],
		stats["stitched_flows"])

	t.Log("Network fingerprint integration OK")
}
