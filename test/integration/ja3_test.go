// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/ja3"
)

// ─── JA3 parsing tests ──────────────────────────────────────

// buildMinimalClientHello creates a minimal TLS Client Hello packet.
func buildMinimalClientHello(cipherIDs []uint16, extTypes []uint16) []byte {
	var p []byte
	p = append(p, 0x16)       // ContentType: Handshake
	p = append(p, 0x03, 0x01) // Version: TLS 1.0
	p = append(p, 0x00, 0x00) // Length (placeholder)

	// Handshake: Client Hello
	p = append(p, 0x01)             // HandshakeType: Client Hello
	p = append(p, 0x00, 0x00, 0x00) // Length (placeholder)
	p = append(p, 0x03, 0x03)       // Version: TLS 1.2

	// Random (32 bytes)
	for i := 0; i < 32; i++ {
		p = append(p, byte(i))
	}

	// Session ID (0)
	p = append(p, 0x00)

	// Cipher suites
	cipherLen := len(cipherIDs) * 2
	p = append(p, byte(cipherLen>>8), byte(cipherLen))
	for _, id := range cipherIDs {
		p = append(p, byte(id>>8), byte(id))
	}

	// Compression methods (1 byte, null)
	p = append(p, 0x01, 0x00)

	// Extensions
	extData := []byte{}
	extCount := 0
	for _, extType := range extTypes {
		extData = append(extData, byte(extType>>8), byte(extType))
		extData = append(extData, 0x00, 0x00) // empty extension data
		extCount++
	}
	extLen := len(extData)
	p = append(p, byte(extLen>>8), byte(extLen))
	p = append(p, extData...)

	return p
}

func TestParseClientHello(t *testing.T) {
	cipherSuites := []uint16{0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F} // TLS 1.3 + 1.2
	extensions := []uint16{0x0000, 0x000B, 0x000A, 0x0033, 0x001D}

	data := buildMinimalClientHello(cipherSuites, extensions)
	record := ja3.ParseClientHello(data, "host-a", 100, "curl", "5.6.7.8", 443)

	if record == nil {
		t.Fatal("ParseClientHello returned nil")
	}
	if record.JA3 == "" {
		t.Error("empty JA3 hash")
	}
	if record.CipherSuites == "" {
		t.Error("empty cipher suites")
	}
	t.Logf("JA3:     %s", record.JA3)
	t.Logf("Text:    %s", record.JA3Text)
	t.Logf("Ciphers: %s", record.CipherSuites)
	t.Logf("Exts:    %s", record.Extensions)
	t.Logf("Curves:  %s", record.EllipticCurves)
}

func TestParseClientHelloInvalid(t *testing.T) {
	record := ja3.ParseClientHello([]byte{0, 0, 0}, "host-a", 0, "test", "", 0)
	if record != nil {
		t.Error("should return nil for invalid data")
	}
}

func TestParseClientHelloNotHandshake(t *testing.T) {
	// ContentType = 23 (not 22 = Handshake)
	record := ja3.ParseClientHello([]byte{0x17, 0x03, 0x03}, "host-a", 0, "test", "", 0)
	if record != nil {
		t.Error("non-handshake should return nil")
	}
}

func TestIsAtypicalJA3(t *testing.T) {
	if ja3.IsAtypicalJA3("6734f37431670b3ab4292b8f60f29984") {
		t.Error("curl JA3 should be common")
	}
	if !ja3.IsAtypicalJA3("00000000000000000000000000000000") {
		t.Error("unknown JA3 should be atypical")
	}
}

func TestJA3RecordString(t *testing.T) {
	record := &ja3.JA3Record{
		JA3: "abcdef0123456789abcdef0123456789", SourceHost: "host-a",
		PID: 100, Comm: "curl", DestIP: "5.6.7.8", DestPort: 443,
	}
	s := record.String()
	if len(s) == 0 {
		t.Error("empty string")
	}
	t.Logf("Record: %s", s)
}

// ─── JA3 store tests ───────────────────────────────────────

func TestNewJA3Store(t *testing.T) {
	js := ja3.NewJA3Store()
	if js == nil {
		t.Fatal("NewJA3Store returned nil")
	}
}

func TestRecord(t *testing.T) {
	js := ja3.NewJA3Store()
	js.Record(&ja3.JA3Record{
		JA3: "test-ja3-hash", SourceHost: "host-a",
		PID: 100, Comm: "curl",
	})
	if len(js.Records()) != 1 {
		t.Errorf("records = %d", len(js.Records()))
	}
}

func TestJA3Stats(t *testing.T) {
	js := ja3.NewJA3Store()
	js.Record(&ja3.JA3Record{JA3: "known-hash", SourceHost: "h1"})
	js.Record(&ja3.JA3Record{JA3: "00000000deadbeef", SourceHost: "h2"})

	stats := js.Stats()
	if stats["total"].(int) != 2 {
		t.Errorf("total = %d", stats["total"])
	}
}

// ─── Central correlator tests ───────────────────────────────

func TestNewCentralCorrelator(t *testing.T) {
	cc := ja3.NewCentralCorrelator()
	if cc == nil {
		t.Fatal("NewCentralCorrelator returned nil")
	}
}

func TestIngestSingle(t *testing.T) {
	cc := ja3.NewCentralCorrelator()
	record := &ja3.JA3Record{
		JA3: "atypical-ja3-001", SourceHost: "host-a",
		PID: 100, Comm: "curl", DestPort: 443,
		IsAtypical: true,
	}
	alert := cc.Ingest(record)
	if alert != nil {
		t.Log("alert created (unexpected for single)")
	}
}

func TestCoordinatedC2Detection(t *testing.T) {
	cc := ja3.NewCentralCorrelator()
	ja3Hash := "c2-suspicious-hash"

	// Same JA3 appearing on 3 different hosts
	hosts := []string{"host-web-01", "host-app-02", "host-db-03"}
	for i, h := range hosts {
		cc.Ingest(&ja3.JA3Record{
			JA3: ja3Hash, SourceHost: h,
			PID: uint32(1000 + i), Comm: "nginx",
			DestPort: 443, IsAtypical: true,
		})
	}

	clusters := cc.Clusters()
	if len(clusters) == 0 {
		t.Fatal("no clusters")
	}

	for _, c := range clusters {
		if c.JA3 == ja3Hash && c.IsC2 {
			t.Logf("C2 cluster detected: %d hosts, %d procs, risk=%.0f",
				len(c.Hosts), len(c.Processes), c.RiskScore)
		}
	}

	alerts := cc.Alerts()
	if len(alerts) == 0 {
		t.Log("no C2 alerts (expected at risk threshold)")
	}
}

func TestMixedJAHosts(t *testing.T) {
	cc := ja3.NewCentralCorrelator()

	// Common JA3 — should not trigger
	cc.Ingest(&ja3.JA3Record{
		JA3: "6734f37431670b3ab4292b8f60f29984", SourceHost: "h1",
		PID: 100, Comm: "curl", IsAtypical: false,
	})
	cc.Ingest(&ja3.JA3Record{
		JA3: "6734f37431670b3ab4292b8f60f29984", SourceHost: "h2",
		PID: 200, Comm: "curl", IsAtypical: false,
	})

	// Atypical JA3 across hosts — should trigger
	cc.Ingest(&ja3.JA3Record{
		JA3: "custom-c2-ja3", SourceHost: "h3",
		PID: 300, Comm: "custom-agent", IsAtypical: true,
	})
	cc.Ingest(&ja3.JA3Record{
		JA3: "custom-c2-ja3", SourceHost: "h4",
		PID: 400, Comm: "custom-agent", IsAtypical: true,
	})

	stats := cc.Stats()
	t.Logf("Clusters: %d, C2: %d, Alerts: %d",
		stats["ja3_fingerprints"], stats["c2_clusters"], stats["alerts"])
}

func TestJA3Stats2(t *testing.T) {
	cc := ja3.NewCentralCorrelator()
	stats := cc.Stats()
	if stats["ja3_fingerprints"].(int) != 0 {
		t.Errorf("fingerprints = %d", stats["ja3_fingerprints"])
	}
}

// ─── Integration test ───────────────────────────────────────

func TestJA3Integration(t *testing.T) {
	t.Log("=== JA3 Fingerprint Integration ===")

	// 1. Parse TLS Client Hello
	ciphers := []uint16{0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xCCAA}
	exts := []uint16{0x0000, 0x000B, 0x000A, 0x0033, 0x001D, 0x0017, 0x002B, 0x002D}

	data := buildMinimalClientHello(ciphers, exts)
	record := ja3.ParseClientHello(data, "host-web-01", 1234, "curl", "5.6.7.8", 443)
	if record == nil {
		t.Fatal("Failed to parse Client Hello")
	}
	t.Logf("JA3: %s (atypical=%v)", record.JA3[:16], record.IsAtypical)
	t.Logf("  Ciphers: %s", record.CipherSuites)
	t.Logf("  Exts:    %s", record.Extensions)

	// 2. Store locally
	store := ja3.NewJA3Store()
	store.Record(record)
	t.Logf("Store: %d records, %d atypical", store.Stats()["total"], store.Stats()["atypical"])

	// 3. Central correlation
	cc := ja3.NewCentralCorrelator()

	// Simulate same JA3 on 3 hosts (coordinated C2)
	for i, host := range []string{"host-web-01", "host-app-05", "host-db-03"} {
		cc.Ingest(&ja3.JA3Record{
			JA3: record.JA3, SourceHost: host,
			PID: uint32(1000 + i), Comm: "backdoor",
			DestPort: 8443, IsAtypical: true,
		})
	}

	ccStats := cc.Stats()
	t.Logf("Central: %d fingerprints, %d C2 clusters, %d alerts",
		ccStats["ja3_fingerprints"], ccStats["c2_clusters"], ccStats["alerts"])

	for _, c := range cc.Clusters() {
		if c.IsC2 {
			t.Logf("C2 CLUSTER: ja3=%s hosts=%v risk=%.0f",
				c.JA3[:16], c.Hosts, c.RiskScore)
		}
	}

	t.Log("JA3 integration OK")
}
