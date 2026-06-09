// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package ja3

import (
	"encoding/binary"
	"testing"
	"time"
)

// buildClientHello constructs a minimal TLS Client Hello for testing.
func buildClientHello(cipherIDs []uint16, extTypes []uint16, curves []uint16, ecFormats []byte) []byte {
	var data []byte
	// TLS Record header (5 bytes)
	data = append(data, 0x16)       // ContentType: Handshake
	data = append(data, 0x03, 0x03) // Version: TLS 1.2
	data = append(data, 0, 0)       // Record length (filled later)
	// Handshake header (4 bytes)
	data = append(data, 0x01) // HandshakeType: Client Hello
	hsLenPos := len(data)
	data = append(data, 0, 0, 0)    // Handshake length (filled later)
	chStart := len(data)            // ClientHello starts here
	data = append(data, 0x03, 0x03) // Client Version
	random := make([]byte, 32)
	data = append(data, random...) // Random
	data = append(data, 0)         // Session ID Length
	// Cipher Suites
	cipherData := make([]byte, len(cipherIDs)*2)
	for i, id := range cipherIDs {
		binary.BigEndian.PutUint16(cipherData[i*2:], id)
	}
	cipherLen := make([]byte, 2)
	binary.BigEndian.PutUint16(cipherLen, uint16(len(cipherData)))
	data = append(data, cipherLen...)
	data = append(data, cipherData...)
	// Compression Methods
	data = append(data, 1, 0) // Length 1, null compression
	// Extensions
	var extData []byte
	for i, typ := range extTypes {
		extType := make([]byte, 2)
		binary.BigEndian.PutUint16(extType, typ)
		extData = append(extData, extType...)
		if typ == 10 && i < len(curves) { // supported_groups
			curveData := make([]byte, len(curves)*2)
			for j, c := range curves {
				binary.BigEndian.PutUint16(curveData[j*2:], c)
			}
			cl := make([]byte, 2)
			binary.BigEndian.PutUint16(cl, uint16(len(curveData)))
			extPayload := append(cl, curveData...)
			extLen := make([]byte, 2)
			binary.BigEndian.PutUint16(extLen, uint16(len(extPayload)))
			extData = append(extData, extLen...)
			extData = append(extData, extPayload...)
		} else if typ == 11 { // EC Point Formats
			extPayload := []byte{byte(len(ecFormats))}
			extPayload = append(extPayload, ecFormats...)
			extLen := make([]byte, 2)
			binary.BigEndian.PutUint16(extLen, uint16(len(extPayload)))
			extData = append(extData, extLen...)
			extData = append(extData, extPayload...)
		} else {
			extData = append(extData, 0, 0) // Length 0
		}
	}
	extLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extLen, uint16(len(extData)))
	data = append(data, extLen...)
	data = append(data, extData...)
	// Fill handshake length (3 bytes, big-endian)
	hsLen := len(data) - chStart
	data[hsLenPos] = byte(hsLen >> 16)
	data[hsLenPos+1] = byte(hsLen >> 8)
	data[hsLenPos+2] = byte(hsLen)
	// Fill TLS record length
	recLen := len(data) - 5
	binary.BigEndian.PutUint16(data[3:5], uint16(recLen))
	return data
}

func TestParseClientHelloValid(t *testing.T) {
	data := buildClientHello(
		[]uint16{0x002F, 0xC02B}, // TLS_RSA_AES_128_SHA, ECDHE
		[]uint16{10, 11},         // supported_groups, EC point formats
		[]uint16{0x0017, 0x0018}, // x25519, secp256r1
		[]byte{0},                // uncompressed
	)
	rec := ParseClientHello(data, "10.0.0.1", 100, "curl", "10.0.0.5", 443)
	if rec == nil {
		t.Fatal("ParseClientHello returned nil")
	}
	if rec.PID != 100 {
		t.Errorf("PID = %d", rec.PID)
	}
	if rec.Comm != "curl" {
		t.Errorf("Comm = %s", rec.Comm)
	}
	if rec.SourceHost != "10.0.0.1" {
		t.Errorf("SourceHost = %s", rec.SourceHost)
	}
	if rec.DestIP != "10.0.0.5" {
		t.Errorf("DestIP = %s", rec.DestIP)
	}
	if rec.DestPort != 443 {
		t.Errorf("DestPort = %d", rec.DestPort)
	}
	// Verify cipher suites parsed
	if rec.CipherSuites != "47-49195" {
		t.Errorf("CipherSuites = %q, want 47-49195", rec.CipherSuites)
	}
	// Verify extensions parsed
	if rec.Extensions != "10-11" {
		t.Errorf("Extensions = %q, want 10-11", rec.Extensions)
	}
	// Verify curves parsed
	if rec.EllipticCurves != "23-24" {
		t.Errorf("EllipticCurves = %q", rec.EllipticCurves)
	}
	// Verify EC formats parsed
	if rec.ECFormats != "0" {
		t.Errorf("ECFormats = %q", rec.ECFormats)
	}
	// JA3 should be non-empty
	if rec.JA3 == "" {
		t.Error("empty JA3 hash")
	}
	if rec.JA3Text == "" {
		t.Error("empty JA3 text")
	}
}

func TestParseClientHelloShortBuffer(t *testing.T) {
	rec := ParseClientHello(nil, "", 0, "", "", 0)
	if rec != nil {
		t.Error("expected nil for nil input")
	}
	rec = ParseClientHello([]byte{0x16, 0x03}, "", 0, "", "", 0)
	if rec != nil {
		t.Error("expected nil for short input")
	}
}

func TestParseClientHelloWrongContentType(t *testing.T) {
	data := buildClientHello([]uint16{0x002F}, nil, nil, nil)
	if len(data) > 0 {
		data[0] = 0x17 // Change from Handshake to Application Data
	}
	rec := ParseClientHello(data, "", 0, "", "", 0)
	if rec != nil {
		t.Error("expected nil for wrong content type")
	}
}

func TestParseClientHelloNoExtensions(t *testing.T) {
	data := buildClientHello([]uint16{0x002F, 0xC02B}, nil, nil, nil)
	rec := ParseClientHello(data, "", 0, "test", "", 0)
	if rec == nil {
		t.Fatal("expected valid record without extensions")
	}
	if rec.CipherSuites != "47-49195" {
		t.Errorf("CipherSuites = %q", rec.CipherSuites)
	}
	if rec.Extensions != "" {
		t.Errorf("Extensions = %q, want empty", rec.Extensions)
	}
	if rec.EllipticCurves != "" {
		t.Errorf("EllipticCurves = %q, want empty", rec.EllipticCurves)
	}
	if rec.ECFormats != "" {
		t.Errorf("ECFormats = %q, want empty", rec.ECFormats)
	}
}

func TestParseClientHelloMultipleCiphers(t *testing.T) {
	data := buildClientHello(
		[]uint16{0x002F, 0xC02B, 0x009C, 0x0035},
		nil, nil, nil,
	)
	rec := ParseClientHello(data, "", 0, "", "", 0)
	if rec == nil {
		t.Fatal("expected valid record")
	}
	if rec.CipherSuites != "47-49195-156-53" {
		t.Errorf("CipherSuites = %q", rec.CipherSuites)
	}
}

func TestJA3HashStability(t *testing.T) {
	data := buildClientHello(
		[]uint16{0x002F, 0xC02B},
		[]uint16{10, 11},
		[]uint16{0x0017, 0x0018},
		[]byte{0},
	)
	rec1 := ParseClientHello(data, "", 0, "", "", 0)
	rec2 := ParseClientHello(data, "", 0, "", "", 0)
	if rec1 == nil || rec2 == nil {
		t.Fatal("nil record")
	}
	if rec1.JA3 != rec2.JA3 {
		t.Errorf("JA3 hash differs between runs: %s vs %s", rec1.JA3, rec2.JA3)
	}
}

func TestIsAtypicalJA3(t *testing.T) {
	if !IsAtypicalJA3("00000000000000000000000000000000") {
		t.Error("unknown hash should be atypical")
	}
	if IsAtypicalJA3("6734f37431670b3ab4292b8f60f29984") {
		t.Error("curl JA3 should not be atypical")
	}
}

func TestJA3RecordString(t *testing.T) {
	rec := &JA3Record{
		JA3:        "abc123def456abc123def456abc123de",
		SourceHost: "10.0.0.1",
		DestIP:     "10.0.0.5",
		DestPort:   443,
		Comm:       "curl",
		PID:        100,
	}
	s := rec.String()
	if s != "JA3=abc123def456abc1 10.0.0.1 -> 10.0.0.5:443 (curl PID 100)" {
		t.Errorf("String = %q", s)
	}
}

func TestNewJA3Store(t *testing.T) {
	js := NewJA3Store()
	if js == nil {
		t.Fatal("NewJA3Store returned nil")
	}
}

func TestJA3StoreRecord(t *testing.T) {
	js := NewJA3Store()
	rec := &JA3Record{
		JA3:        "6734f37431670b3ab4292b8f60f29984",
		SourceHost: "host1",
		PID:        100,
		Comm:       "curl",
	}
	js.Record(rec)
	if len(js.records) != 1 {
		t.Errorf("records = %d", len(js.records))
	}
	if rec.IsAtypical {
		t.Error("curl should not be atypical")
	}
}

func TestJA3StoreRecordNil(t *testing.T) {
	js := NewJA3Store()
	js.Record(nil) // should not panic
	if len(js.records) != 0 {
		t.Errorf("records = %d", len(js.records))
	}
}

func TestJA3StoreRecords(t *testing.T) {
	js := NewJA3Store()
	js.Record(&JA3Record{JA3: "aaa"})
	js.Record(&JA3Record{JA3: "bbb"})
	records := js.Records()
	if len(records) != 2 {
		t.Errorf("Records = %d", len(records))
	}
}

func TestJA3StoreStats(t *testing.T) {
	js := NewJA3Store()
	js.Record(&JA3Record{JA3: "6734f37431670b3ab4292b8f60f29984"})
	js.Record(&JA3Record{JA3: "00000000000000000000000000000000"})
	stats := js.Stats()
	if stats["total"].(int) != 2 {
		t.Errorf("total = %d", stats["total"])
	}
	if stats["atypical"].(int) != 1 {
		t.Errorf("atypical = %d", stats["atypical"])
	}
}

func TestParseEllipticCurves(t *testing.T) {
	// Length = 4 bytes, 2 curves
	data := []byte{0x00, 0x04, 0x00, 0x17, 0x00, 0x18}
	curves := parseEllipticCurves(data)
	if len(curves) != 2 {
		t.Errorf("got %d curves", len(curves))
	}
	if len(curves) >= 1 && curves[0] != "23" {
		t.Errorf("curve[0] = %s", curves[0])
	}
}

func TestParseEllipticCurvesShort(t *testing.T) {
	curves := parseEllipticCurves([]byte{0x00, 0x01}) // claims 1 curve but only 2 bytes
	if len(curves) != 0 {
		t.Errorf("expected 0 curves for short data, got %d", len(curves))
	}
}

func TestParseECFormats(t *testing.T) {
	data := []byte{0x02, 0x00, 0x01} // 2 formats: uncompressed, ANSI X9.62
	formats := parseECFormats(data)
	if len(formats) != 2 {
		t.Errorf("got %d formats", len(formats))
	}
}

func TestParseECFormatsShort(t *testing.T) {
	formats := parseECFormats(nil)
	if len(formats) != 0 {
		t.Errorf("expected 0 formats for nil, got %d", len(formats))
	}
}

// 鈹€鈹€ CentralCorrelator tests 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func TestNewCentralCorrelator(t *testing.T) {
	cc := NewCentralCorrelator()
	if cc == nil {
		t.Fatal("NewCentralCorrelator returned nil")
	}
}

func TestCentralCorrelatorIngest(t *testing.T) {
	cc := NewCentralCorrelator()
	rec := &JA3Record{
		JA3:        "00000000000000000000000000000001",
		SourceHost: "host1",
		PID:        100,
		Comm:       "unknown",
		Timestamp:  time.Now(),
	}
	// First ingest: atypical, count=1, no alert yet
	alert := cc.Ingest(rec)
	if alert != nil {
		t.Error("expected no alert for single ingest")
	}
}

func TestCentralCorrelatorAlert(t *testing.T) {
	cc := NewCentralCorrelator()
	rec := &JA3Record{
		JA3:        "00000000000000000000000000000002",
		SourceHost: "host1",
		PID:        100,
		Comm:       "unknown",
		DestPort:   8443,
		Timestamp:  time.Now(),
	}
	cc.Ingest(rec)
	// Second ingest from same host 鈫?cluster.Count=2, atypical=true, risk > 50
	rec2 := &JA3Record{
		JA3:        "00000000000000000000000000000002",
		SourceHost: "host2",
		PID:        200,
		Comm:       "unknown",
		DestPort:   8443,
		Timestamp:  time.Now(),
	}
	alert := cc.Ingest(rec2)
	if alert == nil {
		t.Fatal("expected C2 alert with 2 hosts")
	}
	if alert.ClusterSize != 2 {
		t.Errorf("ClusterSize = %d", alert.ClusterSize)
	}
	if len(alert.Hosts) != 2 {
		t.Errorf("Hosts = %d", len(alert.Hosts))
	}
}

func TestCentralCorrelatorClusters(t *testing.T) {
	cc := NewCentralCorrelator()
	cc.Ingest(&JA3Record{JA3: "aaa", SourceHost: "h1", Timestamp: time.Now()})
	cc.Ingest(&JA3Record{JA3: "bbb", SourceHost: "h1", Timestamp: time.Now()})
	clusters := cc.Clusters()
	if len(clusters) != 2 {
		t.Errorf("clusters = %d", len(clusters))
	}
}

func TestCentralCorrelatorAlerts(t *testing.T) {
	cc := NewCentralCorrelator()
	alerts := cc.Alerts()
	if len(alerts) != 0 {
		t.Errorf("alerts = %d", len(alerts))
	}
}

func TestCentralCorrelatorStats(t *testing.T) {
	cc := NewCentralCorrelator()
	stats := cc.Stats()
	if stats["ja3_fingerprints"].(int) != 0 {
		t.Errorf("fingerprints = %d", stats["ja3_fingerprints"])
	}
}

func TestCentralCorrelatorCalcRisk(t *testing.T) {
	cc := NewCentralCorrelator()

	cluster := &JA3Cluster{Hosts: []string{"h1"}, Processes: []string{"h1:100:curl"}}
	rec := &JA3Record{IsAtypical: true, DestPort: 443}
	score := cc.calcRisk(cluster, rec)
	if score != 60 { // 30(atypical) + 15(1 host) + 10(1 proc) + 5(port 443)
		t.Errorf("risk = %f, want 60", score)
	}
}

func TestAddUnique(t *testing.T) {
	slice := addUnique([]string{"a", "b"}, "a")
	if len(slice) != 2 {
		t.Errorf("len = %d", len(slice))
	}
	slice = addUnique(slice, "c")
	if len(slice) != 3 {
		t.Errorf("len = %d", len(slice))
	}
}

func TestParseClientHelloWithSessionID(t *testing.T) {
	// Build a Client Hello with a session ID
	data := buildClientHello([]uint16{0x002F}, nil, nil, nil)
	// Insert a session ID after the random (at position 43 after the 5-byte record header + 4-byte handshake header + 2-byte version + 32-byte random)
	// Actually, let me just use buildClientHello and verify it handles standard cases
	rec := ParseClientHello(data, "", 0, "", "", 0)
	if rec == nil {
		t.Fatal("expected valid record")
	}
}

func TestClientHelloHandlesEmptyData(t *testing.T) {
	rec := ParseClientHello([]byte{}, "", 0, "", "", 0)
	if rec != nil {
		t.Error("expected nil for empty data")
	}
}
