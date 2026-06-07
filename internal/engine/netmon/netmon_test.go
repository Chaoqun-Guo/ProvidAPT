// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package netmon

import (
	"strings"
	"testing"
)

// ─── DNS cache tests ────────────────────────────────────────

func TestNewDNSCache(t *testing.T) {
	dc := NewDNSCache()
	if dc == nil {
		t.Fatal("NewDNSCache returned nil")
	}
}

func TestRecordAndLookup(t *testing.T) {
	dc := NewDNSCache()
	dc.RecordDNS("example.com", []string{"93.184.216.34"})

	domain := dc.Lookup("93.184.216.34")
	if domain != "example.com" {
		t.Errorf("domain = %s", domain)
	}
}

func TestLookupUnknown(t *testing.T) {
	dc := NewDNSCache()
	domain := dc.Lookup("1.2.3.4")
	if domain != "" {
		t.Errorf("unexpected: %s", domain)
	}
}

func TestMultipleIPs(t *testing.T) {
	dc := NewDNSCache()
	dc.RecordDNS("google.com", []string{"142.250.80.46", "142.250.80.14"})

	if dc.Lookup("142.250.80.46") != "google.com" {
		t.Error("missing first IP")
	}
	if dc.Lookup("142.250.80.14") != "google.com" {
		t.Error("missing second IP")
	}
}

func TestResolveDomain(t *testing.T) {
	dc := NewDNSCache()
	dc.RecordDNS("github.com", []string{"140.82.121.4"})
	if dc.ResolveDomain("140.82.121.4") != "github.com" {
		t.Errorf("resolve failed")
	}
	if dc.ResolveDomain("9.9.9.9") != "unknown" {
		t.Errorf("unknown should return 'unknown'")
	}
}

func TestParseDNSResponseBasic(t *testing.T) {
	// Build a minimal DNS response packet
	// Header: 12 bytes (standard)
	// Question: domain + type A + class IN
	// Answer: A record pointing to 93.184.216.34
	packet := buildDNSResponse("example.com", "93.184.216.34")
	domain, ips := ParseDNSResponse(packet)
	if domain != "example.com" {
		t.Errorf("domain = %s", domain)
	}
	if len(ips) != 1 || ips[0] != "93.184.216.34" {
		t.Errorf("ips = %v", ips)
	}
	t.Logf("DNS parsed: %s → %v", domain, ips)
}

func buildDNSResponse(domain, ip string) []byte {
	var p []byte
	// Header: 12 bytes (transaction ID + flags + counts)
	p = append(p, 0x12, 0x34)           // Transaction ID
	p = append(p, 0x81, 0x80)           // Flags: response, no error
	p = append(p, 0x00, 0x01)           // Questions: 1
	p = append(p, 0x00, 0x01)           // Answers: 1
	p = append(p, 0x00, 0x00, 0x00, 0x00) // Authority, Additional

	// Question: domain name + type A + class IN
	for _, part := range strings.Split(domain, ".") {
		p = append(p, byte(len(part)))
		p = append(p, []byte(part)...)
	}
	p = append(p, 0x00)     // End of domain name
	p = append(p, 0x00, 0x01) // Type A
	p = append(p, 0x00, 0x01) // Class IN

	// Answer: compressed name + type A + class IN + TTL + RDATA
	p = append(p, 0xC0, 0x0C)           // Compressed name pointer
	p = append(p, 0x00, 0x01)           // Type A
	p = append(p, 0x00, 0x01)           // Class IN
	p = append(p, 0x00, 0x00, 0x0E, 0x10) // TTL: 3600
	p = append(p, 0x00, 0x04)           // Data length: 4
	// IP: 93.184.216.34
	parts := strings.Split(ip, ".")
	for _, part := range parts {
		p = append(p, byte(atoi(part)))
	}

	return p
}

func atoi(s string) int {
	var n int
	for _, c := range []byte(s) {
		n = n*10 + int(c-'0')
	}
	return n
}

func TestStats(t *testing.T) {
	dc := NewDNSCache()
	dc.RecordDNS("test.com", []string{"1.2.3.4"})
	stats := dc.Stats()
	if stats["cached_entries"].(int) != 1 {
		t.Errorf("entries = %d", stats["cached_entries"])
	}
}

// ─── Socket state tests ─────────────────────────────────────

func TestNewSocketTracker(t *testing.T) {
	st := NewSocketTracker(nil)
	if st == nil {
		t.Fatal("NewSocketTracker returned nil")
	}
}

func TestTCPStateTransition(t *testing.T) {
	st := NewSocketTracker(NewDNSCache())
	key := SocketKey{SrcIP: "10.0.0.1", SrcPort: 54321, DstIP: "93.184.216.34", DstPort: 443}

	// Full lifecycle
	st.OnStateChange(key, TCP_SYN_SENT, 100, "curl")
	st.OnStateChange(key, TCP_ESTABLISHED, 100, "curl")
	st.OnStateChange(key, TCP_CLOSE, 100, "curl")

	sock := st.GetSocket(key)
	if sock != nil {
		t.Error("socket should be removed after CLOSE")
	}

	completed := st.CompletedConnections()
	if len(completed) != 1 {
		t.Fatalf("completed = %d", len(completed))
	}
	if completed[0].HandshakeDuration == "" {
		t.Log("handshake duration not set (timestamps may be identical)")
	}
}

func TestActiveConnections(t *testing.T) {
	st := NewSocketTracker(nil)
	st.OnStateChange(SocketKey{SrcIP: "10.0.0.1", SrcPort: 10000, DstIP: "5.6.7.8", DstPort: 80}, TCP_SYN_SENT, 200, "wget")

	active := st.ActiveConnections()
	if len(active) != 1 {
		t.Errorf("active = %d", len(active))
	}
}

func TestTCPStateNames(t *testing.T) {
	if tcpStateName(TCP_ESTABLISHED) != "ESTABLISHED" {
		t.Errorf("ESTABLISHED = %s", tcpStateName(TCP_ESTABLISHED))
	}
	if tcpStateName(TCP_SYN_SENT) != "SYN_SENT" {
		t.Errorf("SYN_SENT = %s", tcpStateName(TCP_SYN_SENT))
	}
	if tcpStateName(99) != "UNKNOWN(99)" {
		t.Errorf("UNKNOWN = %s", tcpStateName(99))
	}
}

func TestSocketKeyString(t *testing.T) {
	key := SocketKey{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "5.6.7.8", DstPort: 443}
	s := key.String()
	if s != "10.0.0.1:12345-5.6.7.8:443" {
		t.Errorf("string = %s", s)
	}
}

// ─── HTTP tracker tests ─────────────────────────────────────

func TestNewHTTPTracker(t *testing.T) {
	ht := NewHTTPTracker()
	if ht == nil {
		t.Fatal("NewHTTPTracker returned nil")
	}
}

func TestParseHTTPRequest(t *testing.T) {
	data := []byte("GET /admin/config HTTP/1.1\r\nHost: internal.example.com\r\nUser-Agent: curl/8.0\r\n\r\n")
	req := ParseHTTPRequest(data)

	if req == nil {
		t.Fatal("ParseHTTPRequest returned nil")
	}
	if req.Method != "GET" {
		t.Errorf("method = %s", req.Method)
	}
	if req.Path != "/admin/config" {
		t.Errorf("path = %s", req.Path)
	}
	if req.Host != "internal.example.com" {
		t.Errorf("host = %s", req.Host)
	}
	if req.UserAgent != "curl/8.0" {
		t.Errorf("ua = %s", req.UserAgent)
	}
}

func TestParseHTTPRequestPost(t *testing.T) {
	data := []byte("POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n")
	req := ParseHTTPRequest(data)

	if req.Method != "POST" {
		t.Errorf("method = %s", req.Method)
	}
	if req.ContentType != "application/json" {
		t.Errorf("content-type = %s", req.ContentType)
	}
}

func TestParseHTTPRequestInvalid(t *testing.T) {
	req := ParseHTTPRequest([]byte{})
	if req != nil {
		t.Error("empty data should return nil")
	}
}

func TestRecordAndGetRequest(t *testing.T) {
	ht := NewHTTPTracker()
	key := SocketKey{DstIP: "93.184.216.34", DstPort: 80}

	req := &HTTPRequest{Method: "GET", Host: "example.com", Path: "/index.html"}
	ht.RecordRequest(key, req)

	got := ht.GetRequest(key)
	if got == nil {
		t.Fatal("GetRequest returned nil")
	}
	if got.Host != "example.com" {
		t.Errorf("host = %s", got.Host)
	}
}

func TestEnrichSocket(t *testing.T) {
	ht := NewHTTPTracker()
	key := SocketKey{DstIP: "10.0.0.1", DstPort: 80}
	ht.RecordRequest(key, &HTTPRequest{Method: "GET", Host: "web.internal", Path: "/config"})

	sock := &SocketState{Key: key}
	ht.EnrichSocket(key, sock)

	if sock.HTTPHost != "web.internal" {
		t.Errorf("HTTPHost = %s", sock.HTTPHost)
	}
	if sock.HTTPPath != "GET /config" {
		t.Errorf("HTTPPath = %s", sock.HTTPPath)
	}
}

// ─── Integration test ───────────────────────────────────────

func TestNetmonIntegration(t *testing.T) {
	t.Log("=== Network Monitoring Integration ===")

	// 1. DNS correlation
	dc := NewDNSCache()
	dc.RecordDNS("evil.example.com", []string{"5.6.7.8"})
	t.Logf("DNS: evil.example.com → 5.6.7.8")

	// 2. Socket tracking with DNS enrichment
	st := NewSocketTracker(dc)
	key := SocketKey{SrcIP: "10.0.0.1", SrcPort: 40000, DstIP: "5.6.7.8", DstPort: 443}

	st.OnStateChange(key, TCP_SYN_SENT, 100, "curl")
	st.OnStateChange(key, TCP_ESTABLISHED, 100, "curl")

	// After established, domain should be resolved
	sock := st.GetSocket(key)
	if sock != nil {
		t.Logf("Connection: %s → %s (domain=%s, handshake=%s)",
			key, sock.StateName, sock.Domain, sock.HandshakeDuration)
	}

	// 3. HTTP metadata
	ht := NewHTTPTracker()
	httpKey := SocketKey{DstIP: "5.6.7.8", DstPort: 443}
	ht.RecordRequest(httpKey, &HTTPRequest{
		Method: "POST", Host: "evil.example.com", Path: "/collect",
	})

	// Enrich the socket
	if sock != nil {
		ht.EnrichSocket(key, sock)
		t.Logf("HTTP: %s %s (host=%s)", sock.HTTPPath, sock.HTTPHost, sock.Domain)
	}

	// 4. Complete
	st.OnStateChange(key, TCP_CLOSE, 100, "curl")

	completed := st.CompletedConnections()
	t.Logf("Completed connections: %d", len(completed))
	if len(completed) > 0 {
		c := completed[0]
		t.Logf("Final: %s domain=%s host=%s path=%s dur=%s",
			c.Key, c.Domain, c.HTTPHost, c.HTTPPath, c.ConnectionDuration)
	}

	// Verify the full chain
	if dc.Lookup("5.6.7.8") != "evil.example.com" {
		t.Error("DNS correlation broken")
	}
	t.Log("Netmon Integration OK")
}
