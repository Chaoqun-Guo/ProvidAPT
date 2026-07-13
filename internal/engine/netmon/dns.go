// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package netmon provides enhanced network monitoring for ProvidAPT.
//
// Features:
// 1. DNS correlation -map IPs to domain names via UDP/53 monitoring
// 2. Socket state tracking -TCP state machine via tcp_set_state hook
// 3. HTTP awareness -extract Host/URL for port 80/443 traffic
package netmon

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// DNS correlation

// DNSCache maps IPs to the domains they resolved to.
type DNSCache struct {
	mu      sync.RWMutex
	entries map[string]*DNSEntry // IP -> domain info
}

// DNSEntry holds a resolved domain for an IP.
type DNSEntry struct {
	IP        string    `json:"ip"`
	Domain    string    `json:"domain"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
}

// NewDNSCache creates a DNS correlation cache.
func NewDNSCache() *DNSCache {
	return &DNSCache{
		entries: make(map[string]*DNSEntry),
	}
}

// RecordDNS is called when a DNS response is observed (UDP/53).
// It maps the resolved IP to the queried domain.
//
// In production, this is called by the eBPF program that hooks
// UDP recvmsg on port 53 and parses the DNS response.
func (dc *DNSCache) RecordDNS(domain string, resolvedIPs []string) {
	for _, ip := range resolvedIPs {
		dc.mu.Lock()
		existing, ok := dc.entries[ip]
		if ok {
			existing.LastSeen = time.Now()
			existing.Count++
			// If domain differs, it might be a shared IP (CDN)
			if existing.Domain != domain {
				existing.Domain = fmt.Sprintf("%s|%s", existing.Domain, domain)
			}
		} else {
			dc.entries[ip] = &DNSEntry{
				IP:        ip,
				Domain:    domain,
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
				Count:     1,
			}
		}
		dc.mu.Unlock()
	}
}

// Lookup returns the domain for an IP, if known.
func (dc *DNSCache) Lookup(ip string) string {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	if entry, ok := dc.entries[ip]; ok {
		return entry.Domain
	}
	return ""
}

// ResolveDomain tries to determine the domain for a connection.
// Priority: DNS cache > reverse lookup > unknown.
func (dc *DNSCache) ResolveDomain(ip string) string {
	// Check DNS cache
	if domain := dc.Lookup(ip); domain != "" {
		return domain
	}
	return "unknown"
}

// ParseDNSResponse parses a simple DNS response packet to extract
// the queried domain and resolved IPs.
//
// This handles the basic DNS response format:
//
//	[12 bytes header][question][answer records]
//
// In production, use a proper DNS parsing library.
func ParseDNSResponse(packet []byte) (domain string, ips []string) {
	if len(packet) < 12 {
		return "", nil
	}

	// Skip header (12 bytes), parse question section
	pos := 12
	domain, pos = parseDNSName(packet, pos)
	if domain == "" {
		return "", nil
	}

	// Skip QTYPE and QCLASS (4 bytes)
	pos += 4

	// Parse answer records
	// Each answer: [name(compressed,2bytes)][type(2)][class(2)][ttl(4)][rdlength(2)][rdata]
	for pos+12 <= len(packet) {
		// Skip compressed name (2 bytes)
		if pos+2 > len(packet) {
			break
		}
		atype := int(packet[pos+2])<<8 | int(packet[pos+3])
		rdlength := int(packet[pos+10])<<8 | int(packet[pos+11])

		if pos+12+rdlength > len(packet) {
			break
		}

		if atype == 1 && rdlength == 4 { // A record
			ip := fmt.Sprintf("%d.%d.%d.%d",
				packet[pos+12], packet[pos+13], packet[pos+14], packet[pos+15])
			ips = append(ips, ip)
		}

		pos += 12 + rdlength
	}

	return domain, ips
}

// parseDNSName extracts a DNS name from a packet at the given position.
func parseDNSName(packet []byte, pos int) (string, int) {
	var parts []string
	for {
		if pos >= len(packet) {
			return "", pos
		}
		length := int(packet[pos])
		if length == 0 {
			pos++
			break
		}
		// Handle DNS name compression (0xC0 prefix)
		if length&0xC0 == 0xC0 {
			if pos+1 >= len(packet) {
				break
			}
			ptr := int(length&0x3F)<<8 | int(packet[pos+1])
			rest, _ := parseDNSName(packet, ptr)
			parts = append(parts, rest)
			pos += 2
			break
		}
		pos++
		if pos+length > len(packet) {
			return "", pos
		}
		parts = append(parts, string(packet[pos:pos+length]))
		pos += length
	}
	return strings.Join(parts, "."), pos
}

// Stats returns DNS cache statistics.
func (dc *DNSCache) Stats() map[string]interface{} {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	return map[string]interface{}{
		"cached_entries": len(dc.entries),
	}
}
