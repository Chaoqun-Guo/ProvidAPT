// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package threatintel provides threat intelligence alignment for
// provenance data.  It maintains a local cache of known-bad IPs,
// domains, and file hashes, and can synchronise with MISP or other
// threat intel platforms.
package threatintel

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/plugin"
)

// ─── IOC types ──────────────────────────────────────────────

type IOCType int

const (
	IOCIP       IOCType = iota // IP address
	IOCDomain                  // domain name
	IOCFileHash                // SHA256 hash
)

// IOC represents a single indicator of compromise.
type IOC struct {
	Type       IOCType
	Value      string
	Label      string  // human-readable description
	Source     string  // e.g. "misp", "local-blacklist"
	Confidence float64 // 0.0 – 1.0
}

// ─── Cache ──────────────────────────────────────────────────

// Cache is a thread-safe in-memory threat intel store.
type Cache struct {
	mu       sync.RWMutex
	iocs     []IOC
	byIP     map[string][]IOC
	byDomain map[string][]IOC
}

// NewCache creates an empty cache.
func NewCache() *Cache {
	return &Cache{
		byIP:     make(map[string][]IOC),
		byDomain: make(map[string][]IOC),
	}
}

// LoadCSV loads IOCs from a CSV file (type,value,label,source,confidence).
func (c *Cache) LoadCSV(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open intel csv: %w", err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		return fmt.Errorf("read intel csv: %w", err)
	}

	loaded := 0
	for _, rec := range records {
		if len(rec) < 2 {
			continue
		}
		var iocType IOCType
		switch strings.ToLower(rec[0]) {
		case "ip":
			iocType = IOCIP
		case "domain":
			iocType = IOCDomain
		case "hash":
			iocType = IOCFileHash
		default:
			continue
		}
		ioc := IOC{
			Type:   iocType,
			Value:  rec[1],
			Label:  safeGet(rec, 2),
			Source: safeGet(rec, 3, "csv"),
		}
		fmt.Sscanf(safeGet(rec, 4, "0.8"), "%f", &ioc.Confidence)
		c.Add(ioc)
		loaded++
	}
	log.Printf("[threatintel] loaded %d IOCs from %s", loaded, path)
	return nil
}

// LoadList loads IOCs from a plain text file (one per line).
func (c *Cache) LoadList(path string, iocType IOCType, source string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open intel list: %w", err)
	}
	defer f.Close()

	loaded := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		c.Add(IOC{Type: iocType, Value: value, Source: source, Confidence: 0.9})
		loaded++
	}
	log.Printf("[threatintel] loaded %d IOCs from %s", loaded, path)
	return scanner.Err()
}

// Add inserts an IOC into the cache.
func (c *Cache) Add(ioc IOC) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.iocs = append(c.iocs, ioc)
	switch ioc.Type {
	case IOCIP:
		c.byIP[ioc.Value] = append(c.byIP[ioc.Value], ioc)
	case IOCDomain:
		c.byDomain[ioc.Value] = append(c.byDomain[ioc.Value], ioc)
	}
}

// MatchIP returns all IOCs matching a given IP.
func (c *Cache) MatchIP(ip string) []IOC {
	c.mu.RLock()
	defer c.mu.RUnlock()
	// Direct match
	if iocs, ok := c.byIP[ip]; ok {
		return iocs
	}
	// CIDR match
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}
	for _, ioc := range c.iocs {
		if ioc.Type != IOCIP {
			continue
		}
		if strings.Contains(ioc.Value, "/") {
			_, cidr, err := net.ParseCIDR(ioc.Value)
			if err == nil && cidr.Contains(parsed) {
				return []IOC{ioc}
			}
		}
	}
	return nil
}

// MatchDomain returns all IOCs matching a domain.
func (c *Cache) MatchDomain(domain string) []IOC {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.byDomain[strings.ToLower(domain)]
}

// Stats returns cache statistics.
func (c *Cache) Stats() map[string]int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	byType := map[string]int{"ip": 0, "domain": 0, "hash": 0}
	for _, ioc := range c.iocs {
		switch ioc.Type {
		case IOCIP:
			byType["ip"]++
		case IOCDomain:
			byType["domain"]++
		case IOCFileHash:
			byType["hash"]++
		}
	}
	byType["total"] = len(c.iocs)
	return byType
}

// ═══════════════════════════════════════════════════════════════
// ThreatIntelPlugin
// ═══════════════════════════════════════════════════════════════

// ThreatIntelPlugin matches provenance nodes against threat intel.
type ThreatIntelPlugin struct {
	Name_ string
	Cache *Cache
}

func (p *ThreatIntelPlugin) Name() string { return p.Name_ }

func (p *ThreatIntelPlugin) Analyse(snap *provenance.Graph) []*plugin.Finding {
	var findings []*plugin.Finding
	if p.Cache == nil {
		return nil
	}

	for _, n := range snap.Nodes() {
		// Check network endpoints
		if n.Subtype == "network" {
			ip := extractIP(n.Label)
			if ip == "" {
				continue
			}
			if iocs := p.Cache.MatchIP(ip); len(iocs) > 0 {
				labels := make([]string, len(iocs))
				for i, ioc := range iocs {
					labels[i] = ioc.Label
				}
				findings = append(findings, &plugin.Finding{
					PluginName: p.Name_,
					Title:      fmt.Sprintf("Known-bad IP: %s (%s)", ip, strings.Join(labels, "; ")),
					Severity:   "HIGH",
					Score:      9,
					NodeIDs:    []string{n.ID},
					Evidence: map[string]interface{}{
						"ip":         ip,
						"matches":    labels,
						"confidence": iocs[0].Confidence,
					},
				})
			}
		}
	}
	return findings
}

// extractIP tries to extract an IP from a network node label.
func extractIP(label string) string {
	// Labels could be "192.168.1.1", "10.0.0.1:443", etc.
	host, _, err := net.SplitHostPort(label)
	if err == nil {
		return host
	}
	if net.ParseIP(label) != nil {
		return label
	}
	return ""
}

func safeGet(rec []string, idx int, def ...string) string {
	if idx < len(rec) {
		return rec[idx]
	}
	if len(def) > 0 {
		return def[0]
	}
	return ""
}
