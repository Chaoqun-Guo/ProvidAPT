// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package supplychain

import (
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SBOMStore manages imported Software Bill of Materials documents
// and provides path-based resolution for binding metadata to graph nodes.
type SBOMStore struct {
	mu           sync.Mutex
	documents    map[string]*SBOMDocument  // ID -> document
	byPurl       map[string]*SBOMEntry     // purl -> entry
	byPath       map[string]*SBOMEntry     // file path -> entry (longest prefix match)
	bindingCache map[string]string         // file path -> SBOM ID
}

// NewSBOMStore creates an SBOM store.
func NewSBOMStore() *SBOMStore {
	return &SBOMStore{
		documents:    make(map[string]*SBOMDocument),
		byPurl:       make(map[string]*SBOMEntry),
		byPath:       make(map[string]*SBOMEntry),
		bindingCache: make(map[string]string),
	}
}

// ImportSBOM auto-detects the format and imports an SBOM document.
func (s *SBOMStore) ImportSBOM(data []byte, source string) (*SBOMDocument, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty SBOM data")
	}

	// Try SPDX first (most common for provenance).
	doc, err := s.ImportSPDX(data, source)
	if err == nil {
		return doc, nil
	}

	// Fall back to CycloneDX.
	doc, err = s.ImportCycloneDX(data, source)
	if err == nil {
		return doc, nil
	}

	return nil, fmt.Errorf("unrecognised SBOM format: SPDX err=%v; CycloneDX also failed", err)
}

// ImportSPDX imports an SPDX 2.3 JSON document.
func (s *SBOMStore) ImportSPDX(data []byte, source string) (*SBOMDocument, error) {
	var raw struct {
		SPDXID        string `json:"spdxId"`
		Name          string `json:"name"`
		DocumentNamespace string `json:"documentNamespace"`
		Packages      []struct {
			SPDXID        string `json:"spdxId"`
			Name          string `json:"name"`
			VersionInfo   string `json:"versionInfo"`
			Supplier      string `json:"supplier"`
			LicenseDeclared string `json:"licenseDeclared"`
			Checksums     []struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"checksums"`
			ExternalRefs []struct {
				Category string `json:"referenceCategory"`
				Locator  string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
		CreationInfo struct {
			Created string `json:"created"`
		} `json:"creationInfo"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("SPDX parse: %w", err)
	}

	docID := raw.DocumentNamespace
	if raw.SPDXID == "" {
		return nil, fmt.Errorf("SPDX parse: missing spdxId")
	}
	if docID == "" {
		docID = fmt.Sprintf("spdx:%s", raw.Name)
	}

	var created time.Time
	if raw.CreationInfo.Created != "" {
		var err error
		created, err = time.Parse(time.RFC3339, raw.CreationInfo.Created)
		if err != nil {
			log.Printf("[sbom] parse SPDX creation time %q: %v", raw.CreationInfo.Created, err)
		}
	}

	doc := &SBOMDocument{
		ID:     docID,
		Format: "spdx",
		Packages: make([]SBOMEntry, 0, len(raw.Packages)),
		CreatedAt: created,
		Source: source,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, p := range raw.Packages {
		entry := SBOMEntry{
			Name:     p.Name,
			Version:  p.VersionInfo,
			Supplier: strings.TrimPrefix(p.Supplier, "Organization: "),
			License:  p.LicenseDeclared,
			Checksums: make(map[string]string),
		}

		for _, c := range p.Checksums {
			entry.Checksums[strings.ToLower(c.Algorithm)] = c.Value
		}

		// Extract Package URL from external refs.
		for _, ref := range p.ExternalRefs {
			if ref.Category == "PACKAGE-MANAGER" {
				entry.Purl = ref.Locator
				break
			}
		}
		if entry.Purl == "" {
			// Construct a minimal purl from name + version.
			entry.Purl = fmt.Sprintf("pkg:generic/%s@%s", entry.Name, entry.Version)
		}

		// Infer source repo from supplier.
		if entry.Supplier != "" {
			entry.SourceRepo = "official"
		} else {
			entry.SourceRepo = "unknown"
		}

		doc.Packages = append(doc.Packages, entry)
		s.byPurl[entry.Purl] = &doc.Packages[len(doc.Packages)-1]
	}

	s.documents[docID] = doc

	log.Printf("[sbom] imported SPDX: %s (%d packages)", docID, len(doc.Packages))
	return doc, nil
}

// ImportCycloneDX imports a CycloneDX 1.4+ JSON document.
func (s *SBOMStore) ImportCycloneDX(data []byte, source string) (*SBOMDocument, error) {
	var raw struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Metadata    struct {
			Timestamp string `json:"timestamp"`
		} `json:"metadata"`
		Components  []struct {
			Type    string `json:"type"`
			Name    string `json:"name"`
			Version string `json:"version"`
			Supplier struct {
				Name string `json:"name"`
			} `json:"supplier"`
			Licenses []struct {
				License struct {
					Name string `json:"name"`
				} `json:"license"`
			} `json:"licenses"`
			Hashes []struct {
				Alg     string `json:"alg"`
				Content string `json:"content"`
			} `json:"hashes"`
			Purl string `json:"purl"`
		} `json:"components"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("CycloneDX parse: %w", err)
	}
	if raw.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("not a CycloneDX document: %s", raw.BOMFormat)
	}

	docID := raw.SerialNumber
	if docID == "" {
		docID = fmt.Sprintf("cyclonedx:%d", time.Now().UnixNano())
	}

	var created time.Time
	if raw.Metadata.Timestamp != "" {
		var err error
		created, err = time.Parse(time.RFC3339, raw.Metadata.Timestamp)
		if err != nil {
			log.Printf("[sbom] parse CycloneDX creation time %q: %v", raw.Metadata.Timestamp, err)
		}
	}

	doc := &SBOMDocument{
		ID:     docID,
		Format: "cyclonedx",
		Packages: make([]SBOMEntry, 0, len(raw.Components)),
		CreatedAt: created,
		Source: source,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, c := range raw.Components {
		entry := SBOMEntry{
			Name:     c.Name,
			Version:  c.Version,
			Supplier: c.Supplier.Name,
			Checksums: make(map[string]string),
		}

		for _, h := range c.Hashes {
			entry.Checksums[strings.ToLower(h.Alg)] = h.Content
		}

		if len(c.Licenses) > 0 {
			entry.License = c.Licenses[0].License.Name
		}

		entry.Purl = c.Purl
		if entry.Purl == "" {
			entry.Purl = fmt.Sprintf("pkg:generic/%s@%s", entry.Name, entry.Version)
		}

		entry.SourceRepo = "official"

		doc.Packages = append(doc.Packages, entry)
		s.byPurl[entry.Purl] = &doc.Packages[len(doc.Packages)-1]
	}

	s.documents[docID] = doc

	log.Printf("[sbom] imported CycloneDX: %s (%d components)", docID, len(doc.Packages))
	return doc, nil
}

// BindToNode enriches a provenance graph node's attrs map with SBOM metadata.
// It looks up the file path in the SBOM index and writes supply-chain fields.
func (s *SBOMStore) BindToNode(filePath string, nodeAttrs map[string]string) {
	entry := s.ResolveByPath(filePath)
	if entry == nil {
		return
	}

	nodeAttrs["sbom_ref"] = fmt.Sprintf("pkg:%s@%s", entry.Name, entry.Version)
	nodeAttrs["package_name"] = entry.Name
	nodeAttrs["package_version"] = entry.Version
	nodeAttrs["license"] = entry.License
	nodeAttrs["source_repo"] = entry.SourceRepo

	// Record checksum as artifact hash if available.
	if sha, ok := entry.Checksums["sha256"]; ok {
		nodeAttrs["artifact_hash"] = "sha256:" + sha
	} else if sha, ok := entry.Checksums["sha512"]; ok {
		nodeAttrs["artifact_hash"] = "sha512:" + sha
	} else if md5, ok := entry.Checksums["md5"]; ok {
		nodeAttrs["artifact_hash"] = "md5:" + md5
	}

	s.mu.Lock()
	s.bindingCache[filePath] = entry.Purl
	s.mu.Unlock()

	log.Printf("[sbom] bound %s -> %s %s", filePath, entry.Name, entry.Version)
}

// BindByPrefix tries to match a file path via heuristic mapping.
// This is called when an exact path lookup via ResolveByPath fails.
// It extracts package name hints from the file path and searches
// the SBOM's package index (byPurl) for the best match.
func (s *SBOMStore) BindByPrefix(filePath string, nodeAttrs map[string]string) {
	candidates := guessPackageCandidates(filePath)
	if len(candidates) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, hint := range candidates {
		for purl, entry := range s.byPurl {
			name := strings.ToLower(entry.Name)
			h := strings.ToLower(hint)
			if name == h || strings.HasPrefix(name, h) || strings.HasSuffix(name, "-"+h) {
				nodeAttrs["sbom_ref"] = purl
				nodeAttrs["package_name"] = entry.Name
				nodeAttrs["package_version"] = entry.Version
				nodeAttrs["license"] = entry.License
				nodeAttrs["source_repo"] = entry.SourceRepo
				if sha, ok := entry.Checksums["sha256"]; ok {
					nodeAttrs["artifact_hash"] = "sha256:" + sha
				} else if sha, ok := entry.Checksums["sha512"]; ok {
					nodeAttrs["artifact_hash"] = "sha512:" + sha
				}
				// Register mapping for future direct lookups
				s.byPath[filePath] = entry
				log.Printf("[sbom] prefix bound %s -> %s %s", filePath, entry.Name, entry.Version)
				return
			}
		}
	}
}

// guessPackageCandidates extracts possible package name hints from a file path.
// Returns hints in priority order (most specific first).
func guessPackageCandidates(filePath string) []string {
	dir := filepath.ToSlash(filepath.Dir(filePath))
	base := filepath.Base(filePath)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	if name == "" || name == "." || name == "/" {
		name = ""
	}

	// Skip non-informative names (Python/Node internals, etc.)
	if name == "__init__" || name == "__main__" || name == "index" || name == "main" {
		name = ""
	}

	var candidates []string

	// Python packages live under site-packages/<name>/
	if strings.Contains(dir, "site-packages") || strings.Contains(dir, "dist-packages") {
		parent := filepath.Base(dir)
		if parent != "" && parent != "." && parent != "/" {
			candidates = append(candidates, "python3-"+parent, parent)
		}
	}

	// Node.js packages live under node_modules/<name>/
	if strings.Contains(dir, "node_modules") {
		parent := filepath.Base(dir)
		if parent != "" && parent != "." && parent != "/" {
			candidates = append(candidates, "node-"+parent, parent)
		}
	}

	// Use filename (without extension) as primary candidate
	if name != "" {
		candidates = append(candidates, name)
	}

	// Walk up past generic directories to find a meaningful ancestor.
	// e.g., /usr/lib/nginx/modules/ngx_http_modsecurity.so → modules (generic) → nginx (candidate)
	walk := dir
	for {
		parent := filepath.Base(walk)
		if parent == "" || parent == "." || parent == "/" || parent == "\\" {
			break
		}
		if parent == name {
			walk = filepath.Dir(walk)
			continue
		}
		if !isGenericDir(parent) {
			candidates = append(candidates, parent)
			break
		}
		walk = filepath.Dir(walk)
		if walk == filepath.Dir(walk) { // reached root
			break
		}
	}

	return candidates
}

// isGenericDir returns true for common system directory names that
// are not useful as package name hints.
func isGenericDir(name string) bool {
	generic := map[string]bool{
		"bin": true, "sbin": true, "lib": true, "lib64": true,
		"usr": true, "etc": true, "opt": true, "home": true,
		"tmp": true, "var": true, "share": true, "doc": true,
		"man": true, "include": true, "src": true, "modules": true,
		"local": true, "node_modules": true, "site-packages": true,
		"dist-packages": true,
	}
	return generic[name]
}

// ResolveByPath looks up an SBOM entry by file path.
// Returns nil if no entry matches.
func (s *SBOMStore) ResolveByPath(filePath string) *SBOMEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Direct hit.
	if entry, ok := s.byPath[filePath]; ok {
		return entry
	}

	// Longest prefix match for directory-level entries.
	dir := filepath.Clean(filePath)
	for {
		if entry, ok := s.byPath[dir]; ok {
			return entry
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return nil
}

// RegisterPathMapping explicitly maps a file path to an SBOM entry.
// This is called when the SBOM contains file-level path information
// or when a package manager monitor confirms an install.
func (s *SBOMStore) RegisterPathMapping(filePath string, purl string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, ok := s.byPurl[purl]; ok {
		s.byPath[filePath] = entry
		log.Printf("[sbom] path mapping: %s -> %s", filePath, purl)
	}
}

// Documents returns all imported SBOM documents.
func (s *SBOMStore) Documents() []*SBOMDocument {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*SBOMDocument, 0, len(s.documents))
	for _, d := range s.documents {
		out = append(out, d)
	}
	return out
}

// Stats returns store statistics.
func (s *SBOMStore) Stats() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]interface{}{
		"documents":      len(s.documents),
		"purl_entries":   len(s.byPurl),
		"path_mappings":  len(s.byPath),
		"binding_cache":  len(s.bindingCache),
	}
}
