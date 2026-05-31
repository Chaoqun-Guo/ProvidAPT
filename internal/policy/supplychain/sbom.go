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
		created, _ = time.Parse(time.RFC3339, raw.CreationInfo.Created)
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
		created, _ = time.Parse(time.RFC3339, raw.Metadata.Timestamp)
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

// BindByPrefix tries to match a file path via longest prefix of registered paths.
// This is called when an exact path lookup fails.
func (s *SBOMStore) BindByPrefix(filePath string, nodeAttrs map[string]string) {
	// Not yet implemented: requires a path->package mapping in the SBOM.
	// Currently only works with exact path lookups via ResolveByPath.
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
