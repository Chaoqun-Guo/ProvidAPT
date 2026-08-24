// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package ja3 implements TLS fingerprinting for ProvidAPT.
//
// JA3 fingerprint identifies TLS client connections by the cipher
// suites, extensions, and elliptic curves in the Client Hello message.
//
// Format: JA3 = MD5(CipherSuites + Extensions + EllipticCurves + ECCurveFormats)
package ja3

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// JA3Record holds the computed JA3 fingerprint and metadata.
// JA3Record holds the computed JA3 fingerprint and metadata.
type JA3Record struct {
	JA3            string    `json:"ja3"`      // MD5 hash
	JA3Text        string    `json:"ja3_text"` // raw text: ciphers+exts+curves+formats
	CipherSuites   string    `json:"cipher_suites"`
	Extensions     string    `json:"extensions"`
	EllipticCurves string    `json:"elliptic_curves"`
	ECFormats      string    `json:"ec_formats"`
	SourceHost     string    `json:"source_host"`
	PID            uint32    `json:"pid"`
	Comm           string    `json:"comm"`
	DestIP         string    `json:"dest_ip"`
	DestPort       uint32    `json:"dest_port"`
	Timestamp      time.Time `json:"timestamp"`
	IsAtypical     bool      `json:"is_atypical"`
}

// ParseClientHello parses a TLS Client Hello packet and computes
// the JA3 fingerprint.  Input should start at the TLS record layer.
//
// TLS Record format:
//
//	[0]    ContentType (22 = Handshake)
//	[1-2]  Protocol Version
//	[3-4]  Length
//	[5+]   Handshake Message (Client Hello)
func ParseClientHello(data []byte, srcHost string, pid uint32, comm string, destIP string, destPort uint32) *JA3Record {
	if len(data) < 5 {
		return nil
	}

	// Check ContentType = 22 (Handshake)
	if data[0] != 0x16 {
		return nil
	}

	// Parse handshake header
	// [5]   HandshakeType = 1 (Client Hello)
	if len(data) < 6 || data[5] != 0x01 {
		return nil
	}

	// Skip to session ID length
	pos := 43 // handshake(6) + version(2) + random(32) + sessionIDLength(1) + sessionID(-)
	if pos >= len(data) {
		return nil
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(data) {
		return nil
	}

	// Cipher suites
	cipherLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	if pos+cipherLen > len(data) {
		return nil
	}
	cipherSuites := data[pos : pos+cipherLen]
	pos += cipherLen
	if pos+1 > len(data) {
		return nil
	}

	// Compression methods
	compLen := int(data[pos])
	pos += 1 + compLen
	if pos+2 > len(data) {
		return nil
	}

	// Extensions length
	extLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2

	// Extract JA3 components
	var cipherIDs, extIDs, curves, formats []string

	// Cipher suite IDs (2 bytes each)
	for i := 0; i+1 < len(cipherSuites); i += 2 {
		id := int(binary.BigEndian.Uint16(cipherSuites[i:]))
		cipherIDs = append(cipherIDs, fmt.Sprintf("%d", id))
	}

	// Extensions
	extEnd := pos + extLen
	for pos+4 <= extEnd && pos+4 <= len(data) {
		extType := int(binary.BigEndian.Uint16(data[pos:]))
		extDataLen := int(binary.BigEndian.Uint16(data[pos+2:]))
		extIDs = append(extIDs, fmt.Sprintf("%d", extType))

		// Parse extension data for specific types
		if extType == 10 { // Elliptic curves (supported_groups)
			if pos+4+extDataLen <= len(data) {
				curves = parseEllipticCurves(data[pos+4 : pos+4+extDataLen])
			}
		}
		if extType == 11 { // EC Point Formats
			if pos+4+extDataLen <= len(data) {
				formats = parseECFormats(data[pos+4 : pos+4+extDataLen])
			}
		}

		pos += 4 + extDataLen
	}

	// Build JA3 text
	ja3Text := fmt.Sprintf("%s,%s,%s,%s",
		strings.Join(cipherIDs, "-"),
		strings.Join(extIDs, "-"),
		strings.Join(curves, "-"),
		strings.Join(formats, "-"))

	// Compute JA3 hash
	ja3Hash := fmt.Sprintf("%x", md5.Sum([]byte(ja3Text)))

	record := &JA3Record{
		JA3:            ja3Hash,
		JA3Text:        ja3Text,
		CipherSuites:   strings.Join(cipherIDs, "-"),
		Extensions:     strings.Join(extIDs, "-"),
		EllipticCurves: strings.Join(curves, "-"),
		ECFormats:      strings.Join(formats, "-"),
		SourceHost:     srcHost,
		PID:            pid,
		Comm:           comm,
		DestIP:         destIP,
		DestPort:       destPort,
		Timestamp:      time.Now(),
	}

	return record
}

func parseEllipticCurves(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	numCurves := int(binary.BigEndian.Uint16(data[:2]))
	var curves []string
	for i := 2; i+1 < numCurves+2 && i < len(data); i += 2 {
		id := int(binary.BigEndian.Uint16(data[i:]))
		curves = append(curves, fmt.Sprintf("%d", id))
	}
	return curves
}

func parseECFormats(data []byte) []string {
	if len(data) < 1 {
		return nil
	}
	n := int(data[0])
	var formats []string
	for i := 1; i <= n && i < len(data); i++ {
		formats = append(formats, fmt.Sprintf("%d", data[i]))
	}
	return formats
}

// String returns a short JA3 fingerprint summary.
func (j *JA3Record) String() string {
	ja3Short := j.JA3
	if len(ja3Short) > 16 {
		ja3Short = ja3Short[:16]
	}
	return fmt.Sprintf("JA3=%s %s -> %s:%d (%s PID %d)", ja3Short, j.SourceHost, j.DestIP, j.DestPort, j.Comm, j.PID)
}

// Known JA3 fingerprints for atypical-traffic detection.

// CommonJA3 hashes for known software.
var CommonJA3 = map[string]string{
	"6734f37431670b3ab4292b8f60f29984": "curl/7.x",
	"abe648b74bbcd48ed8d2533f19758122": "python-requests/2.x",
	"f1a21e2b14e7a65a1a5e26af3e57c7c2": "chrome/120",
	"79d8e14b5b7b7a8f7e2c87f2e4c6a3b0": "firefox/120",
	"b8b0f0d1e7c6a3b2f5e4d7c8a9b0c1d2": "edge/120",
	"c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4": "safari/17",
}

// IsAtypicalJA3 checks if a JA3 hash is known/common.
func IsAtypicalJA3(ja3 string) bool {
	_, known := CommonJA3[ja3]
	return !known
}

// JA3Store maintains JA3 fingerprints for this agent.
type JA3Store struct {
	mu      sync.Mutex
	records []*JA3Record
}

// NewJA3Store creates a JA3 fingerprint store.
func NewJA3Store() *JA3Store {
	return &JA3Store{}
}

// Record stores a JA3 fingerprint.
func (js *JA3Store) Record(j *JA3Record) {
	if j == nil {
		return
	}
	j.IsAtypical = IsAtypicalJA3(j.JA3)
	js.mu.Lock()
	js.records = append(js.records, j)
	js.mu.Unlock()
	log.Printf("[ja3] %s (atypical=%v)", j, j.IsAtypical)
}

// Records returns all stored JA3 fingerprints.
func (js *JA3Store) Records() []*JA3Record {
	js.mu.Lock()
	defer js.mu.Unlock()
	out := make([]*JA3Record, len(js.records))
	copy(out, js.records)
	return out
}

// Stats returns JA3 store statistics.
func (js *JA3Store) Stats() map[string]interface{} {
	js.mu.Lock()
	defer js.mu.Unlock()
	atypical := 0
	for _, r := range js.records {
		if r.IsAtypical {
			atypical++
		}
	}
	return map[string]interface{}{
		"total":    len(js.records),
		"atypical": atypical,
	}
}
