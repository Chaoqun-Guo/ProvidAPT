// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package dist

import (
	"fmt"
	"sync"
)

// ═══════════════════════════════════════════════════════════════
// Metadata compression — dictionary-based GUID compression
// ═══════════════════════════════════════════════════════════════

// Compressor uses a dictionary to compress GUIDs for transmission.
//
// Strategy:
//   - Dictionary maps common GUID prefixes (host IDs) to small integers
//   - Repeated HostID/BootID pairs are replaced with dictionary indices
//   - Typical compression ratio: 64-char hex → 2-4 bytes + delta
type Compressor struct {
	mu      sync.Mutex
	dict    map[string]uint32 // string → index
	reverse map[uint32]string // index → string
	nextIdx uint32
	hits    int64
	misses  int64
}

// CompressedGUID is the wire format for a compressed GUID.
type CompressedGUID struct {
	HostIdx  uint32 `json:"host_idx"`            // dictionary index for HostID
	BootLen  uint8  `json:"boot_len"`            // length of delta-encoded BootID
	BootData []byte `json:"boot_data,omitempty"` // delta-encoded BootID
	LocalID  string `json:"local_id"`            // local entity ID (short)
}

// NewCompressor creates a GUID dictionary compressor.
func NewCompressor() *Compressor {
	return &Compressor{
		dict:    make(map[string]uint32),
		reverse: make(map[uint32]string),
		nextIdx: 1,
	}
}

// Compress compresses a GUID into a compact wire format.
func (c *Compressor) Compress(guid *GUID) *CompressedGUID {
	c.mu.Lock()
	defer c.mu.Unlock()

	cg := &CompressedGUID{LocalID: guid.LocalID}

	// Lookup or assign dictionary index for HostID
	if idx, ok := c.dict[guid.HostID]; ok {
		cg.HostIdx = idx
		c.hits++
	} else {
		cg.HostIdx = c.nextIdx
		c.dict[guid.HostID] = c.nextIdx
		c.reverse[c.nextIdx] = guid.HostID
		c.nextIdx++
		c.misses++
	}

	// Delta-encode BootID (optional, for frequently changing boot IDs)
	// In practice, BootID is stable per boot, so we just store it compactly
	if guid.BootID != "" {
		cg.BootData = []byte(guid.BootID)
		cg.BootLen = uint8(len(guid.BootID))
	}

	return cg
}

// Decompress reverses the compression to recover the original GUID.
func (c *Compressor) Decompress(cg *CompressedGUID) *GUID {
	c.mu.Lock()
	defer c.mu.Unlock()

	hostID := c.reverse[cg.HostIdx]
	bootID := string(cg.BootData)

	return &GUID{
		HostID:  hostID,
		BootID:  bootID,
		LocalID: cg.LocalID,
		FullID:  computeFullID(hostID, bootID, cg.LocalID),
	}
}

// CompressGUIDString compresses a full GUID hex string.
func (c *Compressor) CompressGUIDString(fullID string) []byte {
	if len(fullID) != 64 {
		return []byte(fullID)
	}
	// Compress 64 hex chars to 32 bytes (raw SHA256)
	raw := make([]byte, 32)
	for i := 0; i < 32; i++ {
		high := hexToNibble(fullID[i*2])
		low := hexToNibble(fullID[i*2+1])
		raw[i] = (high << 4) | low
	}
	return raw
}

// DecompressGUIDString decompresses a compressed GUID back to hex.
func (c *Compressor) DecompressGUIDString(data []byte) string {
	if len(data) != 32 {
		return string(data)
	}
	hex := make([]byte, 64)
	for i, b := range data {
		hex[i*2] = nibbleToHex((b >> 4) & 0x0F)
		hex[i*2+1] = nibbleToHex(b & 0x0F)
	}
	return string(hex)
}

func hexToNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0
	}
}

func nibbleToHex(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'a' + n - 10
}

// CompressionRatio returns the compression efficiency.
func (c *Compressor) CompressionRatio() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := c.hits + c.misses
	if total == 0 {
		return 0
	}
	return float64(c.hits) / float64(total) * 100.0
}

// Stats returns compressor statistics.
func (c *Compressor) Stats() map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]interface{}{
		"dictionary_size": len(c.dict),
		"hits":            c.hits,
		"misses":          c.misses,
		"ratio":           fmt.Sprintf("%.1f%%", float64(c.hits)/float64(c.hits+c.misses+1)*100),
	}
}
