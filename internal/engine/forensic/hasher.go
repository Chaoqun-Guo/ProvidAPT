// Package forensic provides binary analysis and threat detection
// capabilities for provenance process nodes.
//
// Features:
//   1. SHA-256 hashing — auto-compute binary hash on execve
//   2. YARA scanning — trigger YARA on suspicious binaries
//   3. Binary anomaly detection — detect memory execution / file replace
package forensic

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ═══════════════════════════════════════════════════════════════
// File hashing
// ═══════════════════════════════════════════════════════════════

// Hasher computes and caches SHA-256 hashes for executable files.
type Hasher struct {
	mu     sync.Mutex
	cache  map[string]string // path → sha256 hex
}

// NewHasher creates a file hasher with an LRU-ish cache.
func NewHasher() *Hasher {
	return &Hasher{
		cache: make(map[string]string),
	}
}

// HashFile computes the SHA-256 hash of a file.
// Results are cached to avoid re-reading the same file.
func (h *Hasher) HashFile(path string) (string, error) {
	h.mu.Lock()
	if hash, ok := h.cache[path]; ok {
		h.mu.Unlock()
		return hash, nil
	}
	h.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}

	hash := sha256.Sum256(data)
	hexHash := hex.EncodeToString(hash[:])

	h.mu.Lock()
	h.cache[path] = hexHash
	h.mu.Unlock()

	return hexHash, nil
}

// HashPathFromInode attempts to resolve a path from inode info
// and compute its hash.  This is a best-effort operation.
func (h *Hasher) HashPathFromInode(path string) (string, error) {
	if path == "" || path == "?" {
		return "", fmt.Errorf("no valid path")
	}
	// Resolve symlinks (handle /proc/pid/exe style paths)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		// Use the original path if symlink resolution fails
		resolved = path
	}
	return h.HashFile(resolved)
}

// HashHex returns the hex-encoded SHA-256 string for a byte slice.
func HashHex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// CacheStats returns cache performance information.
func (h *Hasher) CacheStats() map[string]int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return map[string]int{
		"cached_hashes": len(h.cache),
	}
}
