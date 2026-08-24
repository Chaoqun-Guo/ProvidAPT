// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package secure provides forensic-grade storage security for
// ProvidAPT provenance data.  It implements:
//
//  1. Merkle tree hash chain — every event is a leaf in a binary
//     Merkle tree.  The root hash is anchored to protected kernel
//     memory and/or a remote trusted log server.
//
//  2. SST file signing — each RocksDB SST file is HMAC-signed
//     after compaction to detect offline tampering.
//
//  3. Self-verification — standalone tool that scans all stored
//     data and verifies the hash chain integrity.
package secure

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Merkle tree
// ═══════════════════════════════════════════════════════════════

// MerkleTree is a binary hash tree over a series of events.
// Each event becomes a leaf node; internal nodes are H(left+right).
type MerkleTree struct {
	leaves   [][]byte   // leaf hashes (SHA256 of event data)
	nodes    [][][]byte // tree levels: nodes[0]=leaves, nodes[last]=root
	rootHash []byte
	mu       sync.RWMutex
}

// NewMerkleTree creates an empty Merkle tree.
func NewMerkleTree() *MerkleTree {
	return &MerkleTree{}
}

// HashEvent computes the SHA256 hash of event data.
func HashEvent(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// AddLeaf appends an event hash as a new leaf and recalculates
// the tree path to the root.
func (mt *MerkleTree) AddLeaf(hash []byte) {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	mt.leaves = append(mt.leaves, hash)
	mt.rebuild()
}

// Root returns the current root hash.
func (mt *MerkleTree) Root() []byte {
	mt.mu.RLock()
	defer mt.mu.RUnlock()
	return mt.rootHash
}

// RootHex returns the root hash as a hex string.
func (mt *MerkleTree) RootHex() string {
	r := mt.Root()
	if r == nil {
		return "0000000000000000000000000000000000000000000000000000000000000000"
	}
	return hex.EncodeToString(r)
}

// rebuild recalculates all tree levels from leaves.
func (mt *MerkleTree) rebuild() {
	if len(mt.leaves) == 0 {
		mt.rootHash = nil
		mt.nodes = nil
		return
	}

	// Build tree bottom-up
	current := mt.leaves
	mt.nodes = [][][]byte{current}

	for len(current) > 1 {
		var next [][]byte
		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				combined := append(current[i], current[i+1]...)
				h := sha256.Sum256(combined)
				next = append(next, h[:])
			} else {
				// Odd leaf — promote to next level
				next = append(next, current[i])
			}
		}
		mt.nodes = append(mt.nodes, next)
		current = next
	}

	if len(current) == 1 {
		mt.rootHash = current[0]
	}
}

// Proof generates a Merkle proof for leaf at index i.
// The proof contains the sibling hashes needed to reconstruct the root.
func (mt *MerkleTree) Proof(idx int) ([][]byte, error) {
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	if idx < 0 || idx >= len(mt.leaves) {
		return nil, fmt.Errorf("leaf index %d out of range", idx)
	}

	var proof [][]byte
	currentIdx := idx

	for level := 0; level < len(mt.nodes)-1; level++ {
		nodes := mt.nodes[level]
		var siblingIdx int
		if currentIdx%2 == 0 {
			siblingIdx = currentIdx + 1
		} else {
			siblingIdx = currentIdx - 1
		}

		if siblingIdx < len(nodes) {
			proof = append(proof, nodes[siblingIdx])
		}

		currentIdx /= 2
	}

	return proof, nil
}

// VerifyProof checks that a leaf at the given index leads to the
// expected root hash.
func VerifyProof(leaf []byte, proof [][]byte, idx int, expectedRoot []byte) bool {
	current := leaf
	currentIdx := idx

	for _, sibling := range proof {
		var combined []byte
		if currentIdx%2 == 0 {
			combined = append(current, sibling...)
		} else {
			combined = append(sibling, current...)
		}
		h := sha256.Sum256(combined)
		current = h[:]
		currentIdx /= 2
	}

	return hmac.Equal(current, expectedRoot)
}

// LeafCount returns the number of leaves in the tree.
func (mt *MerkleTree) LeafCount() int {
	mt.mu.RLock()
	defer mt.mu.RUnlock()
	return len(mt.leaves)
}

// ═══════════════════════════════════════════════════════════════
// Root hash anchoring
// ═══════════════════════════════════════════════════════════════

// AnchorRecord is a timestamped root hash that gets sent to a
// trusted log server or stored in protected kernel memory.
type AnchorRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	LeafCount   int       `json:"leaf_count"`
	RootHashHex string    `json:"root_hash"`
	Signature   string    `json:"signature"` // HMAC of the above
}

// AnchorStore persists root hash anchors.
type AnchorStore interface {
	Put(key string, value []byte) error
	Get(key string) ([]byte, error)
}

// MerkleAnchoring manages periodic anchoring of root hashes.
type MerkleAnchoring struct {
	tree       *MerkleTree
	store      AnchorStore
	hmacKey    []byte
	anchors    []*AnchorRecord
	interval   time.Duration
	lastAnchor time.Time
}

// NewMerkleAnchoring creates an anchoring manager.
// The hmacKey must be persisted across restarts (see LoadOrGenerateHMACKey).
func NewMerkleAnchoring(tree *MerkleTree, store AnchorStore, interval time.Duration, hmacKey []byte) *MerkleAnchoring {
	return &MerkleAnchoring{
		tree:       tree,
		store:      store,
		hmacKey:    hmacKey,
		interval:   interval,
		lastAnchor: time.Now(),
	}
}

// MaybeAnchor checks if it's time to anchor the root hash.
// If so, creates an AnchorRecord, signs it, and persists it.
func (ma *MerkleAnchoring) MaybeAnchor() (*AnchorRecord, error) {
	if time.Since(ma.lastAnchor) < ma.interval {
		return nil, nil
	}

	rootHex := ma.tree.RootHex()
	rec := &AnchorRecord{
		Timestamp:   time.Now().UTC(),
		LeafCount:   ma.tree.LeafCount(),
		RootHashHex: rootHex,
	}

	// Sign the record
	data, err := json.Marshal(map[string]interface{}{
		"ts":   rec.Timestamp.UnixNano(),
		"cnt":  rec.LeafCount,
		"root": rec.RootHashHex,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal anchor: %w", err)
	}
	mac := hmac.New(sha256.New, ma.hmacKey)
	mac.Write(data)
	rec.Signature = hex.EncodeToString(mac.Sum(nil))

	// Persist
	if ma.store != nil {
		key := fmt.Sprintf("anchor:%d", rec.Timestamp.UnixNano())
		val, err := json.Marshal(rec)
		if err != nil {
			return nil, fmt.Errorf("marshal record: %w", err)
		}
		if err := ma.store.Put(key, val); err != nil {
			return nil, fmt.Errorf("store anchor: %w", err)
		}
	}

	ma.anchors = append(ma.anchors, rec)
	ma.lastAnchor = time.Now()
	return rec, nil
}

// ═══════════════════════════════════════════════════════════════
// Key persistence
// ═══════════════════════════════════════════════════════════════

// DefaultKeyDir returns the default key directory.
func DefaultKeyDir() string {
	if d := os.Getenv("PROVIDAPT_DATA_DIR"); d != "" {
		return filepath.Join(d, "keys")
	}
	return "/var/lib/providapt/keys"
}

// LoadOrGenerateHMACKey loads an HMAC key from the given path.
// If the file doesn't exist, it generates a new random key and
// persists it atomically (write+rename).  The key file is created
// with 0600 permissions.
//
// This ensures the same key is used across restarts so that
// previously anchored Merkle roots and SST file signatures
// remain verifiable.
func LoadOrGenerateHMACKey(keyPath string, keySize int) ([]byte, error) {
	if keySize <= 0 {
		keySize = 32
	}

	// Try to load existing key
	if data, err := os.ReadFile(keyPath); err == nil {
		if len(data) == keySize {
			return data, nil
		}
		// Key file exists but wrong size — treat as corrupt, regenerate
	}

	// Generate new key
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}

	// Write atomically: temp file then rename
	tmpPath := keyPath + ".tmp"
	if err := os.WriteFile(tmpPath, key, 0600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	if err := os.Rename(tmpPath, keyPath); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("finalize key: %w", err)
	}

	return key, nil
}

// LoadOrGenerateHMACKeyDefault loads the HMAC key from the default
// location (PROVIDAPT_DATA_DIR/keys/hmac.key or
// /var/lib/providapt/keys/hmac.key).
func LoadOrGenerateHMACKeyDefault() ([]byte, error) {
	keyDir := DefaultKeyDir()
	return LoadOrGenerateHMACKey(filepath.Join(keyDir, "hmac.key"), 32)
}

// LatestAnchor returns the most recent anchor record.
func (ma *MerkleAnchoring) LatestAnchor() *AnchorRecord {
	if len(ma.anchors) == 0 {
		return nil
	}
	return ma.anchors[len(ma.anchors)-1]
}

// VerifyAnchors checks the integrity of all anchor records.
func (ma *MerkleAnchoring) VerifyAnchors() (bool, error) {
	for _, rec := range ma.anchors {
		data, _ := json.Marshal(map[string]interface{}{
			"ts":   rec.Timestamp.UnixNano(),
			"cnt":  rec.LeafCount,
			"root": rec.RootHashHex,
		})
		mac := hmac.New(sha256.New, ma.hmacKey)
		mac.Write(data)
		expected := hex.EncodeToString(mac.Sum(nil))
		if rec.Signature != expected {
			return false, fmt.Errorf("anchor %s signature mismatch", rec.Timestamp)
		}
	}
	return true, nil
}

// HashChainSummary returns a human-readable summary of the hash chain.
func (ma *MerkleAnchoring) HashChainSummary() []string {
	var lines []string
	for _, a := range ma.anchors {
		lines = append(lines, fmt.Sprintf("  anchor@%s leaves=%d root=%s sig=%s",
			a.Timestamp.Format(time.RFC3339),
			a.LeafCount,
			a.RootHashHex[:16],
			a.Signature[:16],
		))
	}
	return lines
}
