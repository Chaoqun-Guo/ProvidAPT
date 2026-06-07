// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package chain provides forensic-grade data integrity for ProvidAPT v2.1.
//
// Features:
//   1. Hash chaining — each event includes the hash of the previous event
//   2. Merkle tree — periodic root hash computation
//   3. Anchoring — root hash written to /dev/kmsg and remote server
//   4. Verification — CLI tool to detect tampering
package chain

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Hash chain
// ═══════════════════════════════════════════════════════════════

// ChainRecord is a single entry in the hash chain.
type ChainRecord struct {
	Index      int64  `json:"index"`
	Timestamp  int64  `json:"timestamp_ns"`
	EventType  uint32 `json:"event_type"`
	DataHash   string `json:"data_hash"`   // SHA256 of the event payload
	PrevHash   string `json:"prev_hash"`   // hash of previous ChainRecord
	ChainHash  string `json:"chain_hash"`  // SHA256(this record)
	HMAC       string `json:"hmac"`        // HMAC-SHA256 of chain_hash
}

// ChainStore manages the hash chain.
type ChainStore struct {
	mu       sync.Mutex
	records  []*ChainRecord
	prevHash string
	hmacKey  []byte
}

// NewChainStore creates a hash chain store.
func NewChainStore() *ChainStore {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// Fallback: use timestamp-based key (degraded security, but non-fatal)
		// In production, this should log a critical alert.
		h := sha256.Sum256([]byte(fmt.Sprintf("providapt-fallback-%d", time.Now().UnixNano())))
		key = h[:]
	}
	return &ChainStore{
		hmacKey: key,
	}
}

// Add creates a new chain record for an event.
func (cs *ChainStore) Add(eventType uint32, data []byte) *ChainRecord {
	dataHash := sha256.Sum256(data)
	now := time.Now().UnixNano()

	cs.mu.Lock()
	defer cs.mu.Unlock()

	rec := &ChainRecord{
		Index:     int64(len(cs.records) + 1),
		Timestamp: now,
		EventType: eventType,
		DataHash:  hex.EncodeToString(dataHash[:]),
		PrevHash:  cs.prevHash,
	}

	// Compute chain hash: SHA256(index + timestamp + dataHash + prevHash)
	chainInput := fmt.Sprintf("%d:%d:%s:%s", rec.Index, rec.Timestamp, rec.DataHash, rec.PrevHash)
	chainHash := sha256.Sum256([]byte(chainInput))
	rec.ChainHash = hex.EncodeToString(chainHash[:])

	// HMAC signature
	mac := hmac.New(sha256.New, cs.hmacKey)
	mac.Write([]byte(rec.ChainHash))
	rec.HMAC = hex.EncodeToString(mac.Sum(nil))

	cs.records = append(cs.records, rec)
	cs.prevHash = rec.ChainHash

	return rec
}

// VerifyRecord checks a chain record's integrity.
func (cs *ChainStore) VerifyRecord(rec *ChainRecord) bool {
	// Verify HMAC
	mac := hmac.New(sha256.New, cs.hmacKey)
	mac.Write([]byte(rec.ChainHash))
	expectedHMAC := hex.EncodeToString(mac.Sum(nil))
	if rec.HMAC != expectedHMAC {
		return false
	}

	// Verify chain hash
	chainInput := fmt.Sprintf("%d:%d:%s:%s", rec.Index, rec.Timestamp, rec.DataHash, rec.PrevHash)
	chainHash := sha256.Sum256([]byte(chainInput))
	return rec.ChainHash == hex.EncodeToString(chainHash[:])
}

// VerifyChain checks the integrity of the entire chain.
func (cs *ChainStore) VerifyChain() (bool, int) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	for i, rec := range cs.records {
		// Verify record integrity
		if !cs.verifyRecord(rec) {
			return false, i
		}

		// Verify chain linkage
		if i > 0 {
			if rec.PrevHash != cs.records[i-1].ChainHash {
				return false, i
			}
		}
	}
	return true, len(cs.records)
}

func (cs *ChainStore) verifyRecord(rec *ChainRecord) bool {
	mac := hmac.New(sha256.New, cs.hmacKey)
	mac.Write([]byte(rec.ChainHash))
	expectedHMAC := hex.EncodeToString(mac.Sum(nil))
	if rec.HMAC != expectedHMAC {
		return false
	}
	chainInput := fmt.Sprintf("%d:%d:%s:%s", rec.Index, rec.Timestamp, rec.DataHash, rec.PrevHash)
	chainHash := sha256.Sum256([]byte(chainInput))
	return rec.ChainHash == hex.EncodeToString(chainHash[:])
}

// LatestHash returns the hash of the most recent record.
func (cs *ChainStore) LatestHash() string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if len(cs.records) == 0 {
		return "0000000000000000000000000000000000000000"
	}
	return cs.records[len(cs.records)-1].ChainHash
}

// RootHash returns the Merkle-style root hash.
func (cs *ChainStore) RootHash() string {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if len(cs.records) == 0 {
		return hex.EncodeToString(sha256.New().Sum(nil))
	}

	// Build Merkle tree from chain hashes
	hashes := make([][]byte, len(cs.records))
	for i, rec := range cs.records {
		h, _ := hex.DecodeString(rec.ChainHash)
		hashes[i] = h
	}

	// Pairwise reduction
	for len(hashes) > 1 {
		var next [][]byte
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				combined := append(hashes[i], hashes[i+1]...)
				h := sha256.Sum256(combined)
				next = append(next, h[:])
			} else {
				next = append(next, hashes[i])
			}
		}
		hashes = next
	}

	return hex.EncodeToString(hashes[0])
}

// Count returns the number of records in the chain.
func (cs *ChainStore) Count() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return len(cs.records)
}
