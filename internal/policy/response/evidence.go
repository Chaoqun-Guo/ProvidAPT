// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package response

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Evidence locking
//
// HMACKeySize is the number of bytes for the HMAC key.
const HMACKeySize = 32

// EvidenceRecord is the complete forensic evidence package.
type EvidenceRecord struct {
	// Metadata
	CaseID      string    `json:"case_id"`
	Timestamp   time.Time `json:"timestamp"`
	AlertID     string    `json:"alert_id"`
	ThreatScore float64   `json:"threat_score"`

	// Process identity
	PID  int    `json:"pid"`
	Comm string `json:"comm"`

	// Data hashes (SHA256)
	MemoryDumpHash string `json:"memory_dump_hash"` // hex
	CaptureHash    string `json:"capture_hash"`     // hex
	GraphPathHash  string `json:"graph_path_hash"`  // hex

	// Graph binding -?provenance path summary
	GraphPathSummary string `json:"graph_path_summary"`

	// File locations
	DumpDir string `json:"dump_dir,omitempty"`
	CapFile string `json:"cap_file,omitempty"`

	// HMAC-SHA256 signature over all fields above
	Signature string `json:"signature"` // hex
}

// EvidenceStore persists evidence records.
type EvidenceStore interface {
	Put(key string, value []byte) error
	Get(key string) ([]byte, error)
}

// EvidenceManager handles evidence creation, signing, and verification.
type EvidenceManager struct {
	hmacKey []byte
	store   EvidenceStore
}

// NewEvidenceManager creates an evidence manager with a random key.
func NewEvidenceManager(store EvidenceStore) *EvidenceManager {
	key := make([]byte, HMACKeySize)
	rand.Read(key)
	return &EvidenceManager{
		hmacKey: key,
		store:   store,
	}
}

// NewEvidenceManagerWithKey creates a manager with a specific key (for testing).
func NewEvidenceManagerWithKey(store EvidenceStore, key []byte) *EvidenceManager {
	return &EvidenceManager{
		hmacKey: key,
		store:   store,
	}
}

// CreateEvidence builds, signs, and stores an evidence record.
func (em *EvidenceManager) CreateEvidence(
	alertID string,
	score float64,
	pid int,
	comm string,
	dumpHash, capHash, graphHash string,
	graphSummary string,
	dumpDir, capFile string,
) (*EvidenceRecord, error) {

	rec := &EvidenceRecord{
		CaseID:           fmt.Sprintf("CASE-%s-%d", alertID, time.Now().Unix()),
		Timestamp:        time.Now().UTC(),
		AlertID:          alertID,
		ThreatScore:      score,
		PID:              pid,
		Comm:             comm,
		MemoryDumpHash:   dumpHash,
		CaptureHash:      capHash,
		GraphPathHash:    graphHash,
		GraphPathSummary: graphSummary,
		DumpDir:          dumpDir,
		CapFile:          capFile,
	}

	// Sign all fields
	sig, err := em.Sign(rec)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	rec.Signature = hex.EncodeToString(sig)

	// Persist
	if em.store != nil {
		key := fmt.Sprintf("evidence:%s", rec.CaseID)
		data, _ := json.Marshal(rec)
		if err := em.store.Put(key, data); err != nil {
			return nil, fmt.Errorf("store: %w", err)
		}
	}

	return rec, nil
}

// Sign computes HMAC-SHA256 over the record's serialized fields.
// The signature covers all fields except the signature itself.
func (em *EvidenceManager) Sign(rec *EvidenceRecord) ([]byte, error) {
	// Serialize all fields except Signature
	data := fmt.Sprintf("%s|%d|%s|%.2f|%d|%s|%s|%s|%s|%s|%s|%s",
		rec.CaseID, rec.Timestamp.UnixNano(), rec.AlertID, rec.ThreatScore,
		rec.PID, rec.Comm,
		rec.MemoryDumpHash, rec.CaptureHash, rec.GraphPathHash,
		rec.GraphPathSummary, rec.DumpDir, rec.CapFile,
	)

	mac := hmac.New(sha256.New, em.hmacKey)
	mac.Write([]byte(data))
	return mac.Sum(nil), nil
}

// Verify checks the HMAC signature of an evidence record.
func (em *EvidenceManager) Verify(rec *EvidenceRecord) (bool, error) {
	expected, err := em.Sign(rec)
	if err != nil {
		return false, err
	}
	sig, err := hex.DecodeString(rec.Signature)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	return hmac.Equal(sig, expected), nil
}

// GetEvidence retrieves and verifies an evidence record from the store.
func (em *EvidenceManager) GetEvidence(caseID string) (*EvidenceRecord, bool, error) {
	if em.store == nil {
		return nil, false, fmt.Errorf("no store")
	}
	data, err := em.store.Get(fmt.Sprintf("evidence:%s", caseID))
	if err != nil || data == nil {
		return nil, false, err
	}
	var rec EvidenceRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, false, err
	}
	valid, err := em.Verify(&rec)
	return &rec, valid, err
}

// HMACKeyHex returns the hex-encoded HMAC key (for backup).
func (em *EvidenceManager) HMACKeyHex() string {
	return hex.EncodeToString(em.hmacKey)
}
