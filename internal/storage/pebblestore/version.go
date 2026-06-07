// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package store — entity versioning for provenance data.
//
// When a file is written and later read, new version nodes are
// created to preserve the causal DAG structure:
//
//   v1 ──wasDerivedFrom──▶ process ──wasGeneratedBy──▶ v2
//   (old)                    │                        (new)
//                         (writer)
//
// Storage key: v:<inode>:<dev_major>:<dev_minor>:<version>
// Version edges stored as regular edges in the edge index.
package pebblestore

import (
	"fmt"
	"sort"
	"sync"
)

// ─── Version constants ──────────────────────────────────────

const versionPrefix = "v:"

// ─── VersionTracker ─────────────────────────────────────────

// VersionTracker manages per-file version numbers.
// Thread-safe.
type VersionTracker struct {
	mu      sync.Mutex
	latest  map[string]int64 // fileKey → current version
}

// fileKey builds a unique key for a file from its inode and device.
func fileKey(inode uint64, devMajor, devMinor uint32) string {
	return fmt.Sprintf("%d:%d:%d", inode, devMajor, devMinor)
}

// NewVersionTracker creates a version tracker.
func NewVersionTracker() *VersionTracker {
	return &VersionTracker{
		latest: make(map[string]int64),
	}
}

// VersionID returns the versioned node ID for a file at a given version.
// Format: "v:<inode>:<dev_major>:<dev_minor>:<version>"
func VersionID(inode uint64, devMajor, devMinor uint32, version int64) string {
	return fmt.Sprintf("%s%d:%d:%d:%d", versionPrefix, inode, devMajor, devMinor, version)
}

// BaseNodeID returns the unversioned base identifier.
// Format: "f:<inode>:<dev_major>:<dev_minor>"
func BaseNodeID(inode uint64, devMajor, devMinor uint32) string {
	return fmt.Sprintf("f:%d:%d:%d", inode, devMajor, devMinor)
}

// ─── Version operations ─────────────────────────────────────

// InitVersion ensures a file has version 1.  Returns the version ID.
func (vt *VersionTracker) InitVersion(inode uint64, devMajor, devMinor uint32) string {
	key := fileKey(inode, devMajor, devMinor)
	vt.mu.Lock()
	defer vt.mu.Unlock()
	if _, ok := vt.latest[key]; !ok {
		vt.latest[key] = 1
	}
	return VersionID(inode, devMajor, devMinor, vt.latest[key])
}

// NextVersion increments the version counter and returns both the
// previous and new version IDs.
//
// Returns (prevVersionID, newVersionID).
func (vt *VersionTracker) NextVersion(inode uint64, devMajor, devMinor uint32) (string, string) {
	key := fileKey(inode, devMajor, devMinor)
	vt.mu.Lock()
	defer vt.mu.Unlock()

	prev := vt.latest[key]
	if prev == 0 {
		prev = 1
	}
	prevID := VersionID(inode, devMajor, devMinor, prev)

	vt.latest[key] = prev + 1
	newID := VersionID(inode, devMajor, devMinor, vt.latest[key])

	return prevID, newID
}

// LatestVersion returns the current version ID for a file.
func (vt *VersionTracker) LatestVersion(inode uint64, devMajor, devMinor uint32) string {
	key := fileKey(inode, devMajor, devMinor)
	vt.mu.Lock()
	defer vt.mu.Unlock()
	ver := vt.latest[key]
	if ver == 0 {
		ver = 1
	}
	return VersionID(inode, devMajor, devMinor, ver)
}

// CurrentVersion returns the raw version number.
func (vt *VersionTracker) CurrentVersion(inode uint64, devMajor, devMinor uint32) int64 {
	key := fileKey(inode, devMajor, devMinor)
	vt.mu.Lock()
	defer vt.mu.Unlock()
	return vt.latest[key]
}

// ─── Version record (persisted in RocksDB) ──────────────────

// VersionRecord stores the metadata for a single version change.
type VersionRecord struct {
	VersionID    string `json:"version_id"`
	Inode        uint64 `json:"inode"`
	DevMajor     uint32 `json:"dev_major"`
	DevMinor     uint32 `json:"dev_minor"`
	VersionNum   int64  `json:"version_num"`
	TriggerPID   uint32 `json:"trigger_pid"`
	TriggerComm  string `json:"trigger_comm"`
	Operation    string `json:"operation"` // "write", "read"
	PrevVersion  string `json:"prev_version,omitempty"`
	TimestampNS  uint64 `json:"timestamp_ns"`
}

// VersionEdge returns the edge description between versions.
// Direction: old_version ──wasDerivedFrom──▶ process ──wasGeneratedBy──▶ new_version
func (vr *VersionRecord) ProcessEdge() string {
	return fmt.Sprintf("%s ──wasDerivedFrom──▶ p:%d ──wasGeneratedBy──▶ %s",
		vr.PrevVersion, vr.TriggerPID, vr.VersionID)
}

// VersionStore manages version records in the database.
type VersionStore struct {
	vt      *VersionTracker
	records map[string]*VersionRecord // versionID → record
	mu      sync.RWMutex
}

// NewVersionStore creates a version store.
func NewVersionStore() *VersionStore {
	return &VersionStore{
		vt:      NewVersionTracker(),
		records: make(map[string]*VersionRecord),
	}
}

// RecordWrite creates a new version for a file write operation.
// Returns the new version ID and the version record.
func (vs *VersionStore) RecordWrite(inode uint64, devMajor, devMinor uint32,
	pid uint32, comm string, timestamp uint64) (string, *VersionRecord) {

	prevID, newID := vs.vt.NextVersion(inode, devMajor, devMinor)
	rec := &VersionRecord{
		VersionID:   newID,
		Inode:       inode,
		DevMajor:    devMajor,
		DevMinor:    devMinor,
		VersionNum:  vs.vt.CurrentVersion(inode, devMajor, devMinor),
		TriggerPID:  pid,
		TriggerComm: comm,
		Operation:   "write",
		PrevVersion: prevID,
		TimestampNS: timestamp,
	}

	vs.mu.Lock()
	vs.records[newID] = rec
	vs.mu.Unlock()

	return newID, rec
}

// RecordRead records that a process read the current version.
// If the file has been written before, returns the version info.
// Does NOT create a new version (reads don't change state).
func (vs *VersionStore) RecordRead(inode uint64, devMajor, devMinor uint32,
	pid uint32, comm string, timestamp uint64) *VersionRecord {

	versionID := vs.vt.LatestVersion(inode, devMajor, devMinor)

	vs.mu.RLock()
	existing, ok := vs.records[versionID]
	vs.mu.RUnlock()

	if ok {
		return existing
	}

	// No existing record — first access (implicit v1)
	return &VersionRecord{
		VersionID:  versionID,
		Inode:      inode,
		DevMajor:   devMajor,
		DevMinor:   devMinor,
		VersionNum: 1,
		Operation:  "read",
		TimestampNS: timestamp,
	}
}

// GetVersion retrieves a version record by version ID.
func (vs *VersionStore) GetVersion(versionID string) *VersionRecord {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	return vs.records[versionID]
}

// GetHistory returns all versions of a file, ordered oldest first.
func (vs *VersionStore) GetHistory(inode uint64, devMajor, devMinor uint32) []*VersionRecord {
	baseKey := fileKey(inode, devMajor, devMinor)
	prefix := fmt.Sprintf("%s%s:", versionPrefix, baseKey)

	vs.mu.RLock()
	defer vs.mu.RUnlock()

	var history []*VersionRecord
	for id, rec := range vs.records {
		if len(id) >= len(prefix) && id[:len(prefix)] == prefix {
			history = append(history, rec)
		}
	}
	sort.Slice(history, func(i, j int) bool {
		return history[i].VersionNum < history[j].VersionNum
	})
	return history
}

// VersionCount returns the total number of tracked versions.
func (vs *VersionStore) VersionCount() int {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	return len(vs.records)
}
