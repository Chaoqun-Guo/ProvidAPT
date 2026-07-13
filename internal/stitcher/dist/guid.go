// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package dist implements distributed system infrastructure for ProvidAPT.
//
// Features:
// 1. Global Entity ID -HostID + BootID for globally unique identifiers
// 2. gRPC streaming -non-blocking telemetry pipeline with reconnection
// 3. Metadata compression -dictionary-based GUID compression
package dist

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"
)

// Global Entity ID (GUID)

// GUID represents a globally unique entity identifier.
type GUID struct {
	HostID  string `json:"host_id"`  // system UUID or hostname
	BootID  string `json:"boot_id"`  // system boot ID (/proc/sys/kernel/random/boot_id)
	LocalID string `json:"local_id"` // local entity ID (e.g., "p:1234")
	FullID  string `json:"full_id"`  // SHA256(HostID + BootID + LocalID)
}

// GlobalIDStore manages unique identifiers across hosts.
type GlobalIDStore struct {
	mu     sync.Mutex
	hostID string
	bootID string
	cache  map[string]*GUID // localID -> GUID
}

// NewGlobalIDStore creates a global ID store.
func NewGlobalIDStore() *GlobalIDStore {
	g := &GlobalIDStore{
		cache: make(map[string]*GUID),
	}
	g.hostID = resolveHostID()
	g.bootID = resolveBootID()
	return g
}

// HostID returns the system's unique host identifier.
func (g *GlobalIDStore) HostID() string { return g.hostID }

// BootID returns the system's boot identifier.
func (g *GlobalIDStore) BootID() string { return g.bootID }

// GetOrCreate returns the GUID for a local entity ID.
// Creates one if it doesn't exist.
func (g *GlobalIDStore) GetOrCreate(localID string) *GUID {
	g.mu.Lock()
	defer g.mu.Unlock()

	if existing, ok := g.cache[localID]; ok {
		return existing
	}

	fullID := computeFullID(g.hostID, g.bootID, localID)
	guid := &GUID{
		HostID:  g.hostID,
		BootID:  g.bootID,
		LocalID: localID,
		FullID:  fullID,
	}
	g.cache[localID] = guid
	return guid
}

// Resolve parses a FullID back into its components.
// In production, this would query the central index.
func Resolve(fullID string) (*GUID, bool) {
	// FullID = SHA256(HostID + BootID + LocalID) -64 hex chars
	// This is one-way; for reverse lookup, query the central RocksDB.
	if len(fullID) != 64 {
		return nil, false
	}
	return &GUID{FullID: fullID}, true
}

// computeFullID computes a globally unique hash.
func computeFullID(hostID, bootID, localID string) string {
	input := fmt.Sprintf("%s|%s|%s", hostID, bootID, localID)
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// Host/Boot ID resolution

func resolveHostID() string {
	// Try /etc/machine-id (systemd)
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		return string(trimSpace(data))
	}
	// Fallback: /etc/hostname
	if data, err := os.ReadFile("/etc/hostname"); err == nil {
		return string(trimSpace(data))
	}
	// Final fallback: hostname command
	if host, err := os.Hostname(); err == nil {
		return host
	}
	return "unknown-host"
}

func resolveBootID() string {
	// /proc/sys/kernel/random/boot_id -unique per boot
	if data, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		return string(trimSpace(data))
	}
	return fmt.Sprintf("boot-%d", time.Now().UnixNano())
}

func trimSpace(data []byte) []byte {
	for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == ' ') {
		data = data[:len(data)-1]
	}
	return data
}
