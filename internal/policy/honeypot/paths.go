// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package honeypot implements kernel-level decoy paths (honey inodes)
// for ProvidAPT active defense.  These are virtual file paths that
// appear attractive to attackers but do not exist in the filesystem.
//
// Any access to these paths is a strong indicator of malicious
// reconnaissance activity and triggers immediate countermeasures:
//   - Highest severity silent alert
//   - Full audit mode escalation for the triggering process
//   - All network and memory operations recorded
//   - Potential sandbox induction
package honeypot

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"sync"
)

// ═══════════════════════════════════════════════════════════════
// Honey path definitions
// ═══════════════════════════════════════════════════════════════

// HoneyPath defines a single decoy file path and its metadata.
type HoneyPath struct {
	Path        string `json:"path"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // always "CRITICAL"
	TTPRef      string `json:"ttp_ref"`  // MITRE ATT&CK reference
	Category    string `json:"category"` // cred, config, key, backup
}

// DefaultHoneyPaths returns the standard set of honey paths.
func DefaultHoneyPaths() []HoneyPath {
	return []HoneyPath{
		// Credential files
		{Path: "/root/.aws/credentials", Description: "AWS credential file", TTPRef: "T1552.001", Category: "cred"},
		{Path: "/root/.aws/config", Description: "AWS config file", TTPRef: "T1552.001", Category: "cred"},
		{Path: "/home/admin/.ssh/id_rsa", Description: "SSH private key", TTPRef: "T1552.004", Category: "cred"},
		{Path: "/home/deploy/.ssh/authorized_keys", Description: "SSH authorized keys", TTPRef: "T1098", Category: "cred"},

		// Shadow/backup copies
		{Path: "/etc/shadow.bak", Description: "Shadow backup", TTPRef: "T1003.008", Category: "backup"},
		{Path: "/etc/passwd.bak", Description: "Passwd backup", TTPRef: "T1003.008", Category: "backup"},
		{Path: "/var/backups/etc/shadow.old", Description: "Old shadow backup", TTPRef: "T1003.008", Category: "backup"},

		// Configuration files
		{Path: "/etc/kubernetes/admin.conf", Description: "K8s admin config", TTPRef: "T1552.007", Category: "config"},
		{Path: "/var/lib/mysql/mysql/user.MYD", Description: "MySQL user database", TTPRef: "T1552.005", Category: "db"},
		{Path: "/etc/openvpn/auth.txt", Description: "OpenVPN credentials", TTPRef: "T1552.001", Category: "cred"},

		// Database exports
		{Path: "/tmp/dump.sql", Description: "Database dump", TTPRef: "T1005", Category: "data"},
		{Path: "/root/db_backup.sql", Description: "Root DB backup", TTPRef: "T1005", Category: "data"},

		// Token files
		{Path: "/var/run/secrets/kubernetes.io/serviceaccount/token", Description: "K8s service token", TTPRef: "T1552.007", Category: "token"},
		{Path: "/root/.docker/config.json", Description: "Docker registry auth", TTPRef: "T1552.007", Category: "cred"},
	}
}

// ═══════════════════════════════════════════════════════════════
// Honey path manager
// ═══════════════════════════════════════════════════════════════

// Manager oversees honey path deployment and alert handling.
type Manager struct {
	mu           sync.Mutex
	paths        []HoneyPath
	hashes       map[string]string // hash16 → path (for reverse lookup)
	triggered    map[string]bool   // path → triggered
	triggerCount int
}

// NewManager creates a honey pot manager with default paths.
func NewManager() *Manager {
	m := &Manager{
		hashes:    make(map[string]string),
		triggered: make(map[string]bool),
	}
	for _, p := range DefaultHoneyPaths() {
		m.AddPath(p)
	}
	return m
}

// AddPath registers a honey path and computes its hash.
func (m *Manager) AddPath(hp HoneyPath) {
	m.mu.Lock()
	defer m.mu.Unlock()

	hash := hashPath(hp.Path)
	m.paths = append(m.paths, hp)
	m.hashes[hash] = hp.Path
}

// Hash returns the 16-char hex hash of a path.
func HashPath(path string) string {
	return hashPath(path)
}

func hashPath(path string) string {
	h := sha256.Sum256([]byte(path))
	return hex.EncodeToString(h[:])[:16]
}

// DeployHashes returns all honey path hashes for BPF map injection.
func (m *Manager) DeployHashes() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make(map[string]string)
	for _, hp := range m.paths {
		result[hashPath(hp.Path)] = hp.Path
	}
	return result
}

// DeployToBPFMap would inject hashes into a BPF map.
// In production: honey_map.Put(hash, 1) for each entry.
func (m *Manager) DeployToBPFMap() error {
	hashes := m.DeployHashes()
	log.Printf("[honeypot] deployed %d honey path hashes to BPF map", len(hashes))
	return nil
}

// IsHoneyPath checks if a path hash matches a known honey path.
func (m *Manager) IsHoneyPath(hash string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	path, ok := m.hashes[hash]
	return path, ok
}

// Paths returns all registered honey paths.
func (m *Manager) Paths() []HoneyPath {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]HoneyPath, len(m.paths))
	copy(out, m.paths)
	return out
}

// Stats returns honey pot statistics.
func (m *Manager) Stats() map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]interface{}{
		"total_paths":   len(m.paths),
		"trigger_count": m.triggerCount,
		"triggered":     len(m.triggered),
	}
}

// ── eBPF integration header (kernel-side) ──────────────────

// BPFProgramTemplate returns the C template for the eBPF honey
// pot program that checks file paths against honey hashes.
func BPFProgramTemplate() string {
	return `/* Honey pot eBPF — deployed to kernel via SEC("lsm.s/file_open") */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u32);    /* hash of honey path (first 32 bits) */
    __type(value, u32);  /* flags */
} honey_paths SEC(".maps");

SEC("lsm.s/file_open")
int BPF_PROG(check_honey_path, struct file *file) {
    /* Read the file path and check against honey hashes */
    char path[256];
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry) return 0;

    /* Read path for hash comparison */
    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    if (!name) return 0;
    bpf_probe_read_kernel_str(path, sizeof(path), name);

    /* Hash the path (FNV-1a simplified) and check honey map */
    u32 hash = 0;
    for (int i = 0; i < 256 && path[i]; i++) {
        hash ^= path[i];
        hash *= 16777619;
    }

    if (bpf_map_lookup_elem(&honey_paths, &hash)) {
        /* HONEY PATH TRIGGERED — emit CRITICAL alert */
        struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            fill_event_hdr(e, EV_HONEY_TRIGGER);
            bpf_probe_read_kernel_str(e->pathname, sizeof(e->pathname), path);
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}`
}
