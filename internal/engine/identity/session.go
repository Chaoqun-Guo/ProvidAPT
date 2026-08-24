// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package identity implements user identity association for ProvidAPT.
// It tracks login sessions, propagates identity across process trees,
// and enriches the provenance graph with who-did-what attribution.
//
// Architecture:
//
//	PAM Module (C)           → Login Event (username, IP, session_id)
//	     │
//	     ▼
//	SessionTracker (Go)      → BPF Map: PID → Identity
//	     │
//	     ├── fork → identity propagates to child
//	     ├── sudo → identity preserved (with escalation flag)
//	     └── exit → identity cleaned up
//	     │
//	     ▼
//	IdentityEnricher (Go)    → Provenance Graph gets identity attributes
//
// Result: Every process node shows "employee A via SSH session X",
// even after sudo, su, or container boundary crossing.
package identity

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Identity model
// ═══════════════════════════════════════════════════════════════

// Identity holds the user identity for a process.
type Identity struct {
	UserID      string    `json:"user_id"`     // LDAP UID / login name
	SessionID   string    `json:"session_id"`  // SSH session / login session
	SourceIP    string    `json:"source_ip"`   // login source IP (SSH)
	AuthMethod  string    `json:"auth_method"` // password, pubkey, MFA, ldap
	MFAStatus   string    `json:"mfa_status"`  // verified, skipped, failed
	LoginTime   time.Time `json:"login_time"`
	OriginalUID uint32    `json:"original_uid"` // UID at login time
	CurrentUID  uint32    `json:"current_uid"`  // UID now (may have changed)
	Escalated   bool      `json:"escalated"`    // true if sudo/su was used
}

// ═══════════════════════════════════════════════════════════════
// PAM event structure
// ═══════════════════════════════════════════════════════════════

// LoginEvent is received from the PAM module via a Unix socket / pipe.
type LoginEvent struct {
	Username   string `json:"username"`
	SessionID  string `json:"session_id"`
	SourceIP   string `json:"source_ip"`
	AuthMethod string `json:"auth_method"`
	MFAStatus  string `json:"mfa_status"`
	PID        int    `json:"pid"` // shell PID after login
	Timestamp  int64  `json:"timestamp_ns"`
}

// ═══════════════════════════════════════════════════════════════
// Session tracker
// ═══════════════════════════════════════════════════════════════

// SessionTracker maintains the mapping from PIDs to identities.
type SessionTracker struct {
	mu       sync.RWMutex
	sessions map[string]*Identity // session_id → identity
	byPID    map[uint32]string    // PID → session_id
}

// NewSessionTracker creates a session tracker.
func NewSessionTracker() *SessionTracker {
	return &SessionTracker{
		sessions: make(map[string]*Identity),
		byPID:    make(map[uint32]string),
	}
}

// RegisterLogin processes a login event from the PAM module.
func (st *SessionTracker) RegisterLogin(evt *LoginEvent) *Identity {
	uid := uint32(0)
	// Try to get the UID from the shell process
	if evt.PID > 0 {
		if procUID, err := getUID(evt.PID); err == nil {
			uid = procUID
		}
	}

	ident := &Identity{
		UserID:      evt.Username,
		SessionID:   evt.SessionID,
		SourceIP:    evt.SourceIP,
		AuthMethod:  evt.AuthMethod,
		MFAStatus:   evt.MFAStatus,
		LoginTime:   time.Unix(0, evt.Timestamp),
		OriginalUID: uid,
		CurrentUID:  uid,
		Escalated:   false,
	}

	st.mu.Lock()
	st.sessions[evt.SessionID] = ident
	if evt.PID > 0 {
		st.byPID[uint32(evt.PID)] = evt.SessionID
	}
	st.mu.Unlock()

	log.Printf("[identity] login: %s via %s (session=%s, pid=%d, mfa=%s)",
		evt.Username, evt.AuthMethod, evt.SessionID, evt.PID, evt.MFAStatus)

	return ident
}

// PropagateToChild is called when a process forks.
// The child inherits the parent's identity.
func (st *SessionTracker) PropagateToChild(parentPID, childPID uint32) {
	st.mu.Lock()
	defer st.mu.Unlock()

	sessionID, ok := st.byPID[parentPID]
	if !ok {
		return
	}
	st.byPID[childPID] = sessionID
}

// MarkEscalated marks a PID as having escalated privileges (sudo/su).
func (st *SessionTracker) MarkEscalated(pid uint32) {
	st.mu.Lock()
	defer st.mu.Unlock()

	sessionID, ok := st.byPID[pid]
	if !ok {
		return
	}
	ident, ok := st.sessions[sessionID]
	if !ok {
		return
	}
	ident.Escalated = true

	// Update current UID
	if newUID, err := getUID(int(pid)); err == nil {
		ident.CurrentUID = newUID
	}

	log.Printf("[identity] escalation: PID %d (user=%s, original_uid=%d, current_uid=%d)",
		pid, ident.UserID, ident.OriginalUID, ident.CurrentUID)
}

// GetIdentity returns the identity for a PID.
func (st *SessionTracker) GetIdentity(pid uint32) *Identity {
	st.mu.RLock()
	defer st.mu.RUnlock()

	sessionID, ok := st.byPID[pid]
	if !ok {
		return nil
	}
	ident, ok := st.sessions[sessionID]
	if !ok {
		return nil
	}
	return ident
}

// ProcessExit removes a PID from tracking.
func (st *SessionTracker) ProcessExit(pid uint32) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.byPID, pid)
}

// SessionCount returns the number of tracked sessions.
func (st *SessionTracker) SessionCount() int {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return len(st.sessions)
}

// ActivePIDCount returns the number of tracked PIDs.
func (st *SessionTracker) ActivePIDCount() int {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return len(st.byPID)
}

// ═══════════════════════════════════════════════════════════════
// Identity enrichment for provenance graph
// ═══════════════════════════════════════════════════════════════

// EnrichNode adds identity attributes to a provenance graph node.
func (ident *Identity) EnrichNode(attrs map[string]interface{}) {
	if ident == nil {
		return
	}
	attrs["identity"] = ident.UserID
	attrs["session_id"] = ident.SessionID
	attrs["auth_method"] = ident.AuthMethod
	attrs["mfa_status"] = ident.MFAStatus
	attrs["source_ip"] = ident.SourceIP
	attrs["login_time"] = ident.LoginTime.Format(time.RFC3339)
	attrs["escalated"] = ident.Escalated
	attrs["original_uid"] = ident.OriginalUID
	attrs["current_uid"] = ident.CurrentUID

	if ident.Escalated {
		attrs["identity_label"] = fmt.Sprintf("%s → root (escalated)", ident.UserID)
	} else {
		attrs["identity_label"] = fmt.Sprintf("%s (uid=%d)", ident.UserID, ident.OriginalUID)
	}
}

// IdentitySummary returns a human-readable identity summary.
func (ident *Identity) IdentitySummary() string {
	if ident == nil {
		return "unknown"
	}
	base := fmt.Sprintf("%s session=%s auth=%s", ident.UserID, ident.SessionID, ident.AuthMethod)
	if ident.Escalated {
		base += fmt.Sprintf(" escalated uid=%d→%d", ident.OriginalUID, ident.CurrentUID)
	}
	if ident.SourceIP != "" {
		base += fmt.Sprintf(" from=%s", ident.SourceIP)
	}
	return base
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

// getUID reads the UID from /proc/<pid>/status.
func getUID(pid int) (uint32, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/loginuid", pid))
	if err == nil {
		var uid uint32
		if _, err := fmt.Sscanf(string(data), "%d", &uid); err == nil {
			return uid, nil
		}
	}
	return 0, fmt.Errorf("cannot read UID for PID %d", pid)
}
