package blastradius

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Credential theft correlation
// ═══════════════════════════════════════════════════════════════

// LSASSEvent represents a credential dumping event (LSASS read).
type LSASSEvent struct {
	ID        string    `json:"id"`
	HostID    string    `json:"host_id"`
	PID       uint32    `json:"pid"`
	Comm      string    `json:"comm"`
	Timestamp time.Time `json:"timestamp"`
}

// RemoteLoginEvent represents a subsequent login from a stolen identity.
type RemoteLoginEvent struct {
	ID        string    `json:"id"`
	SourceHost string   `json:"source_host"`
	TargetHost string   `json:"target_host"`
	Identity  string    `json:"identity"` // stolen user identity
	PID       uint32    `json:"pid"`
	Comm      string    `json:"comm"`
	Timestamp time.Time `json:"timestamp"`
}

// CredentialIncident links LSASS theft to lateral movement.
type CredentialIncident struct {
	ID           string              `json:"id"`
	LSASSEvent   *LSASSEvent         `json:"lsass_event"`
	RemoteLogins []*RemoteLoginEvent `json:"remote_logins"`
	Identity     string              `json:"identity"`
	FirstSeen    time.Time           `json:"first_seen"`
	LastSeen     time.Time           `json:"last_seen"`
	Alerted      bool                `json:"alerted"`
}

// CredentialCorrelator links credential theft to remote logins.
type CredentialCorrelator struct {
	mu        sync.Mutex
	lsass     []*LSASSEvent
	logins    []*RemoteLoginEvent
	incidents []*CredentialIncident
	window    time.Duration // correlation window (default 1h)
}

// NewCredentialCorrelator creates a credential theft correlator.
func NewCredentialCorrelator() *CredentialCorrelator {
	return &CredentialCorrelator{
		window: 1 * time.Hour,
	}
}

// RecordLSASS records a credential dumping event on a host.
func (cc *CredentialCorrelator) RecordLSASS(hostID string, pid uint32, comm string) *CredentialIncident {
	evt := &LSASSEvent{
		ID:        fmt.Sprintf("LSASS-%d", time.Now().UnixNano()),
		HostID:    hostID,
		PID:       pid,
		Comm:      comm,
		Timestamp: time.Now(),
	}

	cc.mu.Lock()
	cc.lsass = append(cc.lsass, evt)

	// Create a new incident
	inc := &CredentialIncident{
		ID:         fmt.Sprintf("CRED-%d", time.Now().UnixNano()),
		LSASSEvent: evt,
		Identity:   "unknown",
		FirstSeen:  evt.Timestamp,
		LastSeen:   evt.Timestamp,
	}
	cc.incidents = append(cc.incidents, inc)
	cc.mu.Unlock()

	log.Printf("[detect] LSASS dump on %s (pid=%d %s)", hostID, pid, comm)
	return inc
}

// RecordRemoteLogin records a remote login event.
// If it follows an LSASS dump within the time window, correlates them.
func (cc *CredentialCorrelator) RecordRemoteLogin(sourceHost, targetHost, identity string, pid uint32, comm string) *CredentialIncident {
	evt := &RemoteLoginEvent{
		ID:         fmt.Sprintf("LOGIN-%d", time.Now().UnixNano()),
		SourceHost: sourceHost,
		TargetHost: targetHost,
		Identity:   identity,
		PID:        pid,
		Comm:       comm,
		Timestamp:  time.Now(),
	}

	cc.mu.Lock()
	cc.logins = append(cc.logins, evt)

	// Try to correlate with existing incidents
	var matchedInc *CredentialIncident
	for _, inc := range cc.incidents {
		if inc.Alerted {
			continue
		}
		// Check time window
		if evt.Timestamp.Sub(inc.FirstSeen) > cc.window {
			continue
		}
		// Check if the source host matches the LSASS host
		if inc.LSASSEvent.HostID == sourceHost {
			inc.RemoteLogins = append(inc.RemoteLogins, evt)
			inc.Identity = identity
			inc.LastSeen = evt.Timestamp
			inc.Alerted = true
			matchedInc = inc
			log.Printf("[detect] CREDENTIAL THEFT CORRELATED: %s → %s (identity=%s)",
				sourceHost, targetHost, identity)
			break
		}
	}
	cc.mu.Unlock()

	return matchedInc
}

// Incidents returns all correlated credential incidents.
func (cc *CredentialCorrelator) Incidents() []*CredentialIncident {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	out := make([]*CredentialIncident, len(cc.incidents))
	copy(out, cc.incidents)
	return out
}

// Summary returns a human-readable incident summary.
func (ci *CredentialIncident) Summary() string {
	return fmt.Sprintf("[CRED] %s → %s on %s (identity=%s, %d remote logins)",
		ci.LSASSEvent.HostID, ci.LSASSEvent.Comm,
		ci.LSASSEvent.Timestamp.Format(time.RFC3339),
		ci.Identity, len(ci.RemoteLogins))
}
