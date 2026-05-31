package provenance

import (
	"fmt"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
)

// ═══════════════════════════════════════════════════════════════
// Security context state machine
//
// Each process has an associated SecurityContext that evolves over
// time as the process performs execve (potentially with setuid),
// capset, or other privilege-changing operations.
//
// When a change is detected, a credential entity node is created
// and linked to the process via a hadSecurityContext edge.
//
// Credential chain example:
//   p:1234 ──hadSecurityContext──▶ c:1234:1000 (uid=1000)
//   p:1234 ──hadSecurityContext──▶ c:1234:0    (uid=0 after setuid)
// ═══════════════════════════════════════════════════════════════

// SecurityContext captures the credential state of a process at a
// point in time.
type SecurityContext struct {
	PID          uint32
	UID          uint32
	EUID         uint32
	HasSetuid    bool
	PrevUID      uint32
}

// CredTracker maintains the current security context for each
// tracked process and emits credential-change nodes when the
// context transitions.
type CredTracker struct {
	mu     sync.Mutex
	states map[uint32]*SecurityContext // pid → current context
}

// NewCredTracker creates a credential tracker.
func NewCredTracker() *CredTracker {
	return &CredTracker{
		states: make(map[uint32]*SecurityContext),
	}
}

// OnExec is called when a process performs execve.  It compares the
// new security context against the previous one and detects privilege
// changes.  Returns the credential node ID and previous UID if a
// setuid transition occurred, empty credID otherwise.
//
// NOTE: does NOT touch the graph — the caller (addExec) holds the
// graph lock and must create any credential nodes/edges from the
// returned info.
func (ct *CredTracker) OnExec(evt *collector.Event, ts time.Time) (credID string, prevUID uint32) {
	pid := evt.PID
	isSetuid := evt.Flags&syscall.EventFlagExecSetuid != 0

	ct.mu.Lock()
	prev := ct.states[pid]
	ct.states[pid] = &SecurityContext{
		PID:       pid,
		UID:       evt.UID,
		EUID:      evt.UID,
		HasSetuid: isSetuid,
	}
	ct.mu.Unlock()

	if !isSetuid {
		return "", 0
	}

	if prev != nil {
		prevUID = prev.UID
	}

	credID = fmt.Sprintf("c:%d:%d", pid, ts.UnixNano())
	return credID, prevUID
}

// GetContext returns the current security context for a PID.
func (ct *CredTracker) GetContext(pid uint32) *SecurityContext {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	return ct.states[pid]
}

