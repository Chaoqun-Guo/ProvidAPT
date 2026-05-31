package identity

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// ── Session tracker tests ───────────────────────────────────

func TestNewSessionTracker(t *testing.T) {
	st := NewSessionTracker()
	if st == nil {
		t.Fatal("NewSessionTracker returned nil")
	}
	if st.SessionCount() != 0 {
		t.Errorf("initial sessions = %d", st.SessionCount())
	}
}

func TestRegisterLogin(t *testing.T) {
	st := NewSessionTracker()
	evt := &LoginEvent{
		Username: "alice", SessionID: "sess-001",
		SourceIP: "192.168.1.100", AuthMethod: "pubkey",
		MFAStatus: "verified", PID: os.Getpid(),
	}
	ident := st.RegisterLogin(evt)
	if ident == nil {
		t.Fatal("RegisterLogin returned nil")
	}
	if ident.UserID != "alice" {
		t.Errorf("UserID = %s", ident.UserID)
	}
	if ident.Escalated {
		t.Error("new login should not be escalated")
	}
}

func TestGetIdentity(t *testing.T) {
	st := NewSessionTracker()
	st.RegisterLogin(&LoginEvent{
		Username: "bob", SessionID: "sess-002",
		PID: os.Getpid(), Timestamp: time.Now().UnixNano(),
	})

	ident := st.GetIdentity(uint32(os.Getpid()))
	if ident == nil {
		t.Fatal("GetIdentity returned nil for self")
	}
	if ident.UserID != "bob" {
		t.Errorf("UserID = %s", ident.UserID)
	}
}

func TestPropagateToChild(t *testing.T) {
	st := NewSessionTracker()
	st.RegisterLogin(&LoginEvent{
		Username: "carol", SessionID: "sess-003",
		PID: 100,
	})
	st.PropagateToChild(100, 101)

	ident := st.GetIdentity(101)
	if ident == nil {
		t.Fatal("child PID 101 should inherit identity")
	}
	if ident.UserID != "carol" {
		t.Errorf("child UserID = %s", ident.UserID)
	}
}

func TestMarkEscalated(t *testing.T) {
	st := NewSessionTracker()
	st.RegisterLogin(&LoginEvent{
		Username: "dave", SessionID: "sess-004",
		PID: 200, Timestamp: time.Now().UnixNano(),
	})
	st.MarkEscalated(200)

	ident := st.GetIdentity(200)
	if ident == nil {
		t.Fatal("GetIdentity failed")
	}
	if !ident.Escalated {
		t.Error("should be escalated after MarkEscalated")
	}
	t.Logf("Escalated identity: %s", ident.IdentitySummary())
}

func TestProcessExit(t *testing.T) {
	st := NewSessionTracker()
	st.RegisterLogin(&LoginEvent{
		Username: "eve", SessionID: "sess-005", PID: 300,
	})
	st.ProcessExit(300)
	ident := st.GetIdentity(300)
	if ident != nil {
		t.Error("PID should be removed after exit")
	}
}

func TestMultipleSessions(t *testing.T) {
	st := NewSessionTracker()
	for i := 0; i < 5; i++ {
		st.RegisterLogin(&LoginEvent{
			Username: "user", SessionID: fmt.Sprintf("sess-%d", i),
			PID: 100 + i,
		})
	}
	if st.SessionCount() != 5 {
		t.Errorf("sessions = %d", st.SessionCount())
	}
	if st.ActivePIDCount() != 5 {
		t.Errorf("active PIDs = %d", st.ActivePIDCount())
	}
}

// ── Identity enrichment tests ───────────────────────────────

func TestEnrichNode(t *testing.T) {
	ident := &Identity{
		UserID: "alice", SessionID: "sess-010",
		AuthMethod: "mfa", MFAStatus: "verified",
		SourceIP: "10.0.0.1", Escalated: true,
		OriginalUID: 1000, CurrentUID: 0,
		LoginTime: time.Now(),
	}
	attrs := make(map[string]interface{})
	ident.EnrichNode(attrs)

	if attrs["identity"] != "alice" {
		t.Errorf("identity = %v", attrs["identity"])
	}
	if attrs["escalated"] != true {
		t.Errorf("escalated = %v", attrs["escalated"])
	}
	if attrs["identity_label"] == "" {
		t.Error("identity_label should not be empty")
	}
	t.Logf("Identity label: %v", attrs["identity_label"])
}

func TestEnrichNodeNil(t *testing.T) {
	var ident *Identity
	attrs := make(map[string]interface{})
	// Should not panic
	ident.EnrichNode(attrs)
}

func TestIdentitySummary(t *testing.T) {
	ident := &Identity{
		UserID: "bob", SessionID: "sess-011",
		AuthMethod: "password", SourceIP: "10.0.0.2",
		Escalated: false,
	}
	summary := ident.IdentitySummary()
	if !contains(summary, "bob") || !contains(summary, "sess-011") {
		t.Errorf("summary = %s", summary)
	}
	t.Logf("Summary: %s", summary)
}

func TestIdentitySummaryEscalated(t *testing.T) {
	ident := &Identity{
		UserID: "admin", SessionID: "sess-012",
		Escalated: true, OriginalUID: 1000, CurrentUID: 0,
	}
	summary := ident.IdentitySummary()
	if !contains(summary, "escalated") {
		t.Errorf("escalated summary = %s", summary)
	}
	t.Logf("Escalated summary: %s", summary)
}

func TestIdentitySummaryNil(t *testing.T) {
	var ident *Identity
	summary := ident.IdentitySummary()
	if summary != "unknown" {
		t.Errorf("nil summary = %s", summary)
	}
}

func TestLoginEventTimestamp(t *testing.T) {
	now := time.Now().UnixNano()
	evt := &LoginEvent{
		Username: "test", SessionID: "sess-ts",
		PID: os.Getpid(), Timestamp: now,
	}
	evt.Timestamp = time.Now().UnixNano()
	t.Logf("Login event: user=%s pid=%d ts=%d", evt.Username, evt.PID, evt.Timestamp)
}

// ── Integration test ────────────────────────────────────────

func TestIdentityIntegration(t *testing.T) {
	st := NewSessionTracker()

	// Simulate: alice logs in via SSH → PID 1000
	st.RegisterLogin(&LoginEvent{
		Username: "alice", SessionID: "SSH-abcdef",
		SourceIP: "10.0.0.5", AuthMethod: "pubkey+mfa",
		MFAStatus: "verified", PID: 1000,
	})

	// Alice runs bash → fork to PID 1001
	st.PropagateToChild(1000, 1001)

	// Alice sudo to root → PID 1002
	st.PropagateToChild(1001, 1002)
	st.MarkEscalated(1002)

	// Check all PIDs have alice's identity
	for _, pid := range []uint32{1000, 1001, 1002} {
		ident := st.GetIdentity(pid)
		if ident == nil {
			t.Errorf("PID %d: no identity", pid)
			continue
		}
		if ident.UserID != "alice" {
			t.Errorf("PID %d: UserID = %s", pid, ident.UserID)
		}
		if ident.SessionID != "SSH-abcdef" {
			t.Errorf("PID %d: SessionID = %s", pid, ident.SessionID)
		}
		t.Logf("PID %d: %s", pid, ident.IdentitySummary())
	}

	// Verify escalation is tracked
	rootIdent := st.GetIdentity(1002)
	if !rootIdent.Escalated {
		t.Error("sudo process should be escalated")
	}

	t.Logf("Integration: %d sessions, %d active PIDs",
		st.SessionCount(), st.ActivePIDCount())
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && stringContains(s, substr)
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
