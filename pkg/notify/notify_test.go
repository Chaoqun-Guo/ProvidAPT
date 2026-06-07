// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"testing"
	"time"
)

type mockNotifier struct {
	name string
	sent []Alert
}

func (m *mockNotifier) Name() string     { return m.name }
func (m *mockNotifier) Send(a Alert) error {
	m.sent = append(m.sent, a)
	return nil
}

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.NotifierCount() != 0 {
		t.Errorf("expected 0 notifiers, got %d", m.NotifierCount())
	}
}

func TestAddNotifier(t *testing.T) {
	m := NewManager()
	m.AddNotifier(&mockNotifier{name: "test"})
	if m.NotifierCount() != 1 {
		t.Errorf("expected 1 notifier, got %d", m.NotifierCount())
	}
}

func TestSend(t *testing.T) {
	m := NewManager()
	n := &mockNotifier{name: "test"}
	m.AddNotifier(n)

	alert := Alert{
		Severity: SeverityHigh,
		Pattern:  "TEST_PATTERN",
		Headline: "Test alert",
	}
	m.Send(alert)

	if len(n.sent) != 1 {
		t.Fatalf("expected 1 sent alert, got %d", len(n.sent))
	}
	if n.sent[0].Pattern != "TEST_PATTERN" {
		t.Errorf("pattern = %s", n.sent[0].Pattern)
	}
}

func TestSendMultipleNotifiers(t *testing.T) {
	m := NewManager()
	n1 := &mockNotifier{name: "n1"}
	n2 := &mockNotifier{name: "n2"}
	m.AddNotifier(n1)
	m.AddNotifier(n2)

	m.Send(Alert{Severity: SeverityCritical, Headline: "multi"})

	if len(n1.sent) != 1 {
		t.Errorf("n1: %d", len(n1.sent))
	}
	if len(n2.sent) != 1 {
		t.Errorf("n2: %d", len(n2.sent))
	}
}

func TestThrottle(t *testing.T) {
	m := NewManager()
	m.SetMinInterval(1 * time.Hour)

	n := &mockNotifier{name: "throttle"}
	m.AddNotifier(n)

	alert := Alert{Severity: SeverityHigh, Pattern: "THROTTLE", Headline: "first"}
	m.Send(alert)
	m.Send(alert) // second send with same pattern+severity

	if len(n.sent) != 1 {
		t.Errorf("expected 1 (throttled), got %d", len(n.sent))
	}
}

func TestNoThrottleDifferentPattern(t *testing.T) {
	m := NewManager()
	m.SetMinInterval(1 * time.Hour)

	n := &mockNotifier{name: "n"}
	m.AddNotifier(n)

	m.Send(Alert{Severity: SeverityHigh, Pattern: "P1", Headline: "a"})
	m.Send(Alert{Severity: SeverityHigh, Pattern: "P2", Headline: "b"})

	if len(n.sent) != 2 {
		t.Errorf("expected 2, got %d", len(n.sent))
	}
}

func TestClose(t *testing.T) {
	m := NewManager()
	m.AddNotifier(&mockNotifier{name: "n1"})
	m.AddNotifier(&mockNotifier{name: "n2"})
	m.Close()

	if m.NotifierCount() != 0 {
		t.Error("notifiers should be cleared after close")
	}
}

func TestSetMinInterval(t *testing.T) {
	m := NewManager()
	m.SetMinInterval(5 * time.Second)
	if m.minInterval != 5*time.Second {
		t.Errorf("interval = %v", m.minInterval)
	}
}
