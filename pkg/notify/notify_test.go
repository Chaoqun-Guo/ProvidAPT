// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"fmt"
	"testing"
	"time"
)

type mockNotifier struct {
	name string
	sent []Alert
	fail int
}

func (m *mockNotifier) Name() string { return m.name }
func (m *mockNotifier) Send(a Alert) error {
	if m.fail > 0 {
		m.fail--
		return fmt.Errorf("boom")
	}
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

	m.Send(Alert{Severity: SeverityHigh, Pattern: "pattern-a", Headline: "a"})
	m.Send(Alert{Severity: SeverityHigh, Pattern: "pattern-b", Headline: "b"})

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

func TestRetryDeliveryEventuallySucceeds(t *testing.T) {
	m := NewManager()
	m.SetRetryPolicy(3, 0)
	n := &mockNotifier{name: "retry", fail: 1}
	m.AddNotifier(n)

	m.Send(Alert{ID: "a-1", Severity: SeverityHigh, Pattern: "pattern-a", Headline: "retry"})

	if len(n.sent) != 1 {
		t.Fatalf("expected 1 sent alert, got %d", len(n.sent))
	}
	snapshot := m.DeliverySnapshot()
	if snapshot.Summary.Retrying != 1 {
		t.Fatalf("retrying = %d", snapshot.Summary.Retrying)
	}
	if snapshot.Summary.Delivered != 1 {
		t.Fatalf("delivered = %d", snapshot.Summary.Delivered)
	}
}

func TestDeadLetterAfterExhaustedRetries(t *testing.T) {
	m := NewManager()
	m.SetRetryPolicy(2, 0)
	n := &mockNotifier{name: "dead", fail: 2}
	m.AddNotifier(n)

	m.Send(Alert{ID: "a-2", Severity: SeverityCritical, Pattern: "pattern-b", Headline: "dead"})

	snapshot := m.DeliverySnapshot()
	if snapshot.Summary.DeadLetter != 1 {
		t.Fatalf("dead letters = %d", snapshot.Summary.DeadLetter)
	}
	if len(snapshot.DeadLetters) != 1 {
		t.Fatalf("dead letter list = %d", len(snapshot.DeadLetters))
	}
	if snapshot.DeadLetters[0].Attempt != 2 {
		t.Fatalf("attempt = %d", snapshot.DeadLetters[0].Attempt)
	}
}

func TestReplayDeadLetter(t *testing.T) {
	m := NewManager()
	m.SetRetryPolicy(1, 0)
	n := &mockNotifier{name: "dead", fail: 1}
	m.AddNotifier(n)

	m.Send(Alert{ID: "a-3", Severity: SeverityHigh, Pattern: "pattern-c", Headline: "replay"})
	snapshot := m.DeliverySnapshot()
	if len(snapshot.DeadLetters) != 1 {
		t.Fatalf("dead letter list = %d", len(snapshot.DeadLetters))
	}

	result, err := m.ReplayDeadLetter(snapshot.DeadLetters[0].ID)
	if err != nil {
		t.Fatalf("replay dead letter: %v", err)
	}
	if result.Record.Status != DeliveryStatusDelivered {
		t.Fatalf("replay status = %s", result.Record.Status)
	}
	snapshot = m.DeliverySnapshot()
	if len(snapshot.DeadLetters) != 0 {
		t.Fatalf("dead letters should be cleared, got %d", len(snapshot.DeadLetters))
	}
	if len(n.sent) != 1 {
		t.Fatalf("expected notifier send after replay, got %d", len(n.sent))
	}
}

func TestReplayAllDeadLetters(t *testing.T) {
	m := NewManager()
	m.SetRetryPolicy(1, 0)
	n := &mockNotifier{name: "dead", fail: 3}
	m.AddNotifier(n)

	m.Send(Alert{ID: "a-4", Severity: SeverityHigh, Pattern: "pattern-d", Headline: "replay one"})
	m.Send(Alert{ID: "a-5", Severity: SeverityCritical, Pattern: "P5", Headline: "replay two"})

	batch := m.ReplayAllDeadLetters()
	if batch.Processed != 2 {
		t.Fatalf("processed = %d", batch.Processed)
	}
	if batch.Succeeded != 1 {
		t.Fatalf("succeeded = %d", batch.Succeeded)
	}
	if batch.Failed != 1 {
		t.Fatalf("failed = %d", batch.Failed)
	}
}

func TestSetTicketReference(t *testing.T) {
	m := NewManager()
	m.SetRetryPolicy(1, 0)
	n := &mockNotifier{name: "dead", fail: 1}
	m.AddNotifier(n)

	m.Send(Alert{ID: "a-6", Severity: SeverityHigh, Pattern: "P6", Headline: "ticket"})
	snapshot := m.DeliverySnapshot()
	if len(snapshot.DeadLetters) != 1 {
		t.Fatalf("dead letters = %d", len(snapshot.DeadLetters))
	}

	record, err := m.SetTicketReference(snapshot.DeadLetters[0].ID, TicketReference{
		Provider: "jira",
		Key:      "SEC-1",
		URL:      "https://jira.local/browse/SEC-1",
		LinkedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("set ticket reference: %v", err)
	}
	if record.Ticket == nil || record.Ticket.Key != "SEC-1" {
		t.Fatalf("ticket = %#v", record.Ticket)
	}
}
