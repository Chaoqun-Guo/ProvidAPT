// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"fmt"
	"time"
)

type DeliveryStatus string

const (
	DeliveryStatusDelivered  DeliveryStatus = "delivered"
	DeliveryStatusRetrying   DeliveryStatus = "retrying"
	DeliveryStatusDeadLetter DeliveryStatus = "dead_letter"
)

type DeliveryRecord struct {
	ID            string           `json:"id"`
	Notifier      string           `json:"notifier"`
	AlertID       string           `json:"alert_id"`
	Pattern       string           `json:"pattern"`
	Severity      Severity         `json:"severity"`
	Status        DeliveryStatus   `json:"status"`
	Attempt       int              `json:"attempt"`
	MaxAttempts   int              `json:"max_attempts"`
	LastAttemptAt time.Time        `json:"last_attempt_at"`
	Error         string           `json:"error,omitempty"`
	Ticket        *TicketReference `json:"ticket,omitempty"`
}

type TicketReference struct {
	Provider    string    `json:"provider"`
	Key         string    `json:"key,omitempty"`
	URL         string    `json:"url,omitempty"`
	LinkedAt    time.Time `json:"linked_at"`
	Idempotency string    `json:"idempotency,omitempty"`
}

type DeliverySummary struct {
	Delivered  int `json:"delivered"`
	Retrying   int `json:"retrying"`
	DeadLetter int `json:"dead_letter"`
}

type DeliverySnapshot struct {
	UpdatedAt   string           `json:"updated_at"`
	Summary     DeliverySummary  `json:"summary"`
	Recent      []DeliveryRecord `json:"recent"`
	DeadLetters []DeliveryRecord `json:"dead_letters"`
}

type ReplayResult struct {
	UpdatedAt string         `json:"updated_at"`
	Record    DeliveryRecord `json:"record"`
}

type BatchReplayResult struct {
	UpdatedAt string           `json:"updated_at"`
	Processed int              `json:"processed"`
	Succeeded int              `json:"succeeded"`
	Failed    int              `json:"failed"`
	Records   []DeliveryRecord `json:"records"`
}

func (m *Manager) SetRetryPolicy(maxAttempts int, backoff time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	m.maxAttempts = maxAttempts
	if backoff < 0 {
		backoff = 0
	}
	m.retryBackoff = backoff
}

func (m *Manager) DeliverySnapshot() DeliverySnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	recent := make([]DeliveryRecord, len(m.deliveryHistory))
	copy(recent, m.deliveryHistory)
	dead := make([]DeliveryRecord, len(m.deadLetters))
	copy(dead, m.deadLetters)

	summary := DeliverySummary{}
	for _, item := range recent {
		switch item.Status {
		case DeliveryStatusDelivered:
			summary.Delivered++
		case DeliveryStatusRetrying:
			summary.Retrying++
		case DeliveryStatusDeadLetter:
			summary.DeadLetter++
		}
	}

	return DeliverySnapshot{
		UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
		Summary:     summary,
		Recent:      recent,
		DeadLetters: dead,
	}
}

func buildDeliveryID(alert Alert, notifierName string, attempt int, ts time.Time) string {
	base := alert.ID
	if base == "" {
		base = alert.Pattern
	}
	if base == "" {
		base = "alert"
	}
	return fmt.Sprintf("%s:%s:%d:%d", notifierName, base, attempt, ts.UnixNano())
}

func (m *Manager) DeadLetterRecord(id string) (DeliveryRecord, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	item, ok := m.deadLetterItems[id]
	if !ok {
		return DeliveryRecord{}, false
	}
	return item.Record, true
}

func (m *Manager) DeadLetterRecords() []DeliveryRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	records := make([]DeliveryRecord, len(m.deadLetters))
	copy(records, m.deadLetters)
	return records
}

func (m *Manager) ReplayDeadLetter(id string) (ReplayResult, error) {
	m.mu.RLock()
	item, ok := m.deadLetterItems[id]
	notifiers := make([]Notifier, len(m.notifiers))
	copy(notifiers, m.notifiers)
	maxAttempts := m.maxAttempts
	retryBackoff := m.retryBackoff
	m.mu.RUnlock()

	if !ok {
		return ReplayResult{}, fmt.Errorf("dead letter %q not found", id)
	}

	var notifier Notifier
	for _, candidate := range notifiers {
		if candidate.Name() == item.Notifier {
			notifier = candidate
			break
		}
	}
	if notifier == nil {
		return ReplayResult{}, fmt.Errorf("notifier %q not available", item.Notifier)
	}

	start := time.Now()
	var last DeliveryRecord
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := notifier.Send(item.Alert)
		status := DeliveryStatusDelivered
		errText := ""
		if err != nil {
			errText = err.Error()
			if attempt < maxAttempts {
				status = DeliveryStatusRetrying
			} else {
				status = DeliveryStatusDeadLetter
			}
		}
		last = DeliveryRecord{
			ID:            buildDeliveryID(item.Alert, notifier.Name(), attempt, time.Now().UTC()),
			Notifier:      notifier.Name(),
			AlertID:       item.Alert.ID,
			Pattern:       item.Alert.Pattern,
			Severity:      item.Alert.Severity,
			Status:        status,
			Attempt:       attempt,
			MaxAttempts:   maxAttempts,
			LastAttemptAt: time.Now().UTC(),
			Error:         errText,
		}
		m.recordDelivery(last, item.Alert)
		if err == nil {
			m.clearDeadLetter(id)
			return ReplayResult{
				UpdatedAt: time.Now().UTC().Format(time.RFC3339),
				Record:    last,
			}, nil
		}
		if attempt < maxAttempts && retryBackoff > 0 {
			time.Sleep(retryBackoff)
		}
	}

	return ReplayResult{
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Record:    last,
	}, fmt.Errorf("replay failed after %d attempt(s) in %v", maxAttempts, time.Since(start))
}

func (m *Manager) ReplayAllDeadLetters() BatchReplayResult {
	records := m.DeadLetterRecords()
	result := BatchReplayResult{
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Processed: len(records),
		Records:   make([]DeliveryRecord, 0, len(records)),
	}
	for _, record := range records {
		replayed, err := m.ReplayDeadLetter(record.ID)
		result.Records = append(result.Records, replayed.Record)
		if err != nil {
			result.Failed++
			continue
		}
		result.Succeeded++
	}
	result.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return result
}

func (m *Manager) SetTicketReference(id string, ticket TicketReference) (DeliveryRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	item, ok := m.deadLetterItems[id]
	if !ok {
		return DeliveryRecord{}, fmt.Errorf("dead letter %q not found", id)
	}
	item.Record.Ticket = &ticket
	m.deadLetterItems[id] = item

	for index := range m.deadLetters {
		if m.deadLetters[index].ID == id {
			m.deadLetters[index].Ticket = &ticket
			break
		}
	}
	for index := range m.deliveryHistory {
		if m.deliveryHistory[index].ID == id {
			m.deliveryHistory[index].Ticket = &ticket
			break
		}
	}
	return item.Record, nil
}

func (m *Manager) clearDeadLetter(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.deadLetterItems, id)
	filtered := m.deadLetters[:0]
	for _, item := range m.deadLetters {
		if item.ID == id {
			continue
		}
		filtered = append(filtered, item)
	}
	m.deadLetters = filtered
}
