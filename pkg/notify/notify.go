// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package notify provides multi-channel alert notification for ProvidAPT.
// It supports Slack webhooks, SMTP email, and generic HTTP webhooks.
//
// Usage:
//
//	mgr := notify.NewManager()
//	mgr.AddNotifier(notify.NewSlackNotifier("https://hooks.slack.com/..."))
//	mgr.AddNotifier(notify.NewEmailNotifier("smtp://user:pass@smtp.example.com:587", "alerts@example.com"))
//	mgr.Send(alert)
package notify

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// Severity maps analyzer severity levels to notification urgency.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Alert is the notification-friendly alert payload sent to all channels.
type Alert struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Severity  Severity          `json:"severity"`
	Pattern   string            `json:"pattern"`
	Headline  string            `json:"headline"`
	Reason    string            `json:"reason"`
	Source    string            `json:"source"`
	Details   map[string]string `json:"details,omitempty"`
}

// Notifier sends alerts to a specific channel.
type Notifier interface {
	// Name returns a human-readable name for this notifier (e.g. "slack:#security").
	Name() string

	// Send delivers an alert. Implementations must be thread-safe and
	// should return quickly (non-blocking send is preferred).
	Send(alert Alert) error
}

// Manager coordinates multiple notifiers with optional throttling.
type Manager struct {
	mu        sync.RWMutex
	notifiers []Notifier

	// throttling
	minInterval time.Duration
	lastSent    map[string]time.Time

	maxAttempts     int
	retryBackoff    time.Duration
	deliveryHistory []DeliveryRecord
	deadLetters     []DeliveryRecord
	deadLetterItems map[string]deadLetterItem
	maxHistory      int
}

type deadLetterItem struct {
	Record   DeliveryRecord
	Alert    Alert
	Notifier string
}

// NewManager creates a notification manager with no notifiers attached.
func NewManager() *Manager {
	return &Manager{
		notifiers:       make([]Notifier, 0, 4),
		minInterval:     0,
		lastSent:        make(map[string]time.Time),
		maxAttempts:     3,
		retryBackoff:    250 * time.Millisecond,
		deliveryHistory: make([]DeliveryRecord, 0, 32),
		deadLetters:     make([]DeliveryRecord, 0, 16),
		deadLetterItems: make(map[string]deadLetterItem),
		maxHistory:      200,
	}
}

// SetMinInterval sets the minimum interval between repeated alerts with
// the same pattern+severity. Default is 0 (no throttling).
func (m *Manager) SetMinInterval(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.minInterval = d
}

// AddNotifier registers a notifier to receive all future Send calls.
func (m *Manager) AddNotifier(n Notifier) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notifiers = append(m.notifiers, n)
	log.Printf("[notify] added notifier: %s", n.Name())
}

// NotifierCount returns the number of registered notifiers.
func (m *Manager) NotifierCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.notifiers)
}

// Send dispatches the alert to all registered notifiers concurrently.
// A notifier that returns an error is logged but does not block others.
func (m *Manager) Send(alert Alert) {
	if m.shouldThrottle(alert) {
		return
	}

	m.mu.RLock()
	notifiers := make([]Notifier, len(m.notifiers))
	copy(notifiers, m.notifiers)
	m.mu.RUnlock()

	for _, n := range notifiers {
		func(nn Notifier) {
			start := time.Now()
			maxAttempts, retryBackoff := m.retryPolicy()
			for attempt := 1; attempt <= maxAttempts; attempt++ {
				err := nn.Send(alert)
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
				record := DeliveryRecord{
					ID:            buildDeliveryID(alert, nn.Name(), attempt, time.Now().UTC()),
					Notifier:      nn.Name(),
					AlertID:       alert.ID,
					Pattern:       alert.Pattern,
					Severity:      alert.Severity,
					Status:        status,
					Attempt:       attempt,
					MaxAttempts:   maxAttempts,
					LastAttemptAt: time.Now().UTC(),
					Error:         errText,
				}
				m.recordDelivery(record, alert)
				if err == nil {
					log.Printf("[notify] %s: sent in %v", nn.Name(), time.Since(start))
					return
				}
				log.Printf("[notify] %s: send error: %v (attempt %d/%d, took %v)", nn.Name(), err, attempt, maxAttempts, time.Since(start))
				if attempt < maxAttempts && retryBackoff > 0 {
					time.Sleep(retryBackoff)
				}
			}
		}(n)
	}
}

func (m *Manager) retryPolicy() (int, time.Duration) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.maxAttempts, m.retryBackoff
}

func (m *Manager) recordDelivery(record DeliveryRecord, alert Alert) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.deliveryHistory = append([]DeliveryRecord{record}, m.deliveryHistory...)
	if len(m.deliveryHistory) > m.maxHistory {
		m.deliveryHistory = m.deliveryHistory[:m.maxHistory]
	}
	if record.Status == DeliveryStatusDeadLetter {
		m.deadLetters = append([]DeliveryRecord{record}, m.deadLetters...)
		m.deadLetterItems[record.ID] = deadLetterItem{
			Record:   record,
			Alert:    alert,
			Notifier: record.Notifier,
		}
		if len(m.deadLetters) > m.maxHistory {
			m.deadLetters = m.deadLetters[:m.maxHistory]
		}
	}
}

// shouldThrottle checks whether this alert should be skipped because a
// similar alert was sent recently.
func (m *Manager) shouldThrottle(alert Alert) bool {
	if m.minInterval <= 0 {
		return false
	}
	key := fmt.Sprintf("%s:%s", alert.Pattern, alert.Severity)

	m.mu.Lock()
	defer m.mu.Unlock()

	last, ok := m.lastSent[key]
	now := time.Now()
	if ok && now.Sub(last) < m.minInterval {
		return true // skip — too recent
	}
	m.lastSent[key] = now
	return false
}

// Close gracefully shuts down all notifiers (flushes buffers, closes connections).
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, n := range m.notifiers {
		if closer, ok := n.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				log.Printf("[notify] %s: close error: %v", n.Name(), err)
			}
		}
	}
	m.notifiers = nil
}
