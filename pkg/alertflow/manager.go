// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package alertflow manages alert deduplication, assignment, silence windows,
// and status transitions for control-plane workflows.
package alertflow

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/notify"
)

// Status is the current workflow state of an alert.
type Status string

const (
	// StatusOpen means the alert is unassigned and active.
	StatusOpen Status = "open"
	// StatusAssigned means the alert is assigned to an operator.
	StatusAssigned Status = "assigned"
	// StatusSuppressed means the alert is temporarily silenced.
	StatusSuppressed Status = "suppressed"
	// StatusClosed means the alert has been explicitly closed.
	StatusClosed Status = "closed"
)

// Alert is the workflow-facing representation of a deduplicated alert.
type Alert struct {
	ID             string            `json:"id"`
	DedupKey       string            `json:"dedup_key,omitempty"`
	Severity       string            `json:"severity"`
	Pattern        string            `json:"pattern"`
	Headline       string            `json:"headline"`
	Reason         string            `json:"reason,omitempty"`
	Source         string            `json:"source,omitempty"`
	Status         Status            `json:"status"`
	Assignee       string            `json:"assignee,omitempty"`
	Count          int               `json:"count"`
	FirstSeen      time.Time         `json:"first_seen"`
	LastSeen       time.Time         `json:"last_seen"`
	LastNotifiedAt time.Time         `json:"last_notified_at,omitempty"`
	SilenceUntil   time.Time         `json:"silence_until,omitempty"`
	Note           string            `json:"note,omitempty"`
	Details        map[string]string `json:"details,omitempty"`
}

// Summary contains aggregate counts for alert workflow states.
type Summary struct {
	Total      int `json:"total"`
	Open       int `json:"open"`
	Assigned   int `json:"assigned"`
	Suppressed int `json:"suppressed"`
	Closed     int `json:"closed"`
}

// Snapshot is a point-in-time view of alert workflow state.
type Snapshot struct {
	UpdatedAt string  `json:"updated_at"`
	Summary   Summary `json:"summary"`
	Alerts    []Alert `json:"alerts"`
}

// UpdateRequest describes a workflow action applied to a single alert.
type UpdateRequest struct {
	Action         string `json:"action"`
	AlertID        string `json:"alert_id,omitempty"`
	Assignee       string `json:"assignee,omitempty"`
	Duration       string `json:"duration,omitempty"`
	Note           string `json:"note,omitempty"`
	Classification string `json:"classification,omitempty"`
}

// Manager stores deduplicated alerts and applies workflow transitions.
type Manager struct {
	mu          sync.Mutex
	alerts      map[string]*Alert
	byDedupKey  map[string]string
	order       []string
	dedupWindow time.Duration
	maxAlerts   int
}

// NewManager creates a new in-memory alert workflow manager.
func NewManager() *Manager {
	return &Manager{
		alerts:      make(map[string]*Alert),
		byDedupKey:  make(map[string]string),
		dedupWindow: 10 * time.Minute,
		maxAlerts:   500,
	}
}

// SetDedupWindow changes the minimum notification interval for duplicates.
func (m *Manager) SetDedupWindow(window time.Duration) {
	if window <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dedupWindow = window
}

// Ingest inserts or updates an alert and reports whether it should notify.
func (m *Manager) Ingest(input notify.Alert) (Alert, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := input.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}
	key := dedupKey(input)
	if existingID, ok := m.byDedupKey[key]; ok {
		if existing, ok := m.alerts[existingID]; ok {
			existing.Count++
			existing.LastSeen = now
			if existing.Status == StatusClosed {
				existing.Status = statusFor(existing.Assignee, existing.SilenceUntil, now)
			}
			if input.Reason != "" {
				existing.Reason = input.Reason
			}
			if existing.Details == nil {
				existing.Details = map[string]string{}
			}
			existing.Details["dedup_count"] = fmt.Sprintf("%d", existing.Count)
			deliver := m.shouldNotify(existing, now)
			if deliver {
				existing.LastNotifiedAt = now
			}
			return cloneAlert(*existing), deliver
		}
	}

	record := &Alert{
		ID:        stableID(input, now),
		DedupKey:  key,
		Severity:  string(input.Severity),
		Pattern:   input.Pattern,
		Headline:  input.Headline,
		Reason:    input.Reason,
		Source:    input.Source,
		Status:    StatusOpen,
		Count:     1,
		FirstSeen: now,
		LastSeen:  now,
		Details:   cloneMap(input.Details),
	}
	if record.Details == nil {
		record.Details = map[string]string{}
	}
	record.Details["dedup_count"] = "1"
	m.alerts[record.ID] = record
	m.byDedupKey[key] = record.ID
	m.order = append(m.order, record.ID)
	m.trimLocked()
	record.LastNotifiedAt = now
	return cloneAlert(*record), true
}

// Snapshot returns the current filtered workflow view.
func (m *Manager) Snapshot(status, assignee string) Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	var alerts []Alert
	summary := Summary{}
	for i := len(m.order) - 1; i >= 0; i-- {
		id := m.order[i]
		item, ok := m.alerts[id]
		if !ok {
			continue
		}
		m.refreshStatusLocked(item, now)
		summary.Total++
		switch item.Status {
		case StatusOpen:
			summary.Open++
		case StatusAssigned:
			summary.Assigned++
		case StatusSuppressed:
			summary.Suppressed++
		case StatusClosed:
			summary.Closed++
		}
		if status != "" && string(item.Status) != strings.ToLower(strings.TrimSpace(status)) {
			continue
		}
		if assignee != "" && !strings.EqualFold(item.Assignee, assignee) {
			continue
		}
		alerts = append(alerts, cloneAlert(*item))
	}
	sort.SliceStable(alerts, func(i, j int) bool {
		return alerts[i].LastSeen.After(alerts[j].LastSeen)
	})
	return Snapshot{
		UpdatedAt: now.Format(time.RFC3339),
		Summary:   summary,
		Alerts:    alerts,
	}
}

// Update applies a workflow action to an existing alert.
func (m *Manager) Update(req UpdateRequest) (Alert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	item, ok := m.alerts[strings.TrimSpace(req.AlertID)]
	if !ok {
		return Alert{}, fmt.Errorf("alert %q not found", req.AlertID)
	}
	now := time.Now().UTC()
	switch strings.ToLower(strings.TrimSpace(req.Action)) {
	case "assign":
		item.Assignee = strings.TrimSpace(req.Assignee)
		item.Note = strings.TrimSpace(req.Note)
		item.Status = statusFor(item.Assignee, item.SilenceUntil, now)
	case "silence":
		duration := 30 * time.Minute
		if trimmed := strings.TrimSpace(req.Duration); trimmed != "" {
			parsed, err := time.ParseDuration(trimmed)
			if err != nil {
				return Alert{}, fmt.Errorf("invalid duration: %w", err)
			}
			duration = parsed
		}
		item.SilenceUntil = now.Add(duration)
		item.Note = strings.TrimSpace(req.Note)
		item.Status = StatusSuppressed
	case "unsilence":
		item.SilenceUntil = time.Time{}
		item.Note = strings.TrimSpace(req.Note)
		item.Status = statusFor(item.Assignee, item.SilenceUntil, now)
	case "close":
		item.Note = strings.TrimSpace(req.Note)
		item.Status = StatusClosed
	case "reopen":
		item.Note = strings.TrimSpace(req.Note)
		item.Status = statusFor(item.Assignee, item.SilenceUntil, now)
	case "annotate":
		classification := normalizeClassification(req.Classification)
		if classification == "" {
			return Alert{}, fmt.Errorf("classification must be true_positive, false_positive, benign, duplicate, or needs_review")
		}
		if item.Details == nil {
			item.Details = map[string]string{}
		}
		item.Details["classification"] = classification
		item.Details["classification_updated_at"] = now.Format(time.RFC3339)
		item.Note = strings.TrimSpace(req.Note)
	default:
		return Alert{}, fmt.Errorf("unsupported action %q", req.Action)
	}
	return cloneAlert(*item), nil
}

func normalizeClassification(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	normalized = strings.ReplaceAll(normalized, " ", "_")
	switch normalized {
	case "tp", "true_positive":
		return "true_positive"
	case "fp", "false_positive":
		return "false_positive"
	case "benign":
		return "benign"
	case "duplicate":
		return "duplicate"
	case "needs_review", "review":
		return "needs_review"
	default:
		return ""
	}
}

func (m *Manager) shouldNotify(item *Alert, now time.Time) bool {
	m.refreshStatusLocked(item, now)
	if item.Status == StatusSuppressed {
		return false
	}
	if item.LastNotifiedAt.IsZero() {
		return true
	}
	return now.Sub(item.LastNotifiedAt) >= m.dedupWindow
}

func (m *Manager) refreshStatusLocked(item *Alert, now time.Time) {
	if item.Status == StatusClosed {
		return
	}
	item.Status = statusFor(item.Assignee, item.SilenceUntil, now)
}

func statusFor(assignee string, silenceUntil, now time.Time) Status {
	if !silenceUntil.IsZero() && silenceUntil.After(now) {
		return StatusSuppressed
	}
	if strings.TrimSpace(assignee) != "" {
		return StatusAssigned
	}
	return StatusOpen
}

func dedupKey(input notify.Alert) string {
	parts := []string{
		strings.TrimSpace(strings.ToUpper(string(input.Severity))),
		strings.TrimSpace(strings.ToUpper(input.Pattern)),
		strings.TrimSpace(strings.ToUpper(input.Source)),
		strings.TrimSpace(strings.ToUpper(input.Headline)),
	}
	return strings.Join(parts, "|")
}

func stableID(input notify.Alert, now time.Time) string {
	if trimmed := strings.TrimSpace(input.ID); trimmed != "" {
		return trimmed
	}
	base := strings.TrimSpace(input.Pattern)
	if base == "" {
		base = "alert"
	}
	return fmt.Sprintf("%s-%d", strings.ToLower(base), now.UnixNano())
}

func (m *Manager) trimLocked() {
	for len(m.order) > m.maxAlerts {
		oldest := m.order[0]
		m.order = m.order[1:]
		if item, ok := m.alerts[oldest]; ok {
			delete(m.byDedupKey, item.DedupKey)
		}
		delete(m.alerts, oldest)
	}
}

func cloneAlert(item Alert) Alert {
	item.Details = cloneMap(item.Details)
	return item
}

func cloneMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}
