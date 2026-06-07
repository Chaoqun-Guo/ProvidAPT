// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package rulescanner

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
)

// ═══════════════════════════════════════════════════════════════
// Stream graph scanner
// ═══════════════════════════════════════════════════════════════

// ScannerConfig controls the scanner behaviour.
type ScannerConfig struct {
	// EventCh is the input channel for events from the pipeline.
	EventCh chan *pb.Event

	// AlertCh is the output channel for triggered alerts.
	AlertCh chan *Alert

	// BufferSize for the event channel (default 10000).
	BufferSize int

	// FlushInterval for periodic alert aggregation (default 5s).
	FlushInterval time.Duration
}

// Scanner processes events in real-time and matches them against rules.
type Scanner struct {
	cfg      ScannerConfig
	rules    []*Rule
	alerts   []*Alert
	mu       sync.Mutex
	stopCh   chan struct{}
	stats    ScannerStats
}

// ScannerStats tracks scanner performance.
type ScannerStats struct {
	EventsProcessed int64
	EventsMatched   int64
	AlertsTriggered int64
}

// NewScanner creates a detection scanner.
func NewScanner(rules []*Rule, cfg ScannerConfig) *Scanner {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 10000
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if cfg.EventCh == nil {
		cfg.EventCh = make(chan *pb.Event, cfg.BufferSize)
	}
	if cfg.AlertCh == nil {
		cfg.AlertCh = make(chan *Alert, 256)
	}

	return &Scanner{
		cfg:    cfg,
		rules:  rules,
		stopCh: make(chan struct{}),
	}
}

// Start begins processing events in a background goroutine.
func (s *Scanner) Start() {
	go s.loop()
	log.Printf("[detect] scanner started: %d rules", len(s.rules))
	for _, r := range s.rules {
		log.Printf("  rule: %s [%s] — %s", r.ID, r.Level, r.Title)
	}
}

// Stop signals the scanner to stop.
func (s *Scanner) Stop() {
	close(s.stopCh)
}

// Input returns the event input channel.
func (s *Scanner) Input() chan<- *pb.Event {
	return s.cfg.EventCh
}

// Alerts returns the alert output channel.
func (s *Scanner) Alerts() <-chan *Alert {
	return s.cfg.AlertCh
}

// loop is the main processing goroutine.
func (s *Scanner) loop() {
	ticker := time.NewTicker(s.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case evt := <-s.cfg.EventCh:
			s.processEvent(evt)

		case <-ticker.C:
			s.flushAlerts()

		case <-s.stopCh:
			s.flushAlerts()
			return
		}
	}
}

// processEvent checks an event against all rules.
func (s *Scanner) processEvent(evt *pb.Event) {
	atomic.AddInt64(&s.stats.EventsProcessed, 1)

	for _, rule := range s.rules {
		if rule.Match(evt) {
			atomic.AddInt64(&s.stats.EventsMatched, 1)
			s.triggerAlert(rule, evt)
			return // first match only
		}
	}
}

// triggerAlert creates an alert for a matched rule.
func (s *Scanner) triggerAlert(rule *Rule, evt *pb.Event) {
	alert := &Alert{
		RuleID:      rule.ID,
		Title:       rule.Title,
		Severity:    rule.Level,
		Description: rule.Description,
		Tags:        rule.Tags,
		Event:       evt,
		Timestamp:   time.Now(),
	}

	// Build subgraph description
	alert.SubgraphID = fmt.Sprintf("sg:%d", atomic.LoadInt64(&s.stats.AlertsTriggered))
	alert.SubgraphDesc = s.buildSubgraphDesc(evt)

	alert.RiskScore = s.calcScore(rule.Level)

	s.mu.Lock()
	s.alerts = append(s.alerts, alert)
	s.mu.Unlock()

	atomic.AddInt64(&s.stats.AlertsTriggered, 1)
}

// flushAlerts sends buffered alerts to the output channel.
func (s *Scanner) flushAlerts() {
	s.mu.Lock()
	pending := s.alerts
	s.alerts = nil
	s.mu.Unlock()

	for _, a := range pending {
		select {
		case s.cfg.AlertCh <- a:
		default:
			log.Printf("[detect] alert channel full, dropping: %s", a.Title)
		}
	}
}

// buildSubgraphDesc creates a text description of the event subgraph.
func (s *Scanner) buildSubgraphDesc(evt *pb.Event) string {
	action := eventTypeName(evt.Type)
	target := evt.Pathname
	if target == "" && evt.Daddr > 0 {
		target = fmt.Sprintf("%s:%d", intToIP(evt.Daddr), evt.Dport)
	}
	return fmt.Sprintf("PID %d (%s) %s %s", evt.Pid, evt.Comm, action, target)
}

// calcScore converts severity level to a numeric score.
func (s *Scanner) calcScore(level string) float64 {
	switch level {
	case "critical":
		return 10.0
	case "high":
		return 7.5
	case "medium":
		return 5.0
	case "low":
		return 2.5
	default:
		return 3.0
	}
}

// Stats returns scanner performance statistics.
func (s *Scanner) Stats() map[string]interface{} {
	return map[string]interface{}{
		"events_processed": atomic.LoadInt64(&s.stats.EventsProcessed),
		"events_matched":   atomic.LoadInt64(&s.stats.EventsMatched),
		"alerts_triggered": atomic.LoadInt64(&s.stats.AlertsTriggered),
		"rules_loaded":     len(s.rules),
	}
}

// ─── Event type name mapping ────────────────────────────────

func eventTypeName(typ uint32) string {
	switch typ {
	case 1:
		return "FORK"
	case 2:
		return "EXEC"
	case 10:
		return "OPEN"
	case 11:
		return "CREATE"
	case 12:
		return "MODIFY"
	case 13:
		return "DELETE"
	case 20:
		return "CONNECT"
	case 21:
		return "ACCEPT"
	default:
		return fmt.Sprintf("EVENT_%d", typ)
	}
}
