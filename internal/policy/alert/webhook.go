// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/metrics"
)

// ═══════════════════════════════════════════════════════════════
// Webhook notification
// ═══════════════════════════════════════════════════════════════

// WebhookConfig for alert delivery.
type WebhookConfig struct {
	// URL — webhook endpoint (Slack, Teams, custom).
	URL string

	// Headers — additional HTTP headers.
	Headers map[string]string

	// Timeout — request timeout.
	Timeout time.Duration

	// Retries — number of retries on failure.
	Retries int
}

// DefaultWebhookConfig returns sensible defaults.
func DefaultWebhookConfig() *WebhookConfig {
	return &WebhookConfig{
		Timeout: 10 * time.Second,
		Retries: 3,
	}
}

// WebhookSender delivers alert summaries to external endpoints.
type WebhookSender struct {
	cfg *WebhookConfig
}

// NewWebhookSender creates a webhook sender.
func NewWebhookSender(cfg *WebhookConfig) *WebhookSender {
	if cfg == nil {
		cfg = DefaultWebhookConfig()
	}
	return &WebhookSender{cfg: cfg}
}

// Send delivers an alert summary to the configured webhook.
func (ws *WebhookSender) Send(summary *AlertSummary) error {
	if ws.cfg.URL == "" {
		log.Printf("[webhook] no URL configured, alert logged only")
		return nil
	}

	payload := map[string]interface{}{
		"text":        summary.Text(),
		"title":       summary.Title,
		"severity":    summary.Severity,
		"timestamp":   summary.Timestamp,
		"attack_path": summary.AttackPath,
		"entities":    summary.KeyEntities,
	}

	data, _ := json.Marshal(payload)

	var lastErr error
	for i := 0; i < ws.cfg.Retries; i++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ws.cfg.URL, bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range ws.cfg.Headers {
			req.Header.Set(k, v)
		}

		client := &http.Client{Timeout: ws.cfg.Timeout}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			log.Printf("[webhook] attempt %d failed: %v", i+1, err)
			time.Sleep(time.Second * time.Duration(i+1))
			continue
		}
		if err := resp.Body.Close(); err != nil {
			log.Printf("[webhook] response body close failed: %v", err)
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			log.Printf("[webhook] alert sent to %s (status=%d)", ws.cfg.URL, resp.StatusCode)
			return nil
		}
		lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return fmt.Errorf("webhook failed after %d retries: %w", ws.cfg.Retries, lastErr)
}

// ─── Rate limiter for storm control ─────────────────────────

// RateLimitConfig tunes the alert rate limiter.
type RateLimitConfig struct {
	// MaxAlertsPerMinute is the maximum number of alerts allowed per minute.
	// Beyond this threshold, alerts are coalesced into storm summaries.
	MaxAlertsPerMinute int

	// StormCooldown is the duration to suppress individual alerts after
	// a storm is detected, sending only periodic storm summaries.
	StormCooldown time.Duration
}

// DefaultRateLimitConfig returns sensible defaults.
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		MaxAlertsPerMinute: 60,
		StormCooldown:      30 * time.Second,
	}
}

// RateLimiter implements a sliding-window alert rate limiter with
// storm coalescing.
type RateLimiter struct {
	mu            sync.Mutex
	cfg           *RateLimitConfig
	window        []time.Time // timestamps of alerts within the window
	stormUntil    time.Time   // suppress individual alerts until this time
	stormCount    int         // total alerts during storm
	lastStormSent time.Time   // last storm summary sent
}

// NewRateLimiter creates a rate limiter.
func NewRateLimiter(cfg *RateLimitConfig) *RateLimiter {
	if cfg == nil {
		cfg = DefaultRateLimitConfig()
	}
	return &RateLimiter{cfg: cfg}
}

// Allow checks if an alert should be delivered or coalesced.
// Returns (allow=true) if the alert should be sent.
// Returns (allow=false, isStorm=true) when a storm is active — the caller
// should send a coalesced storm summary instead of individual alerts.
func (rl *RateLimiter) Allow() (allow bool, isStorm bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-1 * time.Minute)

	// Prune old entries outside the window
	cut := 0
	for cut < len(rl.window) && rl.window[cut].Before(windowStart) {
		cut++
	}
	rl.window = rl.window[cut:]

	// Check storm cooldown
	if now.Before(rl.stormUntil) {
		rl.stormCount++
		if now.After(rl.lastStormSent.Add(rl.cfg.StormCooldown)) {
			rl.lastStormSent = now
			return false, true // time for a storm summary tick
		}
		return false, true // suppressed during storm
	}

	// Check rate limit
	if len(rl.window) >= rl.cfg.MaxAlertsPerMinute {
		rl.stormUntil = now.Add(rl.cfg.StormCooldown)
		rl.stormCount = len(rl.window)
		rl.lastStormSent = now
		return false, true // storm just started
	}

	// Normal: record and allow
	rl.window = append(rl.window, now)
	return true, false
}

// StormStats returns the number of alerts suppressed and remaining cooldown.
// If no storm is active, returns (0, 0).
func (rl *RateLimiter) StormStats() (int, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.stormUntil.IsZero() || time.Now().After(rl.stormUntil) {
		return 0, 0
	}
	return rl.stormCount, time.Until(rl.stormUntil)
}

// ─── Alert pipeline orchestrator ─────────────────────────────

// AlertPipeline ties pattern matching, incident aggregation, summary,
// webhook delivery, and rate limiting into a single pipeline.
type AlertPipeline struct {
	Matcher     *PatternMatcher
	Incidents   *IncidentManager
	Summaries   *SummaryGenerator
	Webhook     *WebhookSender
	RateLimiter *RateLimiter

	// AlertSummaryCh, when set, receives every alert summary generated by
	// Tick() for external consumers (gRPC streaming, dashboard, etc.).
	// Non-blocking send — slow consumers drop events.
	AlertSummaryCh chan *AlertSummary `json:"-"`
}

// NewAlertPipeline creates a complete alert pipeline.
func NewAlertPipeline(graph *provenance.Graph, webhookURL string) *AlertPipeline {
	return &AlertPipeline{
		Matcher:     NewPatternMatcher(),
		Incidents:   NewIncidentManager(),
		Summaries:   NewSummaryGenerator(graph),
		Webhook:     NewWebhookSender(&WebhookConfig{URL: webhookURL}),
		RateLimiter: NewRateLimiter(nil),
	}
}

// Tick runs one full alert cycle: match -> aggregate -> rate-limit -> summarize -> notify.
func (ap *AlertPipeline) Tick(graph *provenance.Graph) {
	// 1. Resolve old incidents
	ap.Incidents.ResolveOld()

	// 2. Match patterns
	matches := ap.Matcher.MatchAll(graph)
	if len(matches) == 0 {
		// Send all-clear if storm just ended
		if cnt, _ := ap.RateLimiter.StormStats(); cnt > 0 {
			summary := &AlertSummary{
				Title:       "Alert Storm Resolved",
				Severity:    "info",
				Timestamp:   time.Now().Format(time.RFC3339),
				Description: fmt.Sprintf("Alert storm cleared after %d alerts suppressed", cnt),
			}
			_ = ap.Webhook.Send(summary)
			ap.sendToAlertCh(summary)
		}
		return
	}

	// 3. Rate-limit and process matches
	var stormSummary *AlertSummary

	for _, match := range matches {
		severity := "info"
		if len(match.Nodes) > 5 {
			severity = "high"
		} else if len(match.Nodes) > 2 {
			severity = "medium"
		}
		metrics.AlertsTriggered.WithLabelValues(severity).Inc()

		// Rate limit check
		allow, isStorm := ap.RateLimiter.Allow()
		if !allow {
			if isStorm && stormSummary == nil {
				cnt, _ := ap.RateLimiter.StormStats()
				stormSummary = &AlertSummary{
					Title:       "Alert Storm Detected",
					Severity:    "critical",
					Timestamp:   time.Now().Format(time.RFC3339),
					AttackPath:  "",
					KeyEntities: []string{fmt.Sprintf("%d alerts suppressed", cnt)},
					Description: fmt.Sprintf("Alert storm in progress — %d alerts suppressed. "+
						"Individual alerts will resume after cooldown.", cnt),
				}
			}
			continue
		}

		inc := ap.Incidents.Ingest(match)
		if inc == nil {
			continue
		}

		// 4. Generate and send summary
		summary := ap.Summaries.Generate(inc)
		if err := ap.Webhook.Send(summary); err != nil {
			log.Printf("[alert] webhook error: %v", err)
		}
		log.Printf("[alert] %s", summary.Text())
		ap.sendToAlertCh(summary)
	}

	// 5. Send storm summary if any alerts were suppressed
	if stormSummary != nil {
		if err := ap.Webhook.Send(stormSummary); err != nil {
			log.Printf("[alert] storm webhook error: %v", err)
		}
		log.Printf("[alert] STORM: %s", stormSummary.Description)
		ap.sendToAlertCh(stormSummary)
	}
}

// sendToAlertCh non-blocking sends a summary to AlertSummaryCh if configured.
func (ap *AlertPipeline) sendToAlertCh(summary *AlertSummary) {
	if ap.AlertSummaryCh == nil {
		return
	}
	select {
	case ap.AlertSummaryCh <- summary:
	default:
		log.Printf("[alert] alert channel full, dropping summary: %s", summary.Title)
	}
}
