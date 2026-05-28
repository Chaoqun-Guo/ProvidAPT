package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
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
		"text":       summary.Text(),
		"title":      summary.Title,
		"severity":   summary.Severity,
		"timestamp":  summary.Timestamp,
		"attack_path": summary.AttackPath,
		"entities":   summary.KeyEntities,
	}

	data, _ := json.Marshal(payload)

	var lastErr error
	for i := 0; i < ws.cfg.Retries; i++ {
		req, err := http.NewRequest("POST", ws.cfg.URL, bytes.NewReader(data))
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
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			log.Printf("[webhook] alert sent to %s (status=%d)", ws.cfg.URL, resp.StatusCode)
			return nil
		}
		lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return fmt.Errorf("webhook failed after %d retries: %w", ws.cfg.Retries, lastErr)
}

// ─── Alert pipeline orchestrator ─────────────────────────────

// AlertPipeline ties pattern matching, incident aggregation, summary,
// and webhook delivery into a single pipeline.
type AlertPipeline struct {
	Matcher  *PatternMatcher
	Incidents *IncidentManager
	Summaries *SummaryGenerator
	Webhook  *WebhookSender
}

// NewAlertPipeline creates a complete alert pipeline.
func NewAlertPipeline(graph *provenance.Graph, webhookURL string) *AlertPipeline {
	return &AlertPipeline{
		Matcher:   NewPatternMatcher(),
		Incidents: NewIncidentManager(),
		Summaries: NewSummaryGenerator(graph),
		Webhook:   NewWebhookSender(&WebhookConfig{URL: webhookURL}),
	}
}

// Tick runs one full alert cycle: match → aggregate → summarise → notify.
func (ap *AlertPipeline) Tick(graph *provenance.Graph) {
	// 1. Resolve old incidents
	ap.Incidents.ResolveOld()

	// 2. Match patterns
	matches := ap.Matcher.MatchAll(graph)
	if len(matches) == 0 {
		return
	}

	// 3. Aggregate into incidents
	for _, match := range matches {
		inc := ap.Incidents.Ingest(match)
		if inc == nil {
			continue // was merged into existing incident
		}

		// 4. Generate summary
		summary := ap.Summaries.Generate(inc)

		// 5. Send webhook
		if err := ap.Webhook.Send(summary); err != nil {
			log.Printf("[alert] webhook error: %v", err)
		}

		log.Printf("[alert] %s", summary.Text())
	}
}
