// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// WebhookNotifier sends alerts to a generic HTTP endpoint as JSON POST.
type WebhookNotifier struct {
	url    string
	secret string // optional HMAC secret for Authorization header
	client *http.Client
}

// NewWebhookNotifier creates a notifier that POSTs JSON alerts to url.
func NewWebhookNotifier(url string) *WebhookNotifier {
	return &WebhookNotifier{
		url: url,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SetSecret sets an optional bearer token sent as Authorization header.
func (w *WebhookNotifier) SetSecret(secret string) { w.secret = secret }

// Name returns the notifier identifier.
func (w *WebhookNotifier) Name() string { return fmt.Sprintf("webhook:%s", w.url) }

// webhookEnvelope is the JSON payload sent to the webhook endpoint.
type webhookEnvelope struct {
	Event     string    `json:"event"`
	Alert     Alert     `json:"alert"`
	Timestamp time.Time `json:"timestamp"`
}

// Send delivers the alert to the webhook endpoint.
func (w *WebhookNotifier) Send(alert Alert) error {
	env := webhookEnvelope{
		Event:     "providapt.alert",
		Alert:     alert,
		Timestamp: time.Now(),
	}

	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("webhook marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ProvidAPT/1.0")

	if w.secret != "" {
		req.Header.Set("Authorization", "Bearer "+w.secret)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}
