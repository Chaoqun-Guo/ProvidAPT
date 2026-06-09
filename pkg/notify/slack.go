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

// SlackNotifier sends alerts to a Slack channel via Incoming Webhook.
type SlackNotifier struct {
	webhookURL string
	channel    string // optional: override Slack channel
	username   string // optional: override bot name
	client     *http.Client
}

// NewSlackNotifier creates a notifier that posts to a Slack webhook.
// The webhookURL is the Slack Incoming Webhook URL.
func NewSlackNotifier(webhookURL string) *SlackNotifier {
	return &SlackNotifier{
		webhookURL: webhookURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SetChannel overrides the Slack channel (e.g. "#security-alerts").
func (s *SlackNotifier) SetChannel(ch string) { s.channel = ch }

// SetUsername overrides the bot display name.
func (s *SlackNotifier) SetUsername(name string) { s.username = name }

// Name returns the notifier identifier.
func (s *SlackNotifier) Name() string {
	if s.channel != "" {
		return fmt.Sprintf("slack:%s", s.channel)
	}
	return "slack"
}

// slackPayload is the Slack message attachment format.
type slackPayload struct {
	Channel     string            `json:"channel,omitempty"`
	Username    string            `json:"username,omitempty"`
	Text        string            `json:"text"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

type slackAttachment struct {
	Color string `json:"color"`
	Title string `json:"title"`
	Text  string `json:"text"`
	Ts    int64  `json:"ts"`
}

func severityColor(sev Severity) string {
	switch sev {
	case SeverityCritical:
		return "danger"
	case SeverityHigh:
		return "danger"
	case SeverityMedium:
		return "warning"
	case SeverityLow:
		return "good"
	default:
		return "#cccccc"
	}
}

// Send delivers the alert to Slack.
func (s *SlackNotifier) Send(alert Alert) error {
	color := severityColor(alert.Severity)
	title := fmt.Sprintf("[%s] %s", alert.Severity, alert.Pattern)

	text := alert.Headline
	if alert.Reason != "" {
		text += "\n" + alert.Reason
	}

	payload := slackPayload{
		Channel:  s.channel,
		Username: s.username,
		Text:     fmt.Sprintf("*ProvidAPT Alert* — %s", alert.Headline),
		Attachments: []slackAttachment{{
			Color: color,
			Title: title,
			Text:  text,
			Ts:    alert.Timestamp.Unix(),
		}},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("slack marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack returned %d", resp.StatusCode)
	}
	return nil
}
