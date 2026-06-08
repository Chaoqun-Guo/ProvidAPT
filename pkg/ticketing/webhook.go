// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package ticketing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type WebhookClient struct {
	url    string
	secret string
	client *http.Client
}

func NewWebhookClient(url, secret string) *WebhookClient {
	return &WebhookClient{
		url:    url,
		secret: secret,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *WebhookClient) Provider() string { return "webhook" }

type webhookPayload struct {
	Event     string        `json:"event"`
	Request   CreateRequest `json:"request"`
	Timestamp time.Time     `json:"timestamp"`
}

type webhookCommentPayload struct {
	Event     string    `json:"event"`
	Issue     Issue     `json:"issue"`
	Comment   string    `json:"comment"`
	Timestamp time.Time `json:"timestamp"`
}

func (c *WebhookClient) CreateIssue(req CreateRequest) (Issue, error) {
	body, err := json.Marshal(webhookPayload{
		Event:     "providapt.ticket.create",
		Request:   req,
		Timestamp: time.Now().UTC(),
	})
	if err != nil {
		return Issue{}, fmt.Errorf("marshal ticket webhook payload: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return Issue{}, fmt.Errorf("build ticket webhook request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "ProvidAPT/1.0")
	if c.secret != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.secret)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return Issue{}, fmt.Errorf("ticket webhook post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return Issue{}, fmt.Errorf("ticket webhook returned %d", resp.StatusCode)
	}

	return Issue{
		Provider:  c.Provider(),
		URL:       c.url,
		CreatedAt: time.Now().UTC(),
	}, nil
}

func (c *WebhookClient) AddComment(issue Issue, comment string) error {
	body, err := json.Marshal(webhookCommentPayload{
		Event:     "providapt.ticket.comment",
		Issue:     issue,
		Comment:   comment,
		Timestamp: time.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("marshal ticket webhook comment payload: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build ticket webhook comment request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "ProvidAPT/1.0")
	if c.secret != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.secret)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("ticket webhook comment post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ticket webhook comment returned %d", resp.StatusCode)
	}
	return nil
}
