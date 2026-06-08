// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func init() {
	RegisterProvider("openai", func() Provider { return &OpenAIProvider{} })
}

// OpenAIProvider implements the Provider interface for OpenAI-compatible APIs.
type OpenAIProvider struct {
	client *http.Client
}

func (p *OpenAIProvider) Name() string { return "openai" }

func (p *OpenAIProvider) clientInstance() *http.Client {
	if p.client == nil {
		p.client = &http.Client{Timeout: 60 * time.Second}
	}
	return p.client
}

func (p *OpenAIProvider) SendChat(endpoint, model, apiKey string, messages []chatMessage) (string, error) {
	req := chatRequest{
		Model:    model,
		Messages: messages,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("openai marshal: %w", err)
	}
	httpReq, err := http.NewRequest("POST", endpoint, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("openai new request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.clientInstance().Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("openai request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("openai read body: %w", err)
	}
	var chatResp chatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return "", fmt.Errorf("openai parse: %w (body: %s)", err, string(body))
	}
	if chatResp.Error != "" {
		return "", fmt.Errorf("openai error: %s", chatResp.Error)
	}
	return chatResp.Message.Content, nil
}

func (p *OpenAIProvider) IsAvailable(endpoint string) bool {
	resp, err := p.clientInstance().Get(endpoint)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
