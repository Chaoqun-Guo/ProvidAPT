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
	RegisterProvider("ollama", func() Provider { return &OllamaProvider{} })
}

// ollamaResponse maps the Ollama /api/chat response body.
type ollamaResponse struct {
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
	Done bool `json:"done"`
}

// OllamaProvider implements the Provider interface for Ollama.
type OllamaProvider struct {
	client *http.Client
}

func (p *OllamaProvider) Name() string { return "ollama" }

func (p *OllamaProvider) clientInstance() *http.Client {
	if p.client == nil {
		p.client = &http.Client{Timeout: 60 * time.Second}
	}
	return p.client
}

func (p *OllamaProvider) SendChat(endpoint, model, apiKey string, messages []chatMessage) (string, error) {
	req := chatRequest{
		Model:    model,
		Messages: messages,
		Stream:   false,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("ollama marshal: %w", err)
	}
	httpReq, err := http.NewRequest("POST", endpoint, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("ollama new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.clientInstance().Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("ollama read body: %w", err)
	}
	var ollamaResp ollamaResponse
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return "", fmt.Errorf("ollama parse: %w (body: %s)", err, string(body))
	}
	return ollamaResp.Message.Content, nil
}

func (p *OllamaProvider) IsAvailable(endpoint string) bool {
	resp, err := p.clientInstance().Get(endpoint)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
