// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// LLM client
// ═══════════════════════════════════════════════════════════════

// LLMConfig configures the LLM client.
type LLMConfig struct {
	// Provider: "openai" or "ollama"
	Provider string

	// API endpoint
	// OpenAI: "https://api.openai.com/v1/chat/completions"
	// Ollama: "http://localhost:11434/api/chat"
	Endpoint string

	// API key (for OpenAI)
	APIKey string

	// Model name
	// OpenAI: "gpt-4", "gpt-3.5-turbo"
	// Ollama: "llama3", "mixtral"
	Model string

	// Request timeout
	Timeout time.Duration

	// Ollama specific: use streaming
	Stream bool

	// MaxRetries retries transient provider failures before returning an error.
	MaxRetries int

	// RetryBackoff is the base sleep between retries.
	RetryBackoff time.Duration

	// CircuitBreakerThreshold opens the circuit after consecutive failures.
	CircuitBreakerThreshold int

	// CircuitBreakerCooldown keeps the circuit open for this duration.
	CircuitBreakerCooldown time.Duration

	// MaxPromptBytes bounds prompt size sent to external LLM services.
	MaxPromptBytes int

	// FallbackWithoutLLM returns a deterministic local answer when the LLM fails.
	FallbackWithoutLLM bool
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *LLMConfig {
	return &LLMConfig{
		Provider:                "ollama",
		Endpoint:                "http://localhost:11434/api/chat",
		Model:                   "llama3",
		Timeout:                 60 * time.Second,
		MaxRetries:              1,
		RetryBackoff:            250 * time.Millisecond,
		CircuitBreakerThreshold: 3,
		CircuitBreakerCooldown:  30 * time.Second,
		MaxPromptBytes:          128 * 1024,
		FallbackWithoutLLM:      true,
	}
}

// DefaultOpenAIConfig returns config for OpenAI.
func DefaultOpenAIConfig(apiKey string) *LLMConfig {
	return &LLMConfig{
		Provider:                "openai",
		Endpoint:                "https://api.openai.com/v1/chat/completions",
		APIKey:                  apiKey,
		Model:                   "gpt-4",
		Timeout:                 60 * time.Second,
		MaxRetries:              1,
		RetryBackoff:            250 * time.Millisecond,
		CircuitBreakerThreshold: 3,
		CircuitBreakerCooldown:  30 * time.Second,
		MaxPromptBytes:          128 * 1024,
		FallbackWithoutLLM:      true,
	}
}

// ── Chat message structures ─────────────────────────────────

type chatMessage struct {
	Role    string `json:"role"` // "system", "user", "assistant"
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

type chatResponse struct {
	Message chatMessage `json:"message"`
	Content string      `json:"content,omitempty"` // Ollama format
	Error   string      `json:"error,omitempty"`
}

// ── LLMClient ───────────────────────────────────────────────

// LLMClient sends prompts to an LLM (OpenAI or Ollama).
type LLMClient struct {
	cfg     *LLMConfig
	breaker *llmCircuitBreaker
}

// NewLLMClient creates an LLM client.
func NewLLMClient(cfg *LLMConfig) *LLMClient {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	normalizeLLMConfig(cfg)
	return &LLMClient{
		cfg:     cfg,
		breaker: &llmCircuitBreaker{},
	}
}

// Analyse sends the full analysis prompt to the LLM.
func (lc *LLMClient) Analyse(graphJSON string) (string, error) {
	systemMsg := chatMessage{Role: "system", Content: SystemPrompt}
	userMsg := chatMessage{Role: "user", Content: AnalysePrompt(graphJSON)}

	return lc.sendChat([]chatMessage{systemMsg, userMsg})
}

// Ask sends a specific question about the graph.
func (lc *LLMClient) Ask(graphJSON string, question string) (string, error) {
	systemMsg := chatMessage{Role: "system", Content: SystemPrompt}
	userMsg := chatMessage{Role: "user", Content: QAPrompt(graphJSON, question)}

	return lc.sendChat([]chatMessage{systemMsg, userMsg})
}

// sendChat sends a chat completion request via the registered provider.
func (lc *LLMClient) sendChat(messages []chatMessage) (string, error) {
	if lc.breaker != nil && lc.breaker.open(lc.cfg.CircuitBreakerThreshold, lc.cfg.CircuitBreakerCooldown) {
		if lc.cfg.FallbackWithoutLLM {
			return fallbackChatAnswer(messages), nil
		}
		return "", fmt.Errorf("ai: provider circuit open")
	}
	p := resolveProvider(lc.cfg.Provider)
	if p == nil {
		return "", fmt.Errorf("ai: no provider available for %q (registered: %v)",
			lc.cfg.Provider, ListProviders())
	}
	prepared := limitMessages(messages, lc.cfg.MaxPromptBytes)
	var lastErr error
	for attempt := 0; attempt <= lc.cfg.MaxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), lc.cfg.Timeout)
		response, err := p.SendChat(ctx, lc.cfg.Endpoint, lc.cfg.Model, lc.cfg.APIKey, prepared)
		cancel()
		if err == nil {
			if lc.breaker != nil {
				lc.breaker.recordSuccess()
			}
			return response, nil
		}
		lastErr = err
		if attempt < lc.cfg.MaxRetries {
			time.Sleep(lc.cfg.RetryBackoff * time.Duration(attempt+1))
		}
	}
	if lc.breaker != nil {
		lc.breaker.recordFailure()
		lc.breaker.tripIfNeeded(lc.cfg.CircuitBreakerThreshold, lc.cfg.CircuitBreakerCooldown)
	}
	if lc.cfg.FallbackWithoutLLM {
		return fallbackChatAnswer(messages), nil
	}
	return "", lastErr
}

// IsAvailable checks if the LLM endpoint is reachable via the registered provider.
func (lc *LLMClient) IsAvailable() bool {
	p := resolveProvider(lc.cfg.Provider)
	if p == nil {
		return false
	}
	return p.IsAvailable(lc.cfg.Endpoint)
}

// ═══════════════════════════════════════════════════════════════
// AI Interpreter (facade)
// ═══════════════════════════════════════════════════════════════

// Interpreter combines graph serialization with LLM interaction.
type Interpreter struct {
	client *LLMClient
}

// NewInterpreter creates an AI interpreter.
func NewInterpreter(cfg *LLMConfig) *Interpreter {
	return &Interpreter{
		client: NewLLMClient(cfg),
	}
}

// AnalysisResult holds the full LLM analysis output.
type AnalysisResult struct {
	RawOutput string    `json:"raw_output"`
	GraphJSON string    `json:"graph_json"`
	Graph     *LLMGraph `json:"graph"`
	Error     string    `json:"error,omitempty"`
}

// AnalyseAlert runs the full AI analysis pipeline.
func (ai *Interpreter) AnalyseAlert(graphJSON string) *AnalysisResult {
	result := &AnalysisResult{
		GraphJSON: graphJSON,
	}

	response, err := ai.client.Analyse(graphJSON)
	if err != nil {
		result.Error = err.Error()
		log.Printf("[ai] analyse error: %v", err)
	} else {
		result.RawOutput = response
	}

	return result
}

// AnswerQuestion answers a specific question about the graph.
func (ai *Interpreter) AnswerQuestion(graphJSON string, question string) (string, error) {
	return ai.client.Ask(graphJSON, question)
}

// FormatResponse pretty-prints the LLM analysis response.
func FormatResponse(text string) string {
	// Ensure sections are clearly separated
	text = strings.ReplaceAll(text, "### ", "\n### ")
	return strings.TrimSpace(text)
}

type llmCircuitBreaker struct {
	mu          sync.Mutex
	failures    int
	openedUntil time.Time
}

func (b *llmCircuitBreaker) open(threshold int, cooldown time.Duration) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if threshold <= 0 || cooldown <= 0 {
		return false
	}
	if time.Now().Before(b.openedUntil) {
		return true
	}
	return false
}

func (b *llmCircuitBreaker) recordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	b.openedUntil = time.Time{}
}

func (b *llmCircuitBreaker) recordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures++
}

func (b *llmCircuitBreaker) tripIfNeeded(threshold int, cooldown time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if threshold > 0 && cooldown > 0 && b.failures >= threshold {
		b.openedUntil = time.Now().Add(cooldown)
	}
}

func normalizeLLMConfig(cfg *LLMConfig) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 250 * time.Millisecond
	}
	if cfg.CircuitBreakerThreshold < 0 {
		cfg.CircuitBreakerThreshold = 0
	}
	if cfg.CircuitBreakerCooldown <= 0 {
		cfg.CircuitBreakerCooldown = 30 * time.Second
	}
	if cfg.MaxPromptBytes <= 0 {
		cfg.MaxPromptBytes = 128 * 1024
	}
}

func limitMessages(messages []chatMessage, maxBytes int) []chatMessage {
	if maxBytes <= 0 {
		return messages
	}
	used := 0
	limited := make([]chatMessage, 0, len(messages))
	for _, msg := range messages {
		content := msg.Content
		remaining := maxBytes - used
		if remaining <= 0 {
			content = ""
		} else if len(content) > remaining {
			content = content[:remaining] + "\n[truncated for LLM stability]"
		}
		used += len(content)
		limited = append(limited, chatMessage{Role: msg.Role, Content: content})
	}
	return limited
}

func fallbackChatAnswer(messages []chatMessage) string {
	question := ""
	for i := len(messages) - 1; i >= 0; i-- {
		if strings.TrimSpace(messages[i].Content) != "" {
			question = strings.TrimSpace(messages[i].Content)
			break
		}
	}
	if len(question) > 240 {
		question = question[:240] + "..."
	}
	return "LLM provider is unavailable. ProvidAPT used deterministic fallback analysis. Review the provenance graph, event timeline, high-risk process/file/network edges, and alert evidence manually. Context: " + question
}
