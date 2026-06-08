// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"log"
	"strings"
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
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *LLMConfig {
	return &LLMConfig{
		Provider: "ollama",
		Endpoint: "http://localhost:11434/api/chat",
		Model:    "llama3",
		Timeout:  60 * time.Second,
	}
}

// DefaultOpenAIConfig returns config for OpenAI.
func DefaultOpenAIConfig(apiKey string) *LLMConfig {
	return &LLMConfig{
		Provider: "openai",
		Endpoint: "https://api.openai.com/v1/chat/completions",
		APIKey:   apiKey,
		Model:    "gpt-4",
		Timeout:  60 * time.Second,
	}
}

// ── Chat message structures ─────────────────────────────────

type chatMessage struct {
	Role    string `json:"role"`    // "system", "user", "assistant"
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
	cfg *LLMConfig
}

// NewLLMClient creates an LLM client.
func NewLLMClient(cfg *LLMConfig) *LLMClient {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &LLMClient{
		cfg: cfg,
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
	p := resolveProvider(lc.cfg.Provider)
	if p == nil {
		return "", fmt.Errorf("ai: no provider available for %q (registered: %v)",
			lc.cfg.Provider, ListProviders())
	}
	return p.SendChat(lc.cfg.Endpoint, lc.cfg.Model, lc.cfg.APIKey, messages)
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
	RawOutput string `json:"raw_output"`
	GraphJSON string `json:"graph_json"`
	Graph     *LLMGraph `json:"graph"`
	Error     string   `json:"error,omitempty"`
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
