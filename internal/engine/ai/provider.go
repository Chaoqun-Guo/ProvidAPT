// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"sync"
)

// Provider defines the interface for LLM backends.
// Each provider implements its own HTTP client, request format,
// and response parsing.
type Provider interface {
	// Name returns the provider identifier (e.g. "openai", "ollama").
	Name() string

	// SendChat sends a chat completion request and returns the response text.
	SendChat(endpoint, model, apiKey string, messages []chatMessage) (string, error)

	// IsAvailable checks if the provider endpoint is reachable.
	IsAvailable(endpoint string) bool
}

// ProviderFactory creates a Provider instance.  This allows providers
// with custom initialization (e.g., custom HTTP clients, TLS config).
type ProviderFactory func() Provider

var (
	providers   = map[string]ProviderFactory{}
	providersMu sync.RWMutex
)

// RegisterProvider registers an LLM provider by name.
// Called from init() in provider implementation files.
// Panics if a provider with the same name is already registered.
func RegisterProvider(name string, factory ProviderFactory) {
	providersMu.Lock()
	defer providersMu.Unlock()
	if _, ok := providers[name]; ok {
		panic(fmt.Sprintf("ai: provider %q already registered", name))
	}
	providers[name] = factory
}

// GetProvider returns a named provider instance.
// Returns nil if the provider is not registered.
func GetProvider(name string) Provider {
	providersMu.RLock()
	defer providersMu.RUnlock()
	fn, ok := providers[name]
	if !ok {
		return nil
	}
	return fn()
}

// ListProviders returns all registered provider names.
func ListProviders() []string {
	providersMu.RLock()
	defer providersMu.RUnlock()
	names := make([]string, 0, len(providers))
	for n := range providers {
		names = append(names, n)
	}
	return names
}

// resolveProvider resolves a provider name, falling back to "ollama"
// when the requested provider is not found.
func resolveProvider(name string) Provider {
	if p := GetProvider(name); p != nil {
		return p
	}
	// Fallback to ollama
	if p := GetProvider("ollama"); p != nil {
		return p
	}
	return nil
}
