// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package plugin provides the analysis plugin system for ProvidAPT.
// It defines a Plugin interface and registry, along with concrete
// plugins for Sigma rule matching, threat intelligence alignment,
// and multi-dimensional scoring.
package plugin

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ErrUnsupported is returned by Discover on platforms that do not
// support dynamic plugin loading (plugin package requires Unix).
var ErrUnsupported = errors.New("plugin discovery not supported on this platform")

// DiscoveryResult summarises the outcome of a Discover call.
type DiscoveryResult struct {
	// Loaded contains the names of plugins successfully loaded.
	Loaded []string

	// Failed contains the paths of plugins that failed to load,
	// with the associated error message.
	Failed []string
}

// ═══════════════════════════════════════════════════════════════
// Registry
// ═══════════════════════════════════════════════════════════════

// Registry manages all registered plugins.
var (
	mu      sync.RWMutex
	plugins = make(map[string]Plugin)
)

// Register adds a plugin to the global registry.
func Register(p Plugin) error {
	mu.Lock()
	defer mu.Unlock()
	name := p.Name()
	if _, ok := plugins[name]; ok {
		return fmt.Errorf("plugin %q already registered", name)
	}
	plugins[name] = p
	return nil
}

// Get retrieves a plugin by name.
func Get(name string) Plugin {
	mu.RLock()
	defer mu.RUnlock()
	return plugins[name]
}

// List returns all registered plugin names.
func List() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(plugins))
	for n := range plugins {
		names = append(names, n)
	}
	return names
}

// ═══════════════════════════════════════════════════════════════
// Plugin interface
// ═══════════════════════════════════════════════════════════════

// Plugin is the interface all analysis plugins must implement.
type Plugin interface {
	// Name returns a unique plugin identifier.
	Name() string

	// Analyse is called with a provenance graph snapshot and returns
	// a list of findings.
	Analyse(snap *provenance.Graph) []*Finding
}

// LifecyclePlugin is an optional interface that plugins can implement
// alongside Plugin to support initialization and shutdown hooks.
type LifecyclePlugin interface {
	// Init is called once when the plugin is loaded. Config is
	// a plugin-specific key/value map. Return an error to abort.
	Init(config map[string]interface{}) error

	// Shutdown is called when the plugin is being unloaded.
	Shutdown() error
}

// Finding is the result of a plugin analysis.
type Finding struct {
	PluginName string                 `json:"plugin"`
	Title      string                 `json:"title"`
	Severity   string                 `json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
	Score      float64                `json:"score"`
	NodeIDs    []string               `json:"node_ids"`
	Evidence   map[string]interface{} `json:"evidence,omitempty"`
}

func (f *Finding) String() string {
	return fmt.Sprintf("[%s] [%s] %s (nodes=%v)", f.Severity, f.PluginName, f.Title, f.NodeIDs)
}

// ═══════════════════════════════════════════════════════════════
// PluginManager — runs all registered plugins
// ═══════════════════════════════════════════════════════════════

// PluginManager orchestrates multiple plugins over a graph snapshot.
type PluginManager struct {
	enabled []string
	configs map[string]map[string]interface{}
}

// NewManager creates a manager with the given enabled plugin names.
func NewManager(enabled []string) *PluginManager {
	return &PluginManager{enabled: enabled}
}

// SetPluginConfig sets configuration for a named plugin.
func (pm *PluginManager) SetPluginConfig(name string, cfg map[string]interface{}) {
	if pm.configs == nil {
		pm.configs = make(map[string]map[string]interface{})
	}
	pm.configs[name] = cfg
}

// InitAll initializes all enabled plugins that implement LifecyclePlugin.
// Returns the first initialization error, if any.
func (pm *PluginManager) InitAll() error {
	for _, name := range pm.enabled {
		p := Get(name)
		if p == nil {
			continue
		}
		if lp, ok := p.(LifecyclePlugin); ok {
			if err := lp.Init(pm.configs[name]); err != nil {
				return fmt.Errorf("plugin %q init: %w", name, err)
			}
		}
	}
	return nil
}

// ShutdownAll shuts down all enabled plugins that implement LifecyclePlugin.
func (pm *PluginManager) ShutdownAll() {
	for _, name := range pm.enabled {
		p := Get(name)
		if p == nil {
			continue
		}
		if lp, ok := p.(LifecyclePlugin); ok {
			_ = lp.Shutdown()
		}
	}
}

// RunAll executes all enabled plugins against the graph snapshot
// and returns combined findings.
func (pm *PluginManager) RunAll(snap *provenance.Graph) []*Finding {
	var all []*Finding
	for _, name := range pm.enabled {
		p := Get(name)
		if p == nil {
			continue
		}
		findings := p.Analyse(snap)
		all = append(all, findings...)
	}
	return all
}

// ── Common helpers ──────────────────────────────────────────

// NodeLabelMatch checks if a node's label contains the given substring.
func NodeLabelMatch(n *provenance.Node, substr string) bool {
	return strings.Contains(strings.ToLower(n.Label), strings.ToLower(substr))
}

// NodeAttrString returns a node attribute as string, or "".
func NodeAttrString(n *provenance.Node, key string) string {
	if n == nil {
		return ""
	}
	if v, ok := n.Attributes[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return ""
}

// ── Plugin discovery ──────────────────────────────────────────

// Discover scans dir for compiled Go plugins (.so files built with
// -buildmode=plugin), loads each one, and calls its exported
// RegisterPlugins() function to auto-register types in the global
// registry.
//
// On non-Unix platforms (e.g. Windows), Discover returns ErrUnsupported
// and a nil result.
func Discover(dir string) (*DiscoveryResult, error) {
	return discoverPlugins(dir)
}

// discoverPlugins is implemented per-platform in discover_*.go files.
