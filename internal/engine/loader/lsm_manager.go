// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package loader

import "fmt"

// lsm_manager.go — Manages per-hook enable/disable at runtime.
// This allows selective activation of heavyweight hooks.

// HookID identifies a specific LSM hook by name.
type HookID string

const (
	HookTaskAlloc      HookID = "task_alloc"
	HookTaskFree       HookID = "task_free"
	HookFileOpen       HookID = "file_open"
	HookFilePermission HookID = "file_permission"
	HookBprmCheck      HookID = "bprm_check_security"
	HookSocketConnect  HookID = "socket_connect"
)

// HookConfig controls which hooks are enabled at load time.
type HookConfig struct {
	EnabledHooks []HookID
}

// DefaultHooks returns the default set of enabled hooks.
func DefaultHooks() HookConfig {
	return HookConfig{
		EnabledHooks: []HookID{
			HookTaskAlloc,
			HookTaskFree,
			HookFileOpen,
			HookBprmCheck,
			HookSocketConnect,
		},
	}
}

var supportedHooks = map[HookID]struct{}{
	HookTaskAlloc:      {},
	HookTaskFree:       {},
	HookFileOpen:       {},
	HookFilePermission: {},
	HookBprmCheck:      {},
	HookSocketConnect:  {},
}

// ParseHookConfig validates configured hook names, removes duplicates,
// and falls back to the default hook set when no explicit list is provided.
func ParseHookConfig(names []string) (HookConfig, error) {
	if len(names) == 0 {
		return DefaultHooks(), nil
	}

	enabled := make([]HookID, 0, len(names))
	seen := make(map[HookID]struct{}, len(names))
	for _, name := range names {
		hook := HookID(name)
		if _, ok := supportedHooks[hook]; !ok {
			return HookConfig{}, fmt.Errorf("unknown kernel hook %q", name)
		}
		if _, ok := seen[hook]; ok {
			continue
		}
		seen[hook] = struct{}{}
		enabled = append(enabled, hook)
	}

	if len(enabled) == 0 {
		return HookConfig{}, fmt.Errorf("no kernel hooks enabled")
	}

	return HookConfig{EnabledHooks: enabled}, nil
}
