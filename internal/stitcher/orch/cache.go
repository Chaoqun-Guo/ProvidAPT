package orch

import (
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Local policy cache — offline execution during network partitions
// ═══════════════════════════════════════════════════════════════

// CachedPolicyStore stores policies locally for offline execution.
// Agents use this to continue enforcing global policies even when
// disconnected from the central server.
type CachedPolicyStore struct {
	mu        sync.Mutex
	commands  []*PolicyCommand
	isolation *IsolationEngine
	lastSync  time.Time
	synced    bool
}

// NewCachedPolicyStore creates a local policy cache.
func NewCachedPolicyStore(engine *IsolationEngine) *CachedPolicyStore {
	return &CachedPolicyStore{
		isolation: engine,
	}
}

// SyncFromServer downloads the latest policies from the central server.
// In production, this is a gRPC call.
func (cps *CachedPolicyStore) SyncFromServer(commands []*PolicyCommand) {
	cps.mu.Lock()
	defer cps.mu.Unlock()

	for _, cmd := range commands {
		cps.commands = append(cps.commands, cmd)
		// Apply immediately
		if cps.isolation != nil {
			cps.isolation.ExecuteCommand(cmd)
		}
	}
	cps.lastSync = time.Now()
	cps.synced = true
	log.Printf("[cache] synced %d policies from server", len(commands))
}

// ExecuteCached applies cached policies.  Called when the agent
// detects a network partition — continues to enforce without
// central connectivity.
func (cps *CachedPolicyStore) ExecuteCached() int {
	cps.mu.Lock()
	defer cps.mu.Unlock()

	applied := 0
	for _, cmd := range cps.commands {
		if cps.isolation != nil {
			cps.isolation.ExecuteCommand(cmd)
			applied++
		}
	}
	return applied
}

// IsSynced returns whether the cache has been initialized.
func (cps *CachedPolicyStore) IsSynced() bool {
	cps.mu.Lock()
	defer cps.mu.Unlock()
	return cps.synced
}

// LastSync returns the last synchronization time.
func (cps *CachedPolicyStore) LastSync() time.Time {
	cps.mu.Lock()
	defer cps.mu.Unlock()
	return cps.lastSync
}

// CommandCount returns the number of cached commands.
func (cps *CachedPolicyStore) CommandCount() int {
	cps.mu.Lock()
	defer cps.mu.Unlock()
	return len(cps.commands)
}

// Stats returns cache statistics.
func (cps *CachedPolicyStore) Stats() map[string]interface{} {
	cps.mu.Lock()
	defer cps.mu.Unlock()
	return map[string]interface{}{
		"cached_commands": len(cps.commands),
		"synced":          cps.synced,
		"last_sync":       cps.lastSync.Format(time.RFC3339),
	}
}

