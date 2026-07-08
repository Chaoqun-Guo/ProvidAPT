// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package selfheal

import (
	"log"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/pkg/audit"
)

// recordReloadFailure logs a reload failure and trips the circuit breaker
// after a threshold of consecutive failures within the time window.
func (h *Healer) recordReloadFailure(msg string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-10 * time.Minute)

	// Reset if the window expired
	if h.cbFirstFailAt.Before(windowStart) {
		h.cbFailures = 0
	}
	if h.cbFirstFailAt.IsZero() {
		h.cbFirstFailAt = now
	}

	h.cbFailures++
	h.failCnt++
	h.healthy = false

	h.auditLog = append(h.auditLog, AuditEvent{
		Timestamp: now,
		Type:      "reload",
		Severity:  "CRITICAL",
		Message:   msg,
	})
	log.Printf("[heal] reload failed (%d/3): %s", h.cbFailures, msg)

	// Trip circuit breaker if threshold exceeded (3 failures in window)
	if h.cbFailures >= 3 {
		h.cbTrippedAt = now
		h.auditLog = append(h.auditLog, AuditEvent{
			Timestamp: now,
			Type:      "reload",
			Severity:  "CRITICAL",
			Message:   "Circuit breaker tripped — suppressing reloads for 10 minutes",
		})
		log.Printf("[heal] CIRCUIT BREAKER TRIPPED after %d consecutive failures", h.cbFailures)
	}

	if h.auditStore != nil {
		if err := h.auditStore.Log(audit.Entry{
			Category: audit.CatIntegrity,
			Severity: "CRITICAL",
			Message:  msg,
			Source:   "selfheal",
			Details: map[string]interface{}{
				"consecutive_failures": h.cbFailures,
				"circuit_breaker_open": !h.cbTrippedAt.IsZero(),
			},
		}); err != nil {
			log.Printf("[heal] audit log failed: %v", err)
		}
	}
}

// resetCircuitBreaker clears the circuit breaker after a successful reload.
func (h *Healer) resetCircuitBreaker() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cbFailures = 0
	h.cbTrippedAt = time.Time{}
	h.cbFirstFailAt = time.Time{}
	h.healthy = true
	log.Printf("[heal] circuit breaker reset — reloads re-enabled")
}
