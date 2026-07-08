// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package deception

import (
	"fmt"
	"log"
	"strconv"
	"time"
)

// ═══════════════════════════════════════════════════════════════════
// Provenance graph integration — attaches honeytoken/freeze metadata
// to provenance graph nodes.
// ═══════════════════════════════════════════════════════════════════

// DeceptionIntegrator orchestrates the full deception lifecycle
// by wiring together the overlay manager, freezer, and provenance
// graph updates.
type DeceptionIntegrator struct {
	cfg     *Config
	manager *OverlayManager
	freezer *Freezer
	graph   GraphUpdater
	events  chan HoneypotTrigger
	stopCh  chan struct{}
}

// GraphUpdater is called to update provenance node attributes.
type GraphUpdater func(nodeID string, attrs map[string]string)

// NewDeceptionIntegrator creates the full deception system.
func NewDeceptionIntegrator(cfg *Config) *DeceptionIntegrator {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	di := &DeceptionIntegrator{
		cfg:    cfg,
		events: make(chan HoneypotTrigger, 256),
		stopCh: make(chan struct{}),
	}

	di.manager = NewOverlayManager(cfg)
	di.freezer = NewFreezer(cfg)
	di.graph = cfg.GraphUpdater

	return di
}

// Start initializes the deception system:
//  1. Clean stale cgroups
//  2. Mount overlayfs with honeytoken files
//  3. Start the event loop
func (di *DeceptionIntegrator) Start() error {
	log.Println("[deception] starting deception integrator")

	// Clean stale cgroups from previous runs.
	if err := CleanupStaleCgroups(di.cfg); err != nil {
		log.Printf("[deception] stale cgroup cleanup: %v", err)
	}

	// Mount overlayfs with honeytoken files.
	if err := di.manager.Start(); err != nil {
		return fmt.Errorf("overlay start: %w", err)
	}

	// Start goroutine to process honeytoken triggers.
	go di.eventLoop()

	log.Printf("[deception] active with %d honeytoken files across %d mounts",
		len(di.cfg.Honeytokens), len(di.manager.Mounts()))
	return nil
}

// Stop shuts down the deception system.
func (di *DeceptionIntegrator) Stop() error {
	log.Println("[deception] stopping deception integrator")
	close(di.stopCh)

	// Unmount overlays.
	if err := di.manager.Stop(); err != nil {
		log.Printf("[deception] overlay stop: %v", err)
	}

	return nil
}

// Manager returns the overlay manager.
func (di *DeceptionIntegrator) Manager() *OverlayManager {
	return di.manager
}

// Freezer returns the process freezer.
func (di *DeceptionIntegrator) Freezer() *Freezer {
	return di.freezer
}

// ── Event loop ───────────────────────────────────────────────────

func (di *DeceptionIntegrator) eventLoop() {
	for {
		select {
		case trigger := <-di.manager.TriggerCh():
			di.handleTrigger(trigger)
		case <-di.stopCh:
			return
		}
	}
}

func (di *DeceptionIntegrator) handleTrigger(t HoneypotTrigger) {
	log.Printf("[deception] processing trigger: pid=%d path=%s type=%s",
		t.PID, t.Path, t.Trigger)

	// 1. Freeze the process.
	record, err := di.freezer.Freeze(&t)
	if err != nil {
		log.Printf("[deception] freeze failed: %v", err)
		return
	}

	// 2. Update provenance graph node.
	if di.graph != nil {
		nodeID := fmt.Sprintf("p:%d", t.PID)
		di.graph(nodeID, NodeAttrsForTrigger(&t, record))
	}

	log.Printf("[deception] process %d (%s) frozen — context captured: cmdline=%q fds=%d maps=%d",
		record.PID, record.Comm, record.Context.Cmdline,
		len(record.Context.OpenFDs), len(record.Context.MmapRegions))
}

// ── Node attribute generation ────────────────────────────────────

// NodeAttrsForTrigger returns provenance node attributes for
// a honeytoken trigger event.
func NodeAttrsForTrigger(t *HoneypotTrigger, r *FreezeRecord) map[string]string {
	attrs := make(map[string]string)

	// Confirmed malicious — this is the highest severity signal.
	attrs["confirmed_malicious"] = "true"
	attrs["honeypot_triggered"] = "true"

	// Trigger details.
	attrs["honeypot_path"] = t.Path
	attrs["honeypot_type"] = string(t.TokenType)
	attrs["honeypot_trigger_type"] = string(t.Trigger)
	attrs["honeypot_tripwire"] = strconv.FormatBool(t.Tripwire)
	attrs["honeypot_timestamp"] = t.Timestamp.Format(time.RFC3339)

	// Freeze details.
	if r != nil {
		attrs["frozen"] = "true"
		attrs["frozen_cgroup"] = r.CGroupsPath
		attrs["frozen_state"] = string(r.State)
		attrs["frozen_at"] = r.FrozenAt.Format(time.RFC3339)

		// Process context summary.
		ctx := r.Context
		if ctx.Cmdline != "" {
			attrs["captured_cmdline"] = ctx.Cmdline
		}
		attrs["captured_fd_count"] = strconv.Itoa(len(ctx.OpenFDs))
		attrs["captured_maps_count"] = strconv.Itoa(len(ctx.MmapRegions))
		attrs["captured_env_count"] = strconv.Itoa(len(ctx.EnvVars))
		if len(ctx.EnvVars) > 0 {
			// Include a few key env vars for context.
			for _, key := range []string{"PATH", "HOME", "USER", "PWD", "LD_PRELOAD"} {
				if val, ok := ctx.EnvVars[key]; ok {
					attrs["env_"+key] = val
				}
			}
		}
	}

	return attrs
}

// ── Standalone helper ────────────────────────────────────────────

// AttrsForTrigger is a convenience function that generates node attrs
// without requiring a full FreezeRecord.
func AttrsForTrigger(t *HoneypotTrigger) map[string]string {
	return NodeAttrsForTrigger(t, &FreezeRecord{
		PID:         int(t.PID),
		Comm:        t.Comm,
		Trigger:     *t,
		State:       FreezePending,
		CGroupsPath: "",
		FrozenAt:    time.Now(),
	})
}
