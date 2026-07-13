// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package memforensic

import (
	"fmt"
	"time"
)

// Trigger condition evaluator
//
// Evaluates whether a provenance graph node (process) meets the
// criteria for on-demand memory acquisition.
//
// Primary triggers:
// 1. MPROTECT RW X -tainted process performed mprotect to make
//      memory writable+executable (classic shellcode injection).
// 2. shellcode attr -the provenance graph already flagged this
//      process with the "shellcode" attribute (set by the eBPF
// memory probe on detecting mprotect RW X).
// 3. fileless attr -process was started from memfd_create
//      or an anonymous file (no disk backing).
// 4. deep taint -highly tainted process (depth >= 3) that
//      also has network activity or file operations.
// 5. supply chain risk -previously flagged high-risk binary.
// 6. manual -explicit request by operator.

// TriggerConfig controls which triggers are active and their thresholds.
type TriggerConfig struct {
	// EnableMprotectRX triggers on mprotect RW X events (default true).
	EnableMprotectRX bool

	// EnableShellcodeAttr triggers when process has "shellcode" node attr.
	EnableShellcodeAttr bool

	// EnableFileless triggers when process has "fileless" node attr.
	EnableFileless bool

	// EnableDeepTaint triggers on deeply tainted processes.
	EnableDeepTaint bool

	// DeepTaintMinDepth minimum taint depth for trigger (default 3).
	DeepTaintMinDepth int

	// EnableSupplyChain triggers when supply_chain_risk >= this level.
	EnableSupplyChain bool

	// SupplyChainMinLevel triggers at "high" or higher.
	SupplyChainMinLevel string
}

// DefaultTriggerConfig returns sensible defaults.
func DefaultTriggerConfig() *TriggerConfig {
	return &TriggerConfig{
		EnableMprotectRX:    true,
		EnableShellcodeAttr: true,
		EnableFileless:      true,
		EnableDeepTaint:     true,
		DeepTaintMinDepth:   3,
		EnableSupplyChain:   true,
		SupplyChainMinLevel: "high",
	}
}

// TriggerEvaluator checks process attributes against trigger conditions.
type TriggerEvaluator struct {
	cfg *TriggerConfig
}

// NewTriggerEvaluator creates a trigger evaluator.
func NewTriggerEvaluator(cfg *TriggerConfig) *TriggerEvaluator {
	if cfg == nil {
		cfg = DefaultTriggerConfig()
	}
	return &TriggerEvaluator{cfg: cfg}
}

// TriggerConfig returns the evaluator's configuration.
func (te *TriggerEvaluator) TriggerConfig() *TriggerConfig {
	return te.cfg
}

// Evaluate checks a process node's attributes against all active triggers.
// Returns a TriggerEvent (with reason) if a condition is met, or nil.
//
// nodeAttrs is the provenance graph node's Attributes map.
// Additional context (taintDepth, etc.) is passed explicitly since the
// evaluator does not have direct access to the v1 TaintEngine.
func (te *TriggerEvaluator) Evaluate(
	pid int,
	comm string,
	nodeAttrs map[string]interface{},
	nodeID string,
	hostID string,
	taintDepth int,
) *TriggerEvent {

	if pid <= 0 {
		return nil
	}
	if nodeAttrs == nil {
		nodeAttrs = make(map[string]interface{})
	}

	// 1. Mprotect RW X trigger
	if te.cfg.EnableMprotectRX {
		if isTruthyValue(nodeAttrs["shellcode"]) {
			return &TriggerEvent{
				PID:       pid,
				Comm:      comm,
				Reason:    TrigMprotectRX,
				Detail:    fmt.Sprintf("process %s (PID %d) executed mprotect RW->RX (possible shellcode injection)", comm, pid),
				NodeAttrs: nodeAttrs,
				NodeID:    nodeID,
				HostID:    hostID,
				Timestamp: time.Now(),
			}
		}
		if s, isStr := nodeAttrs["memory_op"].(string); isStr && s == "mprotect_rx" {
			return &TriggerEvent{
				PID:       pid,
				Comm:      comm,
				Reason:    TrigMprotectRX,
				Detail:    fmt.Sprintf("process %s (PID %d) executed mprotect RW->RX (possible shellcode injection)", comm, pid),
				NodeAttrs: nodeAttrs,
				NodeID:    nodeID,
				HostID:    hostID,
				Timestamp: time.Now(),
			}
		}
	}

	// 2. Shellcode attribute trigger
	if te.cfg.EnableShellcodeAttr {
		if isTruthyValue(nodeAttrs["shellcode"]) {
			return &TriggerEvent{
				PID:       pid,
				Comm:      comm,
				Reason:    TrigShellcodeAttr,
				Detail:    fmt.Sprintf("process %s (PID %d) is marked as containing shellcode", comm, pid),
				NodeAttrs: nodeAttrs,
				NodeID:    nodeID,
				HostID:    hostID,
				Timestamp: time.Now(),
			}
		}
	}

	// 3. Fileless execution trigger
	if te.cfg.EnableFileless {
		if isTruthyValue(nodeAttrs["fileless"]) {
			return &TriggerEvent{
				PID:       pid,
				Comm:      comm,
				Reason:    TrigFilelessExec,
				Detail:    fmt.Sprintf("process %s (PID %d) performed fileless execution via memfd_create", comm, pid),
				NodeAttrs: nodeAttrs,
				NodeID:    nodeID,
				HostID:    hostID,
				Timestamp: time.Now(),
			}
		}
	}

	// 4. Deep taint trigger
	if te.cfg.EnableDeepTaint && taintDepth >= te.cfg.DeepTaintMinDepth {
		hasNet := false
		hasFile := false
		for k, v := range nodeAttrs {
			if k == "network" || k == "dport" {
				hasNet = true
			}
			if k == "file_write" || k == "file_read" {
				if b, isBool := v.(bool); isBool && b {
					hasFile = true
				}
			}
		}
		if hasNet || hasFile {
			return &TriggerEvent{
				PID:       pid,
				Comm:      comm,
				Reason:    TrigDeepTainted,
				Detail:    fmt.Sprintf("process %s (PID %d) is deeply tainted (depth=%d) and has network/file activity", comm, pid, taintDepth),
				NodeAttrs: nodeAttrs,
				NodeID:    nodeID,
				HostID:    hostID,
				Timestamp: time.Now(),
			}
		}
	}

	// 5. Supply chain risk trigger
	if te.cfg.EnableSupplyChain {
		if v, ok := nodeAttrs["supply_chain_risk"]; ok {
			if s, isStr := v.(string); isStr {
				if isHighOrCritical(s) {
					return &TriggerEvent{
						PID:       pid,
						Comm:      comm,
						Reason:    TrigSupplyChainRisk,
						Detail:    fmt.Sprintf("process %s (PID %d) has supply-chain risk level %s", comm, pid, s),
						NodeAttrs: nodeAttrs,
						NodeID:    nodeID,
						HostID:    hostID,
						Timestamp: time.Now(),
					}
				}
			}
		}
	}

	return nil
}

// EvaluateNodeAttrMap is a convenience overload that accepts map[string]string
// (common in GlobalNode.Props format).
func (te *TriggerEvaluator) EvaluateStringMap(
	pid int,
	comm string,
	attrs map[string]string,
	nodeID string,
	hostID string,
	taintDepth int,
) *TriggerEvent {
	// Convert to map[string]interface{}.
	iface := make(map[string]interface{}, len(attrs))
	for k, v := range attrs {
		iface[k] = v
	}
	return te.Evaluate(pid, comm, iface, nodeID, hostID, taintDepth)
}

// Manual trigger

// ManualTrigger creates a trigger event from an explicit operator request.
func ManualTrigger(pid int, comm string, reason string) *TriggerEvent {
	return &TriggerEvent{
		PID:       pid,
		Comm:      comm,
		Reason:    TrigManual,
		Detail:    reason,
		Timestamp: time.Now(),
	}
}

// Helpers

// isTruthyValue checks if an interface value represents boolean true,
// supporting both bool and string representations ("true", "1").
func isTruthyValue(v interface{}) bool {
	if b, isBool := v.(bool); isBool && b {
		return true
	}
	if s, isStr := v.(string); isStr && (s == "true" || s == "1") {
		return true
	}
	return false
}

func isHighOrCritical(level string) bool {
	switch level {
	case "high", "critical":
		return true
	}
	return false
}

// ValidateConfig checks trigger config for inconsistencies.
func ValidateConfig(cfg *TriggerConfig) error {
	if cfg == nil {
		return fmt.Errorf("trigger config is nil")
	}
	if cfg.DeepTaintMinDepth < 1 {
		return fmt.Errorf("DeepTaintMinDepth must be >= 1, got %d", cfg.DeepTaintMinDepth)
	}
	switch cfg.SupplyChainMinLevel {
	case "low", "medium", "high", "critical":
		// valid
	default:
		return fmt.Errorf("invalid SupplyChainMinLevel: %s", cfg.SupplyChainMinLevel)
	}
	return nil
}
