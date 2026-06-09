// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package memforensic

import (
	"fmt"
	"log"
)

// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
// Provenance graph integration
//
// Updates provenance graph nodes with memory forensic findings.
// Supports both:
//   - v1 Node (map[string]interface{} Attributes)
//   - GlobalNode (map[string]interface{} Props)
// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

// GraphNode is a minimal interface for updating provenance node attributes.
// Both *provenance.Node and *store.GlobalNode satisfy this.
type GraphNode interface {
	// Attrs returns the mutable attribute map of the node.
	Attrs() map[string]interface{}
}

// 鈹€鈹€ Adapter types for graph integration 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

// NodeAttrsAdapter wraps a map for use as GraphNode.
type NodeAttrsAdapter struct {
	attrs map[string]interface{}
}

// Attrs returns the underlying attribute map.
func (a *NodeAttrsAdapter) Attrs() map[string]interface{} {
	return a.attrs
}

// NewNodeAttrsAdapter creates an adapter from an existing attr map.
func NewNodeAttrsAdapter(attrs map[string]interface{}) *NodeAttrsAdapter {
	return &NodeAttrsAdapter{attrs: attrs}
}

// 鈹€鈹€ Integration functions 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

// ApplyToNode writes the forensic result attributes to a provenance
// graph node's attribute map.
//
// The following attributes are set:
//
//	mem_forensic        鈥-"scanned" (marker)
//	mem_trigger          鈥-trigger reason string
//	mem_risk_score      鈥-numeric score (0-100)
//	mem_risk_level      鈥-"low"/"medium"/"high"/"critical"
//	mem_stack_hash      鈥-SHA256 of stack dump
//	mem_exec_hash       鈥-SHA256 of executable segments
//	mem_heap_hash       鈥-SHA256 of heap dump
//	mem_match_count     鈥-total YARA+hex matches
//	mem_top_match       鈥-highest severity match name
//	mem_matches         鈥-comma-separated list of matched rules
//	mem_regions         鈥-total parsed memory regions
//	mem_anon_exec       鈥-count of anonymous executable regions
//	mem_wx_regions      鈥-true if any W+X region found
//
// Returns the number of attributes set.
func ApplyToNode(node GraphNode, result *MemForensicResult) int {
	if node == nil || result == nil {
		return 0
	}

	attrs := node.Attrs()
	if attrs == nil {
		return 0
	}

	count := 0

	// Always set the forensic marker.
	if _, exists := attrs["mem_forensic"]; !exists {
		attrs["mem_forensic"] = "scanned"
		count++
	}

	setStr := func(key, val string) {
		if val != "" {
			if old, ok := attrs[key].(string); ok && old == val {
				return // already set
			}
			attrs[key] = val
			count++
		}
	}

	setInt := func(key string, val int) {
		if old, ok := attrs[key].(int); ok && old == val {
			return
		}
		attrs[key] = val
		count++
	}

	// Trigger info.
	setStr("mem_trigger", string(result.Trigger))

	// Scan results.
	if result.Scan != nil {
		setStr("mem_risk_score", fmt.Sprintf("%.0f", result.Scan.RiskScore))
		setStr("mem_risk_level", result.Scan.RiskLevel)
		setStr("mem_stack_hash", result.Scan.StackHash)
		setStr("mem_exec_hash", result.Scan.ExecHash)
		setStr("mem_heap_hash", result.Scan.HeapHash)
		setInt("mem_match_count", len(result.Scan.Matches))

		if len(result.Scan.Matches) > 0 {
			setStr("mem_top_match", result.Scan.Matches[0].Rule+"/"+string(result.Scan.Matches[0].Severity))

			// Build comma-separated match list (max 5 to avoid bloat).
			rules := make([]string, 0, len(result.Scan.Matches))
			for _, m := range result.Scan.Matches {
				if len(rules) >= 5 {
					rules = append(rules, "...")
					break
				}
				rules = append(rules, m.Rule)
			}
			setStr("mem_matches", joinStrings(rules, ", "))
		}
	}

	// Dump metadata.
	if result.Dump != nil {
		setInt("mem_regions", result.Dump.SegmentCount())

		anonExec := len(AnonExecRegions(result.Dump.Regions))
		setInt("mem_anon_exec", anonExec)

		hasWX := HasWXPerms(result.Dump.Regions)
		if hasWX {
			setStr("mem_wx_regions", "true")
		}
	}

	return count
}

// ApplyToStringAttrs writes forensic results to a map[string]string
// (the format used in v2 protobuf Node.attrs and GlobalNode.Props).
func ApplyToStringAttrs(attrs map[string]string, result *MemForensicResult) int {
	if attrs == nil || result == nil {
		return 0
	}

	count := 0
	set := func(k, v string) {
		if v != "" {
			if existing, ok := attrs[k]; ok && existing == v {
				return
			}
			attrs[k] = v
			count++
		}
	}

	set("mem_forensic", "scanned")
	set("mem_trigger", string(result.Trigger))

	if result.Scan != nil {
		set("mem_risk_score", fmt.Sprintf("%.0f", result.Scan.RiskScore))
		set("mem_risk_level", result.Scan.RiskLevel)
		set("mem_stack_hash", result.Scan.StackHash)
		set("mem_exec_hash", result.Scan.ExecHash)
		set("mem_heap_hash", result.Scan.HeapHash)
		set("mem_match_count", fmtInt(len(result.Scan.Matches)))

		if len(result.Scan.Matches) > 0 {
			set("mem_top_match", result.Scan.Matches[0].Rule+"/"+string(result.Scan.Matches[0].Severity))

			rules := make([]string, 0, len(result.Scan.Matches))
			for _, m := range result.Scan.Matches {
				if len(rules) >= 5 {
					rules = append(rules, "...")
					break
				}
				rules = append(rules, m.Rule)
			}
			set("mem_matches", joinStrings(rules, ", "))
		}
	}

	if result.Dump != nil {
		set("mem_regions", fmtInt(result.Dump.SegmentCount()))
		anonExec := len(AnonExecRegions(result.Dump.Regions))
		set("mem_anon_exec", fmtInt(anonExec))
		if HasWXPerms(result.Dump.Regions) {
			set("mem_wx_regions", "true")
		}
	}

	return count
}

// 鈹€鈹€ High-level orchestration 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

// AcquireAndScan runs the full acquisition鈫抯can鈫抮esult pipeline.
// It is the main entry point for forensic operations.
//
// Parameters:
//   - pid: target process ID
//   - trigger: the reason for acquisition
//   - nodeID: provenance graph node ID
//   - hostID: host identifier
//
// Returns a complete MemForensicResult.
func AcquireAndScan(
	pid int,
	trigger TriggerReason,
	nodeID string,
	hostID string,
	scanner *MemoryScanner,
) *MemForensicResult {

	result := &MemForensicResult{
		Trigger: trigger,
		NodeID:  nodeID,
		HostID:  hostID,
	}

	dump, err := Acquire(pid)
	if err != nil {
		log.Printf("[memforensic] acquire failed for PID %d: %v", pid, err)
		result.Dump = dump // partial dump may still be available
	} else {
		result.Dump = dump
	}

	if dump != nil && scanner != nil {
		scanResult := scanner.Scan(dump)
		result.Scan = scanResult
	}

	return result
}

// 鈹€鈹€ Orchestration hook for the analyzer 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

// HandleTrigger is called when a trigger event fires. It performs the
// acquisition and scan, then returns attributes ready for graph update.
//
// Returns the graph attributes to set, or nil if acquisition failed
// entirely (no data at all).
func HandleTrigger(
	event *TriggerEvent,
	scanner *MemoryScanner,
) (*MemForensicResult, map[string]string) {
	if event == nil {
		return nil, nil
	}

	result := AcquireAndScan(event.PID, event.Reason, event.NodeID, event.HostID, scanner)
	if result == nil {
		return nil, nil
	}

	// If no data was acquired AND no scan was done, nothing to attach.
	if (result.Dump == nil || !result.Dump.HasData()) && result.Scan == nil {
		return result, nil
	}

	// Convert forensic result to string-keyed attribute map for graph nodes.
	attrsMap := make(map[string]string)
	ApplyToStringAttrs(attrsMap, result)

	return result, attrsMap
}
