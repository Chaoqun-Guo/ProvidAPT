// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package cli — container-aware provenance tracing for v2.1.
//
// Features:
//   provid-cli trace --container web_server
//   provid-cli trace --pid 1234 --container
//   provid-cli trace --image nginx:latest
package trace

import (
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════
// TraceRequest
// ═══════════════════════════════════════════════════════════════

// TraceRequest describes a provenance trace query.
type TraceRequest struct {
	// PID to trace (optional)
	PID int

	// Container name/ID filter (optional)
	Container string

	// Container image filter (optional)
	Image string

	// Orchestrator filter (optional)
	Orchestrator string

	// Max trace depth
	Depth int

	// Output format: "text", "json", "dot"
	Format string
}

// DefaultTraceRequest returns defaults.
func DefaultTraceRequest() *TraceRequest {
	return &TraceRequest{
		Depth:  10,
		Format: "text",
	}
}

// ═══════════════════════════════════════════════════════════════
// TraceResult
// ═══════════════════════════════════════════════════════════════

// TraceNode is a single step in the trace chain with container context.
type TraceNode struct {
	PID           uint32 `json:"pid"`
	Comm          string `json:"comm"`
	ContainerID   string `json:"container_id,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
	PodName       string `json:"pod_name,omitempty"`
	Action        string `json:"action"`
	Target        string `json:"target"`
	Depth         int    `json:"depth"`
}

// TraceResult is the complete trace output.
type TraceResult struct {
	Request TraceRequest `json:"request"`
	Chain   []TraceNode  `json:"chain"`
	Total   int          `json:"total"`
}

// ─── Container filter logic ─────────────────────────────────

// MatchContainer checks if a container matches the trace filter.
func (req *TraceRequest) MatchContainer(containerID, containerName, image, orchestrator string) bool {
	if req.Container != "" {
		if !strings.Contains(strings.ToLower(containerName), strings.ToLower(req.Container)) &&
			!strings.Contains(strings.ToLower(containerID), strings.ToLower(req.Container)) {
			return false
		}
	}
	if req.Image != "" {
		if !strings.Contains(strings.ToLower(image), strings.ToLower(req.Image)) {
			return false
		}
	}
	if req.Orchestrator != "" {
		if !strings.EqualFold(orchestrator, req.Orchestrator) {
			return false
		}
	}
	return true
}

// ─── Chain formatting ───────────────────────────────────────

// FormatText returns a human-readable trace chain.
func (tr *TraceResult) FormatText() string {
	var b strings.Builder
	if tr.Request.Container != "" {
		b.WriteString(fmt.Sprintf("Container filter: %s\n", tr.Request.Container))
	}
	if tr.Request.Image != "" {
		b.WriteString(fmt.Sprintf("Image filter: %s\n", tr.Request.Image))
	}
	b.WriteString(fmt.Sprintf("Trace chain (%d nodes):\n", tr.Total))

	for i, node := range tr.Chain {
		prefix := "  "
		for j := 0; j < node.Depth; j++ {
			prefix += "  "
		}
		marker := "├─"
		if i == 0 {
			marker = "●"
		}
		line := fmt.Sprintf("%s%s [%s] %s", prefix, marker, node.Action, node.Comm)
		if node.Target != "" {
			line += fmt.Sprintf(" → %s", node.Target)
		}
		if node.ContainerName != "" {
			line += fmt.Sprintf(" (container: %s)", node.ContainerName)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// BuildTraceFromEvents builds a trace result from a simulated event chain.
// In production, this queries the RocksDB store.
func BuildTraceFromEvents(events []TraceNode, req TraceRequest) *TraceResult {
	// Filter by container if specified
	var filtered []TraceNode
	for _, evt := range events {
		if req.Container != "" {
			if !strings.Contains(strings.ToLower(evt.ContainerName), strings.ToLower(req.Container)) {
				continue
			}
		}
		filtered = append(filtered, evt)
	}

	return &TraceResult{
		Request: req,
		Chain:   filtered,
		Total:   len(filtered),
	}
}
