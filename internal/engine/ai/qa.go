// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"log"
	"strings"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ═══════════════════════════════════════════════════════════════
// Interactive Q&A Engine
//
// Supports questions like:
//   "How did this process connect to the network?"
//   "What files did bash modify?"
//   "Who forked this process?"
//   "What is the attack path from the web server to the C2?"
// ═══════════════════════════════════════════════════════════════

// QAEngine answers questions by searching the provenance graph.
type QAEngine struct {
	graph  *provenance.Graph
	client *LLMClient
}

// NewQAEngine creates a Q&A engine.
func NewQAEngine(graph *provenance.Graph, cfg *LLMConfig) *QAEngine {
	return &QAEngine{
		graph:  graph,
		client: NewLLMClient(cfg),
	}
}

// Answer handles a natural language question about the graph.
func (qa *QAEngine) Answer(question string) (string, error) {
	question = strings.TrimSpace(question)
	if question == "" {
		return "", fmt.Errorf("empty question")
	}

	// First, extract a focused subgraph based on the question
	subgraph := qa.extractRelevantSubgraph(question)
	graphJSON, err := SerializeGraph(subgraph.nodes, subgraph.edges, nil).ToJSON()
	if err != nil {
		log.Printf("[ai] serialize subgraph: %v", err)
		graphJSON = "{}"
	}

	// Ask the LLM with the focused subgraph
	return qa.client.Ask(graphJSON, question)
}

// extractRelevantSubgraph tries to find a subgraph relevant to the question.
// If no specific entity is mentioned, returns the full graph.
func (qa *QAEngine) extractRelevantSubgraph(question string) *subgraphResult {
	q := strings.ToLower(question)

	// Try to identify a target entity from the question
	var targetIDs []string

	// Check for PID mentions
	if pid := extractPID(q); pid > 0 {
		targetIDs = append(targetIDs, fmt.Sprintf("p:%d", pid))
	}

	// Check for process name mentions
	for _, name := range commonProcessNames {
		if strings.Contains(q, name) {
			// Find the node by label
			for _, n := range qa.graph.Nodes() {
				if strings.EqualFold(n.Label, name) {
					targetIDs = append(targetIDs, n.ID)
					break
				}
			}
		}
	}

	// If no specific targets, return the whole graph
	if len(targetIDs) == 0 {
		allNodes := qa.graph.Nodes()
		allEdges := qa.graph.Edges()
		return &subgraphResult{nodes: allNodes, edges: allEdges}
	}

	// Build 1-hop neighbourhood around each target
	allEdges := qa.graph.Edges()
	nodeSet := make(map[string]bool)
	var edges []*provenance.Edge

	for _, target := range targetIDs {
		nodeSet[target] = true
		for _, e := range allEdges {
			if e.Source == target || e.Target == target {
				edges = append(edges, e)
				nodeSet[e.Source] = true
				nodeSet[e.Target] = true
			}
		}
	}

	var nodes []*provenance.Node
	for _, n := range qa.graph.Nodes() {
		if nodeSet[n.ID] {
			nodes = append(nodes, n)
		}
	}

	// If nothing found, return full graph
	if len(nodes) == 0 {
		return &subgraphResult{nodes: qa.graph.Nodes(), edges: qa.graph.Edges()}
	}

	return &subgraphResult{nodes: nodes, edges: edges}
}

type subgraphResult struct {
	nodes []*provenance.Node
	edges []*provenance.Edge
}

// extractPID tries to find a PID mentioned in the question.
func extractPID(q string) int {
	var pid int
	// Match patterns like "PID 1234" or "process 1234"
	_, err := fmt.Sscanf(q, "pid %d", &pid)
	if err == nil {
		return pid
	}
	_, err = fmt.Sscanf(q, "process %d", &pid)
	if err == nil {
		return pid
	}
	return 0
}

// commonProcessNames used for QA entity recognition.
var commonProcessNames = []string{
	"bash", "sh", "nginx", "apache2", "httpd", "sshd",
	"curl", "wget", "python", "python3", "node",
	"systemd", "cron", "sudo", "php", "java",
}

// AnswerWithoutLLM provides a built-in answer without calling an LLM.
// Useful when no LLM endpoint is available.
func (qa *QAEngine) AnswerWithoutLLM(question string) string {
	q := strings.ToLower(question)

	var lines []string

	if strings.Contains(q, "how did") && strings.Contains(q, "connect") {
		lines = append(lines, "Processes that made network connections:")
		for _, e := range qa.graph.Edges() {
			if e.Relation == "prov:used" {
				if n, ok := qa.graph.LookupNode(e.Target); ok && n != nil && n.Subtype == "network" {
					src, _ := qa.graph.LookupNode(e.Source)
					if src != nil {
						lines = append(lines, fmt.Sprintf("  %s (%s) → %s", src.Label, e.Source, n.Label))
					}
				}
			}
		}
	}

	if strings.Contains(q, "what file") && (strings.Contains(q, "modify") || strings.Contains(q, "write")) {
		lines = append(lines, "Files that were modified:")
		for _, e := range qa.graph.Edges() {
			if e.Relation == "prov:wasGeneratedBy" {
				if n, ok := qa.graph.LookupNode(e.Source); ok && n != nil {
					src, _ := qa.graph.LookupNode(e.Target)
					if src != nil {
						lines = append(lines, fmt.Sprintf("  %s (written by %s)", n.Label, src.Label))
					}
				}
			}
		}
	}

	if strings.Contains(q, "fork") || strings.Contains(q, "child") {
		lines = append(lines, "Process fork chains:")
		for _, e := range qa.graph.Edges() {
			if e.Relation == "prov:wasInformedBy" {
				child, _ := qa.graph.LookupNode(e.Source)
				parent, _ := qa.graph.LookupNode(e.Target)
				if child != nil && parent != nil {
					lines = append(lines, fmt.Sprintf("  %s (%s) ← forked from %s (%s)",
						child.Label, child.ID, parent.Label, parent.ID))
				}
			}
		}
	}

	if len(lines) == 0 {
		return fmt.Sprintf("The provenance graph contains %d nodes and %d edges. I can answer questions about processes, files, network connections, and their relationships.",
			qa.graph.Stats().Nodes, qa.graph.Stats().Edges)
	}

	return strings.Join(lines, "\n")
}
