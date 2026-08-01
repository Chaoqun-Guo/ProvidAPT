// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

type OnlineMLConfig struct {
	ModelDir          string
	DeployGatePath    string
	RequireDeployGate bool
	Threshold         float64
	MinNodes          int
	MinEdges          int
}

type OnlineMLScorer struct {
	modelName        string
	modelVersion     string
	modelDir         string
	deployGatePath   string
	deployGateStatus string
	threshold        float64
	minNodes         int
	minEdges         int
}

type onlineModelRegistry struct {
	Models []struct {
		ModelName    string `json:"model_name"`
		ModelVersion string `json:"model_version"`
	} `json:"models"`
}

type onlineModelDeployGate struct {
	Schema       string `json:"schema"`
	Status       string `json:"status"`
	ModelName    string `json:"model_name"`
	ModelVersion string `json:"model_version"`
}

func NewOnlineMLScorer(cfg OnlineMLConfig) (*OnlineMLScorer, error) {
	modelDir := strings.TrimSpace(cfg.ModelDir)
	if modelDir == "" {
		modelDir = "/var/lib/providapt/models/current"
	}
	info, err := os.Stat(modelDir)
	if err != nil {
		return nil, fmt.Errorf("stat model dir %s: %w", modelDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("model dir is not a directory: %s", modelDir)
	}
	threshold := cfg.Threshold
	if threshold <= 0 || threshold > 1 {
		threshold = 0.85
	}
	minNodes := cfg.MinNodes
	if minNodes < 1 {
		minNodes = 3
	}
	minEdges := cfg.MinEdges
	if minEdges < 1 {
		minEdges = 2
	}
	scorer := &OnlineMLScorer{
		modelName:    "graph-detector",
		modelVersion: filepath.Base(modelDir),
		modelDir:     modelDir,
		threshold:    threshold,
		minNodes:     minNodes,
		minEdges:     minEdges,
	}
	scorer.loadRegistryMetadata()
	if err := scorer.loadDeployGate(cfg); err != nil {
		return nil, err
	}
	return scorer, nil
}

func (s *OnlineMLScorer) ModelName() string {
	return s.modelName
}

func (s *OnlineMLScorer) ModelVersion() string {
	return s.modelVersion
}

func (s *OnlineMLScorer) Threshold() float64 {
	return s.threshold
}

func (s *OnlineMLScorer) DeployGatePath() string {
	return s.deployGatePath
}

func (s *OnlineMLScorer) DeployGateStatus() string {
	return s.deployGateStatus
}

func (s *OnlineMLScorer) loadRegistryMetadata() {
	data, err := os.ReadFile(filepath.Join(s.modelDir, "model-registry.json"))
	if err != nil {
		return
	}
	var registry onlineModelRegistry
	if json.Unmarshal(data, &registry) != nil || len(registry.Models) == 0 {
		return
	}
	latest := registry.Models[len(registry.Models)-1]
	if latest.ModelName != "" {
		s.modelName = latest.ModelName
	}
	if latest.ModelVersion != "" {
		s.modelVersion = latest.ModelVersion
	}
}

func (s *OnlineMLScorer) loadDeployGate(cfg OnlineMLConfig) error {
	gatePath := strings.TrimSpace(cfg.DeployGatePath)
	if gatePath == "" {
		gatePath = filepath.Join(s.modelDir, "model-deploy-gate.json")
	}
	data, err := os.ReadFile(gatePath)
	if err != nil {
		if cfg.RequireDeployGate {
			return fmt.Errorf("read model deploy gate %s: %w", gatePath, err)
		}
		return nil
	}
	var gate onlineModelDeployGate
	if err := json.Unmarshal(data, &gate); err != nil {
		return fmt.Errorf("parse model deploy gate %s: %w", gatePath, err)
	}
	if gate.Schema != "providapt.model_deploy_gate.v1" {
		return fmt.Errorf("model deploy gate %s has unsupported schema %q", gatePath, gate.Schema)
	}
	status := strings.ToLower(strings.TrimSpace(gate.Status))
	if status != "pass" {
		return fmt.Errorf("model deploy gate %s status is %q", gatePath, gate.Status)
	}
	if gate.ModelName != "" && gate.ModelName != s.modelName {
		return fmt.Errorf("model deploy gate %s model_name %q does not match loaded model %q", gatePath, gate.ModelName, s.modelName)
	}
	if gate.ModelVersion != "" && gate.ModelVersion != s.modelVersion {
		return fmt.Errorf("model deploy gate %s model_version %q does not match loaded model %q", gatePath, gate.ModelVersion, s.modelVersion)
	}
	s.deployGatePath = gatePath
	s.deployGateStatus = status
	return nil
}

func (s *OnlineMLScorer) Score(snap *Snapshot, te *TaintEngine) *Alert {
	if snap == nil || len(snap.Nodes) < s.minNodes || len(snap.Edges) < s.minEdges {
		return nil
	}
	features := extractOnlineGraphFeatures(snap, te)
	score := calibratedGraphScore(features)
	if score < s.threshold {
		return nil
	}
	alertNodeID := selectMLAlertNode(snap, te)
	if alertNodeID == "" {
		return nil
	}
	return &Alert{
		Pattern:  PatMLGraphAnomaly,
		Severity: mlSeverity(score),
		Headline: fmt.Sprintf("[ML] %s:%s graph anomaly score %.3f", s.modelName, s.modelVersion, score),
		Reason: fmt.Sprintf(
			"online graph scorer exceeded threshold %.3f; score=%.3f nodes=%d edges=%d tainted=%d sensitive=%d network=%d exec=%d model_dir=%s",
			s.threshold, score, features.nodes, features.edges, features.taintedProcesses, features.sensitiveFiles, features.networkNodes, features.execEdges, s.modelDir),
		AlertNodeID: alertNodeID,
		DetectedAt:  time.Now(),
		Metadata: map[string]interface{}{
			"detector":      "online_graph_scorer",
			"model_name":    s.modelName,
			"model_version": s.modelVersion,
			"model_dir":     s.modelDir,
			"deploy_gate": map[string]interface{}{
				"path":   s.deployGatePath,
				"status": s.deployGateStatus,
			},
			"score":     score,
			"threshold": s.threshold,
			"feature_counts": map[string]interface{}{
				"nodes":             features.nodes,
				"edges":             features.edges,
				"tainted_processes": features.taintedProcesses,
				"sensitive_files":   features.sensitiveFiles,
				"network_nodes":     features.networkNodes,
				"exec_edges":        features.execEdges,
			},
		},
	}
}

type onlineGraphFeatures struct {
	nodes            int
	edges            int
	processes        int
	files            int
	networkNodes     int
	sensitiveFiles   int
	taintedProcesses int
	execEdges        int
	fileWriteEdges   int
	fileReadEdges    int
	networkEdges     int
	maxOutDegree     int
	maxInDegree      int
}

func extractOnlineGraphFeatures(snap *Snapshot, te *TaintEngine) onlineGraphFeatures {
	features := onlineGraphFeatures{nodes: len(snap.Nodes), edges: len(snap.Edges)}
	outDegree := map[string]int{}
	inDegree := map[string]int{}
	for _, node := range snap.Nodes {
		switch node.Subtype {
		case "process":
			features.processes++
			if te != nil && te.Tainted(node.ID) != nil {
				features.taintedProcesses++
			}
		case "file":
			features.files++
			if isMLSensitivePath(node.Label) {
				features.sensitiveFiles++
			}
		case "network":
			features.networkNodes++
		}
	}
	for _, edge := range snap.Edges {
		outDegree[edge.Source] += maxIntForML(edge.Count, 1)
		inDegree[edge.Target] += maxIntForML(edge.Count, 1)
		switch edge.Relation {
		case provenance.ProvWasInformedBy:
			features.execEdges++
		case provenance.ProvWasGeneratedBy:
			features.fileWriteEdges++
		case provenance.ProvUsed:
			features.fileReadEdges++
			if target := findSnapshotNode(snap, edge.Target); target != nil && target.Subtype == "network" {
				features.networkEdges++
			}
		}
	}
	for _, value := range outDegree {
		if value > features.maxOutDegree {
			features.maxOutDegree = value
		}
	}
	for _, value := range inDegree {
		if value > features.maxInDegree {
			features.maxInDegree = value
		}
	}
	return features
}

func calibratedGraphScore(features onlineGraphFeatures) float64 {
	if features.nodes == 0 {
		return 0
	}
	raw := -3.2
	raw += math.Log1p(float64(features.taintedProcesses)) * 1.25
	raw += math.Log1p(float64(features.sensitiveFiles)) * 0.9
	raw += math.Log1p(float64(features.networkNodes+features.networkEdges)) * 0.85
	raw += math.Log1p(float64(features.execEdges)) * 0.35
	raw += math.Log1p(float64(features.fileWriteEdges)) * 0.25
	raw += math.Log1p(float64(features.maxOutDegree+features.maxInDegree)) * 0.2
	if features.sensitiveFiles > 0 && (features.networkNodes > 0 || features.networkEdges > 0) {
		raw += 1.2
	}
	if features.taintedProcesses > 0 && features.fileWriteEdges > 0 {
		raw += 0.65
	}
	score := 1 / (1 + math.Exp(-raw))
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return math.Round(score*1000) / 1000
}

func selectMLAlertNode(snap *Snapshot, te *TaintEngine) string {
	if te != nil {
		bestID := ""
		bestDepth := -1
		for _, node := range snap.Nodes {
			taint := te.Tainted(node.ID)
			if taint != nil && node.Subtype == "process" && taint.Depth > bestDepth {
				bestID = node.ID
				bestDepth = taint.Depth
			}
		}
		if bestID != "" {
			return bestID
		}
	}
	for _, node := range snap.Nodes {
		if node.Subtype == "process" {
			return node.ID
		}
	}
	if len(snap.Nodes) > 0 {
		return snap.Nodes[0].ID
	}
	return ""
}

func mlSeverity(score float64) Severity {
	switch {
	case score >= 0.95:
		return SeverityHigh
	case score >= 0.90:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

func isMLSensitivePath(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" {
		return false
	}
	for _, prefix := range []string{"/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/ssh/", "/root/", "/.ssh/", "/var/log/auth.log", "/var/log/secure"} {
		if strings.HasPrefix(path, prefix) || strings.Contains(path, prefix) {
			return true
		}
	}
	return false
}

func findSnapshotNode(snap *Snapshot, id string) *provenance.Node {
	for _, node := range snap.Nodes {
		if node.ID == id {
			return node
		}
	}
	return nil
}

func maxIntForML(a, b int) int {
	if a > b {
		return a
	}
	return b
}
