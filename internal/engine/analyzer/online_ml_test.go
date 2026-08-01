// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

func TestOnlineMLScorerEmitsGraphAnomaly(t *testing.T) {
	dir := t.TempDir()
	registry := `{"models":[{"model_name":"graph-detector","model_version":"test-gat"}]}`
	if err := os.WriteFile(filepath.Join(dir, "model-registry.json"), []byte(registry), 0644); err != nil {
		t.Fatal(err)
	}
	scorer, err := NewOnlineMLScorer(OnlineMLConfig{ModelDir: dir, Threshold: 0.40, MinNodes: 3, MinEdges: 2})
	if err != nil {
		t.Fatalf("NewOnlineMLScorer: %v", err)
	}
	snap := &Snapshot{
		Nodes: []*provenance.Node{
			{ID: "p:1", ProvType: provenance.ProvActivity, Subtype: "process", Label: "sshd", Attributes: map[string]interface{}{}},
			{ID: "p:2", ProvType: provenance.ProvActivity, Subtype: "process", Label: "bash", Attributes: map[string]interface{}{}},
			{ID: "f:1#v1", ProvType: provenance.ProvEntity, Subtype: "file", Label: "/etc/shadow", Attributes: map[string]interface{}{}},
			{ID: "n:1", ProvType: provenance.ProvEntity, Subtype: "network", Label: "127.0.0.1:1", Attributes: map[string]interface{}{}},
		},
		Edges: []*provenance.Edge{
			{ID: "e1", Source: "p:2", Target: "p:1", Relation: provenance.ProvWasInformedBy, Count: 1, Timestamp: time.Now()},
			{ID: "e2", Source: "p:2", Target: "f:1#v1", Relation: provenance.ProvUsed, Count: 2, Timestamp: time.Now()},
			{ID: "e3", Source: "p:2", Target: "n:1", Relation: provenance.ProvUsed, Count: 1, Timestamp: time.Now()},
		},
	}
	alert := scorer.Score(snap, nil)
	if alert == nil {
		t.Fatal("expected ML alert")
	}
	if alert.Pattern != PatMLGraphAnomaly {
		t.Fatalf("pattern = %s", alert.Pattern)
	}
	if alert.AlertNodeID == "" || alert.Reason == "" {
		t.Fatalf("incomplete alert: %+v", alert)
	}
	if alert.Metadata["model_version"] != "test-gat" || alert.Metadata["model_name"] != "graph-detector" {
		t.Fatalf("missing ML metadata: %+v", alert.Metadata)
	}
	gateMetadata, ok := alert.Metadata["deploy_gate"].(map[string]interface{})
	if !ok || gateMetadata["status"] != "" {
		t.Fatalf("unexpected deploy gate metadata: %+v", alert.Metadata["deploy_gate"])
	}
	var buf bytes.Buffer
	if err := SerializeAlertJSON(&buf, []*Alert{alert}); err != nil {
		t.Fatalf("SerializeAlertJSON: %v", err)
	}
	var serialized []map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &serialized); err != nil {
		t.Fatalf("decode alert JSON: %v", err)
	}
	metadata, ok := serialized[0]["metadata"].(map[string]interface{})
	if !ok || metadata["model_version"] != "test-gat" {
		t.Fatalf("serialized metadata = %#v", serialized[0]["metadata"])
	}
}

func TestOnlineMLScorerRequiresDeployGate(t *testing.T) {
	_, err := NewOnlineMLScorer(OnlineMLConfig{ModelDir: t.TempDir(), RequireDeployGate: true})
	if err == nil {
		t.Fatal("expected missing deploy gate to block scorer")
	}
}

func TestOnlineMLScorerLoadsPassingDeployGate(t *testing.T) {
	dir := t.TempDir()
	registry := `{"models":[{"model_name":"graph-detector","model_version":"approved"}]}`
	if err := os.WriteFile(filepath.Join(dir, "model-registry.json"), []byte(registry), 0644); err != nil {
		t.Fatal(err)
	}
	gate := `{"schema":"providapt.model_deploy_gate.v1","status":"pass","model_name":"graph-detector","model_version":"approved"}`
	gatePath := filepath.Join(dir, "model-deploy-gate.json")
	if err := os.WriteFile(gatePath, []byte(gate), 0644); err != nil {
		t.Fatal(err)
	}
	scorer, err := NewOnlineMLScorer(OnlineMLConfig{ModelDir: dir, RequireDeployGate: true})
	if err != nil {
		t.Fatalf("NewOnlineMLScorer: %v", err)
	}
	if scorer.DeployGatePath() != gatePath || scorer.DeployGateStatus() != "pass" {
		t.Fatalf("deploy gate evidence not loaded: path=%q status=%q", scorer.DeployGatePath(), scorer.DeployGateStatus())
	}
}

func TestOnlineMLScorerHonorsThreshold(t *testing.T) {
	scorer, err := NewOnlineMLScorer(OnlineMLConfig{ModelDir: t.TempDir(), Threshold: 0.99, MinNodes: 3, MinEdges: 2})
	if err != nil {
		t.Fatalf("NewOnlineMLScorer: %v", err)
	}
	snap := &Snapshot{
		Nodes: []*provenance.Node{
			{ID: "p:1", ProvType: provenance.ProvActivity, Subtype: "process", Label: "date", Attributes: map[string]interface{}{}},
			{ID: "f:1", ProvType: provenance.ProvEntity, Subtype: "file", Label: "/tmp/out", Attributes: map[string]interface{}{}},
			{ID: "f:2", ProvType: provenance.ProvEntity, Subtype: "file", Label: "/tmp/in", Attributes: map[string]interface{}{}},
		},
		Edges: []*provenance.Edge{
			{ID: "e1", Source: "p:1", Target: "f:1", Relation: provenance.ProvUsed, Count: 1, Timestamp: time.Now()},
			{ID: "e2", Source: "f:2", Target: "p:1", Relation: provenance.ProvWasGeneratedBy, Count: 1, Timestamp: time.Now()},
		},
	}
	if alert := scorer.Score(snap, nil); alert != nil {
		t.Fatalf("unexpected alert: %+v", alert)
	}
}
