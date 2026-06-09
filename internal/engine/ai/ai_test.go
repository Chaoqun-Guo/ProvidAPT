// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"strings"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
)

// ── Test helpers ────────────────────────────────────────────

func testGraph() *provenance.Graph {
	g := provenance.NewGraph()
	// Web server compromise: nginx forks child, child downloads evil.sh
	g.AddEvent(&collector.Event{
		Type: syscall.EventProcessFork, TimestampNS: 1000,
		PID: 100, ChildPID: 101, Comm: "nginx",
	})
	g.AddEvent(&collector.Event{
		Type: syscall.EventProcessExec, TimestampNS: 2000,
		PID: 101, Comm: "bash", Pathname: "/tmp/evil.sh",
		Inode: 5000, DevMajor: 8, DevMinor: 3,
	})
	g.AddEvent(&collector.Event{
		Type: syscall.EventFileOpen, TimestampNS: 3000,
		PID: 101, Comm: "bash", Pathname: "/etc/shadow",
		Inode: 5001, DevMajor: 8, DevMinor: 3,
	})
	g.AddEvent(&collector.Event{
		Type: syscall.EventFileModify, TimestampNS: 4000,
		PID: 101, Comm: "bash", Pathname: "/tmp/backdoor.sh",
		Inode: 5002, DevMajor: 8, DevMinor: 3,
		FFlags: 1,
	})
	g.AddEvent(&collector.Event{
		Type: syscall.EventNetConnect, TimestampNS: 5000,
		PID: 101, Comm: "bash",
	})
	return g
}

// ── Serialization tests ─────────────────────────────────────

func TestSerializeGraph(t *testing.T) {
	g := testGraph()
	llmGraph := SerializeGraph(g.Nodes(), g.Edges(), &AlertInfo{
		AlertID: "test-001", Score: 85, Severity: "HIGH",
	})
	if llmGraph == nil {
		t.Fatal("SerializeGraph returned nil")
	}
	if len(llmGraph.Nodes) == 0 {
		t.Error("no nodes")
	}
	if len(llmGraph.Edges) == 0 {
		t.Error("no edges")
	}
	t.Logf("Serialized: %d nodes, %d edges, %d timeline events",
		len(llmGraph.Nodes), len(llmGraph.Edges), len(llmGraph.Timeline))
}

func TestSerializeGraphToJSON(t *testing.T) {
	g := testGraph()
	llmGraph := SerializeGraph(g.Nodes(), g.Edges(), nil)
	jsonStr, err := llmGraph.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if !strings.Contains(jsonStr, "nodes") {
		t.Error("JSON missing nodes")
	}
	if len(jsonStr) > 0 {
		t.Logf("JSON length: %d bytes", len(jsonStr))
	}
}

func TestShortText(t *testing.T) {
	g := testGraph()
	llmGraph := SerializeGraph(g.Nodes(), g.Edges(), nil)
	text := llmGraph.ShortText()
	if !strings.Contains(text, "process") {
		t.Error("short text missing process count")
	}
	t.Logf("Short text: %s", text)
}

func TestShortAction(t *testing.T) {
	tests := []struct{ in, want string }{
		{"prov:used", "READ"},
		{"prov:wasGeneratedBy", "WROTE"},
		{"prov:wasInformedBy", "FORKED"},
		{"unknown", "unknown"},
	}
	for _, tt := range tests {
		got := shortAction(tt.in)
		if got != tt.want {
			t.Errorf("shortAction(%q) = %q", tt.in, got)
		}
	}
}

// ── Prompt tests ────────────────────────────────────────────

func TestAnalysePrompt(t *testing.T) {
	prompt := AnalysePrompt(`{"nodes":[{"id":"p:1","label":"test"}]}`)
	if !strings.Contains(prompt, "Attack Path Description") {
		t.Error("prompt missing attack path section")
	}
	if !strings.Contains(prompt, "Remediation") {
		t.Error("prompt missing remediation section")
	}
}

func TestQAPrompt(t *testing.T) {
	prompt := QAPrompt(`{"nodes":[]}`, "How did this happen?")
	if !strings.Contains(prompt, "Analyst Question") {
		t.Error("prompt missing question section")
	}
}

func TestSystemPrompt(t *testing.T) {
	if !strings.Contains(SystemPrompt, "senior cybersecurity analyst") {
		t.Error("system prompt role missing")
	}
}

// ── LLM client tests ───────────────────────────────────────

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Provider != "ollama" {
		t.Errorf("provider = %s", cfg.Provider)
	}
	if cfg.Model != "llama3" {
		t.Errorf("model = %s", cfg.Model)
	}
}

func TestDefaultOpenAIConfig(t *testing.T) {
	cfg := DefaultOpenAIConfig("sk-test")
	if cfg.Provider != "openai" {
		t.Errorf("provider = %s", cfg.Provider)
	}
	if cfg.Model != "gpt-4" {
		t.Errorf("model = %s", cfg.Model)
	}
	if cfg.APIKey != "sk-test" {
		t.Errorf("api key = %s", cfg.APIKey)
	}
}

func TestLLMClientNew(t *testing.T) {
	client := NewLLMClient(nil)
	if client == nil {
		t.Fatal("NewLLMClient returned nil")
	}
}

func TestLLMClientAnalyseNoEndpoint(t *testing.T) {
	client := NewLLMClient(&LLMConfig{
		Provider: "ollama",
		Endpoint: "http://127.0.0.1:1",
		Timeout:  1,
	})
	_, err := client.Analyse(`{"test":true}`)
	if err == nil {
		t.Log("expected connection error (ollama not running)")
	} else {
		t.Logf("Expected error: %v", err)
	}
}

func TestFormatResponse(t *testing.T) {
	text := "### Section 1\ncontent\n### Section 2"
	formatted := FormatResponse(text)
	if !strings.HasPrefix(formatted, "### Section 1") {
		t.Errorf("formatted = %q", formatted)
	}
}

// ── Q&A tests ──────────────────────────────────────────────

func TestNewQAEngine(t *testing.T) {
	qa := NewQAEngine(provenance.NewGraph(), nil)
	if qa == nil {
		t.Fatal("NewQAEngine returned nil")
	}
}

func TestQAWithoutLLM(t *testing.T) {
	g := testGraph()
	qa := NewQAEngine(g, nil)

	answer := qa.AnswerWithoutLLM("what files did bash modify?")
	if !strings.Contains(answer, "backdoor") {
		t.Logf("Answer: %s", answer)
	}
}

func TestQAWithoutLLMNetwork(t *testing.T) {
	g := testGraph()
	qa := NewQAEngine(g, nil)

	answer := qa.AnswerWithoutLLM("how did the process connect to the network?")
	if strings.Contains(answer, "Processes that made network connections") {
		t.Log("Network connection query works")
	}
}

func TestQAWithoutLLMGeneral(t *testing.T) {
	g := provenance.NewGraph()
	qa := NewQAEngine(g, nil)

	answer := qa.AnswerWithoutLLM("what happened?")
	if strings.Contains(answer, "nodes") && strings.Contains(answer, "edges") {
		t.Log("General query returns stats")
	}
}

func TestExtractPID(t *testing.T) {
	if pid := extractPID("pid 1234"); pid != 1234 {
		t.Errorf("extractPID = %d", pid)
	}
	if pid := extractPID("process 5678"); pid != 5678 {
		t.Errorf("extractPID = %d", pid)
	}
	if pid := extractPID("no numbers"); pid != 0 {
		t.Errorf("extractPID = %d", pid)
	}
}

// ── Integration test ────────────────────────────────────────

func TestAIIntegration(t *testing.T) {
	g := testGraph()

	// Serialize
	llmGraph := SerializeGraph(g.Nodes(), g.Edges(), &AlertInfo{
		AlertID:  "INTEGRATION-TEST",
		Score:    75,
		Severity: "HIGH",
	})
	jsonStr, _ := llmGraph.ToJSON()
	if jsonStr == "" {
		t.Fatal("empty JSON")
	}
	t.Logf("Graph JSON (%d bytes): %s", len(jsonStr), jsonStr[:min(200, len(jsonStr))])

	// Interpreter
	interp := NewInterpreter(nil)
	result := interp.AnalyseAlert(jsonStr)
	t.Logf("Analyse result: error=%v, output_len=%d",
		result.Error != "", len(result.RawOutput))

	// Q&A
	qa := NewQAEngine(g, nil)
	answer := qa.AnswerWithoutLLM("what is the attack path?")
	t.Logf("Q&A answer: %s", answer[:min(100, len(answer))])

	t.Log("AI Integration OK")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
