package dsl

import (
	"strings"
	"testing"
)

// ─── Lexer tests ────────────────────────────────────────────

func TestTokenizer(t *testing.T) {
	parts := tokenize(`find process where name="nginx" -> follow child`)
	if len(parts) != 9 {
		t.Errorf("got %d tokens: %v", len(parts), parts)
	}
}

func TestTokenizerQuotedStrings(t *testing.T) {
	parts := tokenize(`find file where path="/etc/shadow"`)
	if len(parts) < 4 {
		t.Errorf("too few tokens: %v", parts)
	}
}

func TestTokenizerArrows(t *testing.T) {
	parts := tokenize(`find process -> follow child`)
	if len(parts) != 5 {
		t.Errorf("got %d: %v", len(parts), parts)
	}
}

// ─── Parser tests ───────────────────────────────────────────

func TestParseSimpleFind(t *testing.T) {
	q, err := Parse(`find process where name="bash"`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(q.Steps) != 1 {
		t.Fatalf("steps = %d", len(q.Steps))
	}
	if q.Steps[0].Action != "find" {
		t.Errorf("action = %s", q.Steps[0].Action)
	}
	if q.Steps[0].NodeType != "process" {
		t.Errorf("node type = %s", q.Steps[0].NodeType)
	}
	if q.Steps[0].Value != "bash" {
		t.Errorf("value = %s", q.Steps[0].Value)
	}
}

func TestParseChainQuery(t *testing.T) {
	q, err := Parse(`find process where name="nginx" -> follow child -> find file where path="/etc/*"`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(q.Steps) != 3 {
		t.Fatalf("steps = %d, want 3", len(q.Steps))
	}
	if q.Steps[0].Action != "find" {
		t.Errorf("step 0 action = %s", q.Steps[0].Action)
	}
	if q.Steps[1].Action != "follow" {
		t.Errorf("step 1 action = %s", q.Steps[1].Action)
	}
	if q.Steps[1].Direction != "child" {
		t.Errorf("step 1 direction = %s", q.Steps[1].Direction)
	}
	if q.Steps[2].Action != "find" {
		t.Errorf("step 2 action = %s", q.Steps[2].Action)
	}
}

func TestParseFollowParent(t *testing.T) {
	q, err := Parse(`find process -> follow parent`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if q.Steps[1].Direction != "parent" {
		t.Errorf("direction = %s", q.Steps[1].Direction)
	}
}

func TestParseEdgeRelation(t *testing.T) {
	q, err := Parse(`find process -> write -> find file`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if q.Steps[1].Action != "edge" || q.Steps[1].Relation != "write" {
		t.Errorf("step 1 = %+v", q.Steps[1])
	}
}

func TestParseNetworkQuery(t *testing.T) {
	q, err := Parse(`find network where addr="5.6.7.8" -> follow parent -> find process`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if q.Steps[0].NodeType != "network" {
		t.Errorf("type = %s", q.Steps[0].NodeType)
	}
}

func TestParseEmptyError(t *testing.T) {
	_, err := Parse("")
	if err == nil {
		t.Error("expected error for empty query")
	}
}

func TestQueryString(t *testing.T) {
	q, _ := Parse(`find process where name="bash"`)
	s := q.String()
	if !strings.Contains(s, "find process") {
		t.Errorf("string = %s", s)
	}
}

func TestQueryChainString(t *testing.T) {
	q, _ := Parse(`find process -> read -> find file`)
	s := q.String()
	if !strings.Contains(s, "read") {
		t.Errorf("string = %s", s)
	}
	t.Logf("Query: %s", s)
}

// ─── Chain formatting tests ─────────────────────────────────

func TestFormatChainEmpty(t *testing.T) {
	result := &ChainResult{}
	s := FormatChain(result)
	if !strings.Contains(s, "No results") {
		t.Errorf("empty result: %s", s)
	}
}

func TestFormatChainBasic(t *testing.T) {
	result := &ChainResult{
		Chain: []ChainNode{
			{ID: "p:100", Type: "process", Label: "nginx", PID: 100, Depth: 0},
			{ID: "f:5000:8:3", Type: "file", Label: "/etc/shadow", Depth: 1, Relation: "read"},
		},
	}
	s := FormatChain(result)
	if !strings.Contains(s, "nginx") {
		t.Errorf("missing nginx: %s", s)
	}
	if !strings.Contains(s, "/etc/shadow") {
		t.Errorf("missing file: %s", s)
	}
	t.Logf("Chain:\n%s", s)
}

func TestFormatChainMultiLevel(t *testing.T) {
	result := &ChainResult{
		Chain: []ChainNode{
			{ID: "p:1", Type: "process", Label: "systemd", Depth: 0},
			{ID: "p:100", Type: "process", Label: "nginx", Depth: 1, Relation: "fork"},
			{ID: "p:101", Type: "process", Label: "bash", Depth: 2, Relation: "fork"},
			{ID: "f:5000", Type: "file", Label: "/etc/shadow", Depth: 3, Relation: "read"},
		},
	}
	s := FormatChain(result)
	t.Logf("Multi-level chain:\n%s", s)
	if !strings.Contains(s, "systemd") {
		t.Error("missing systemd")
	}
}

// ─── Helper tests ───────────────────────────────────────────

func TestInferType(t *testing.T) {
	if inferType("p:100") != "process" {
		t.Error("p: should be process")
	}
	if inferType("f:5000") != "file" {
		t.Error("f: should be file")
	}
	if inferType("n:8.8.8.8") != "network" {
		t.Error("n: should be network")
	}
}

func TestRelationToPROV(t *testing.T) {
	if relationToPROV("read") != "used" {
		t.Errorf("read -> %s", relationToPROV("read"))
	}
	if relationToPROV("write") != "wasGeneratedBy" {
		t.Errorf("write -> %s", relationToPROV("write"))
	}
	if relationToPROV("fork") != "wasInformedBy" {
		t.Errorf("fork -> %s", relationToPROV("fork"))
	}
}

// ─── Integration test ───────────────────────────────────────

func TestCLIIntegration(t *testing.T) {
	queries := []string{
		`find process where name="bash"`,
		`find process where name="nginx" -> follow child -> find file`,
		`find network where addr="5.6.7.8" -> follow parent -> find process`,
		`find process -> write -> find file where path="/tmp/*"`,
		`find process -> fork -> find process -> follow child -> find network`,
	}

	for _, qs := range queries {
		q, err := Parse(qs)
		if err != nil {
			t.Errorf("FAIL: %s\n  error: %v", qs, err)
			continue
		}
		t.Logf("OK: %s", q.String())
	}
}
