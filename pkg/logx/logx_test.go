package logx

import (
	"bytes"
	"strings"
	"testing"
)

func TestInitDefaults(t *testing.T) {
	// Should not panic and return non-nil loggers
	if System() == nil || Audit() == nil || Debug() == nil {
		t.Fatal("loggers should not be nil after init")
	}
}

func TestTextOutput(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	System().Info("hello", "key", "val")
	out := buf.String()
	if !strings.Contains(out, "hello") {
		t.Errorf("expected message in output, got %q", out)
	}
	if !strings.Contains(out, "category=system") {
		t.Errorf("expected category=system, got %q", out)
	}
}

func TestJSONOutput(t *testing.T) {
	var buf bytes.Buffer
	Init("info", "json")
	SetOutput(&buf)
	System().Info("json_test")
	out := buf.String()
	if !strings.Contains(out, `"msg":"json_test"`) && !strings.Contains(out, `"msg": "json_test"`) {
		t.Errorf("expected json message, got %q", out)
	}
	if !strings.Contains(out, "system") {
		t.Errorf("expected category system in json, got %q", out)
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	Init("warn", "text")
	SetOutput(&buf)
	Debug().Debug("should_not_appear")
	System().Info("should_not_appear_either")
	System().Warn("should_appear")
	out := buf.String()
	if strings.Contains(out, "should_not_appear") {
		t.Error("debug message should be filtered at warn level")
	}
	if !strings.Contains(out, "should_appear") {
		t.Error("warn message should appear at warn level")
	}
}

func TestAuditCategory(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	Audit().Warn("audit_event", "event_type", "security")
	out := buf.String()
	if !strings.Contains(out, "category=audit") {
		t.Errorf("expected category=audit, got %q", out)
	}
}

func TestDebugLogger(t *testing.T) {
	var buf bytes.Buffer
	Init("debug", "text")
	SetOutput(&buf)
	Debug().Debug("debug_msg")
	out := buf.String()
	if !strings.Contains(out, "debug_msg") {
		t.Errorf("expected debug_msg in output, got %q", out)
	}
}
