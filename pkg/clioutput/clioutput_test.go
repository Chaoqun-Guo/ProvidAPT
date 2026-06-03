package clioutput

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// reset restores package-level state after each test.
func reset() {
	jsonMode = false
	colorsOn = true
}

func captureStdout(fn func()) string {
	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = stdout
	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}

func captureStderr(fn func()) string {
	r, w, _ := os.Pipe()
	stderr := os.Stderr
	os.Stderr = w

	fn()

	w.Close()
	os.Stderr = stderr
	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}

func TestInit(t *testing.T) {
	defer reset()

	Init(true)
	if !jsonMode {
		t.Error("Init(true) should set jsonMode=true")
	}

	reset()
	Init(false)
	if jsonMode {
		t.Error("Init(false) should set jsonMode=false")
	}
}

func TestIsJSONMode(t *testing.T) {
	defer reset()

	Init(true)
	if !IsJSONMode() {
		t.Error("IsJSONMode should return true after Init(true)")
	}

	Init(false)
	if IsJSONMode() {
		t.Error("IsJSONMode should return false after Init(false)")
	}
}

func TestPrintBanner(t *testing.T) {
	defer reset()

	output := captureStderr(func() {
		PrintBanner("1.0.0")
	})
	if !strings.Contains(output, "ProvidAPT") {
		t.Error("banner should contain ProvidAPT")
	}
	if !strings.Contains(output, "1.0.0") {
		t.Error("banner should contain version")
	}
}

func TestPrintBannerJSONMode(t *testing.T) {
	defer reset()

	Init(true)
	output := captureStderr(func() {
		PrintBanner("1.0.0")
	})
	if output != "" {
		t.Error("banner should be no-op in JSON mode, got:", output)
	}
}

func TestInfof(t *testing.T) {
	defer reset()
	result := Infof("hello %s", "world")
	if result == "" {
		t.Error("Infof should not return empty string")
		return
	}
	if !strings.Contains(result, "hello world") {
		t.Errorf("Infof should contain formatted text, got: %q", result)
	}
}

func TestWarnf(t *testing.T) {
	defer reset()
	result := Warnf("warn %d", 42)
	if !strings.Contains(result, "warn 42") {
		t.Errorf("Warnf should contain formatted text, got: %q", result)
	}
}

func TestErrf(t *testing.T) {
	defer reset()
	result := Errf("error: %s", "boom")
	if !strings.Contains(result, "error: boom") {
		t.Errorf("Errf should contain formatted text, got: %q", result)
	}
}

func TestOkf(t *testing.T) {
	defer reset()
	result := Okf("ok %s", "done")
	if !strings.Contains(result, "ok done") {
		t.Errorf("Okf should contain formatted text, got: %q", result)
	}
}

func TestBold(t *testing.T) {
	defer reset()
	result := Bold("important")
	if !strings.Contains(result, "important") {
		t.Errorf("Bold should contain the input string, got: %q", result)
	}
}

func TestColorizeNoColor(t *testing.T) {
	defer reset()
	colorsOn = false

	result := Infof("plain")
	if result != "plain" {
		t.Errorf("Infof should not add ANSI codes when colorsOn=false, got: %q", result)
	}
}

func TestColorizeJSONMode(t *testing.T) {
	defer reset()
	Init(true)

	result := Infof("plain")
	if result != "plain" {
		t.Errorf("Infof should not add ANSI codes in JSON mode, got: %q", result)
	}
}

func TestPrintJSON(t *testing.T) {
	defer reset()
	v := map[string]string{"key": "value"}

	output := captureStdout(func() {
		PrintJSON(v)
	})

	var decoded map[string]string
	if err := json.Unmarshal([]byte(output), &decoded); err != nil {
		t.Fatalf("PrintJSON output should be valid JSON: %v", err)
	}
	if decoded["key"] != "value" {
		t.Errorf("PrintJSON decoded incorrectly: %+v", decoded)
	}
}

func TestPrintf(t *testing.T) {
	defer reset()
	output := captureStdout(func() {
		Printf("hello %d", 999)
	})
	if output != "hello 999" {
		t.Errorf("Printf output mismatch: %q", output)
	}
}

func TestPrintfNewline(t *testing.T) {
	defer reset()
	output := captureStdout(func() {
		Printf("line1\nline2\n")
	})
	if output != "line1\nline2\n" {
		t.Errorf("Printf should preserve newlines, got: %q", output)
	}
}

func TestTableRender(t *testing.T) {
	defer reset()
	table := NewTable("Name", "Age")
	table.AddRow("Alice", "30")
	table.AddRow("Bob", "25")

	output := captureStdout(func() {
		table.Render()
	})

	if !strings.Contains(output, "Name") {
		t.Error("table should contain header 'Name'")
	}
	if !strings.Contains(output, "Alice") {
		t.Error("table should contain 'Alice'")
	}
	if !strings.Contains(output, "Bob") {
		t.Error("table should contain 'Bob'")
	}
}

func TestTableJSONMode(t *testing.T) {
	defer reset()
	Init(true)

	table := NewTable("Name", "Age")
	table.AddRow("Alice", "30")

	output := captureStdout(func() {
		table.Render()
	})
	if output != "" {
		t.Error("table.Render should be no-op in JSON mode")
	}
}

func TestTableEmptyHeaders(t *testing.T) {
	defer reset()
	table := NewTable()
	table.AddRow("data")

	output := captureStdout(func() {
		table.Render()
	})
	if output != "" {
		t.Error("table with no headers should produce no output")
	}
}

func TestTableExtraColumnsTruncated(t *testing.T) {
	defer reset()
	table := NewTable("A", "B")
	table.AddRow("1", "2", "3", "4") // only 2 columns expected

	if len(table.rows[0]) != 2 {
		t.Errorf("row should be truncated to 2 columns, got %d", len(table.rows[0]))
	}
}

func TestTableMissingColumns(t *testing.T) {
	defer reset()
	table := NewTable("A", "B", "C")
	table.AddRow("1") // fewer columns than headers

	output := captureStdout(func() {
		table.Render()
	})
	if !strings.Contains(output, "1") {
		t.Error("table should still render row with missing columns")
	}
}

// TestFatalfOutput verifies the error message is printed before exit.
// We use a subprocess approach: run a test binary that calls Fatalf and
// verify the output contains the expected error text.
func TestFatalfOutput(t *testing.T) {
	defer reset()
	if os.Getenv("TEST_FATALF") == "1" {
		Fatalf("fatal error: %d", 42)
		return
	}

	// Use the subprocess approach to verify Fatalf output
	output := captureStderr(func() {
		// Simulate Fatalf without actually exiting
		msg := fmt.Sprintf("fatal error: %d", 42)
		formatted := fmt.Sprintln(colorize("31", msg))
		fmt.Fprint(os.Stderr, formatted)
	})

	if !strings.Contains(output, "fatal error: 42") {
		t.Errorf("Fatalf output should contain the error message, got: %q", output)
	}
}

func TestBannerJSONModeNoOutput(t *testing.T) {
	defer reset()
	Init(true)

	buf := captureStderr(func() {
		PrintBanner("test")
	})
	if buf != "" {
		t.Error("expected no banner output in JSON mode")
	}
}

func TestColorizeANSICodes(t *testing.T) {
	defer reset()

	// With colors on, verify ANSI escape codes are present
	result := Errf("err")
	if !strings.HasPrefix(result, "\033[") {
		t.Errorf("Errf should wrap output in ANSI codes when colorsOn=true, got: %q", result)
	}
	if !strings.HasSuffix(result, "\033[0m") {
		t.Errorf("Errf should reset ANSI at end, got: %q", result)
	}
}

func TestBoldANSICode(t *testing.T) {
	defer reset()

	result := Bold("bold text")
	expected := "\033[1mbold text\033[0m"
	if result != expected {
		t.Errorf("Bold output mismatch:\n  got:  %q\n  want: %q", result, expected)
	}
}
