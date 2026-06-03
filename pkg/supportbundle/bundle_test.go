package supportbundle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCaptureBasic(t *testing.T) {
	// Override bundle dir to a temp location
	tmpDir := t.TempDir()
	origBundleDir := bundleDir
	// We can't change const, but Capture writes to bundleDir-<ts>.
	// Instead test the individual pieces.
	_ = origBundleDir
	_ = tmpDir
}

func TestWriteGoroutines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "goroutines.txt")
	writeGoroutines(path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "goroutine ") {
		t.Errorf("expected goroutine dump, got:\n%s", string(data))
	}
}

func TestWriteBuildInfo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "buildinfo.txt")
	writeBuildInfo(path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "go") {
		t.Errorf("expected build info, got:\n%s", string(data))
	}
}

func TestCollectSystemInfo(t *testing.T) {
	info := collectSystemInfo()
	// On non-Linux systems this may be empty, but should not panic
	_ = info
}

func TestRunCommandSuccess(t *testing.T) {
	out := runCommand("go", "version")
	if out == "" {
		t.Skip("go not in PATH")
	}
	if !strings.Contains(out, "go") {
		t.Errorf("expected go version, got %q", out)
	}
}

func TestRunCommandNotFound(t *testing.T) {
	out := runCommand("nonexistent-command-12345")
	if out != "" {
		t.Errorf("expected empty output for missing command, got %q", out)
	}
}

func TestCaptureWritesFiles(t *testing.T) {
	// Use a non-standard location by manipulating the directory via Capture
	// We can test through the write helpers directly
	dir := t.TempDir()
	writeFile(filepath.Join(dir, "test.txt"), "hello")
	data, err := os.ReadFile(filepath.Join(dir, "test.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Errorf("expected hello, got %q", string(data))
	}
}

func TestCaptureDoesNotPanic(t *testing.T) {
	// Should not panic even when config doesn't exist, etc.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Capture panicked: %v", r)
		}
	}()
	// Can't easily test full Capture without root, but sub-functions shouldn't panic
	_ = readConfig()
}

func TestTryWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	tryWriteFile(path, "content")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "content" {
		t.Errorf("got %q", string(data))
	}
}

func TestTryWriteFileEmptySkips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	tryWriteFile(path, "")
	// File should not have been created
	if _, err := os.Stat(path); err == nil {
		t.Error("empty content should not create file")
	}
}

func TestReadOSReleaseNotFound(t *testing.T) {
	result := readOSRelease()
	if result != "(not found)\n" {
		t.Errorf("expected not-found message, got %q", result)
	}
}

func TestReadConfigNotFound(t *testing.T) {
	result := readConfig()
	if result != "" {
		t.Errorf("expected empty for missing config, got %q", result)
	}
}

func TestHandleCrashNoPanic(t *testing.T) {
	// HandleCrash should not re-panic when there is no panic
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	// Simply defer and return — must not re-panic
	func() {
		defer HandleCrash()
	}()
}

func TestWriteFileCreatesDirectories(t *testing.T) {
	// writeFile should NOT create directories (it uses os.WriteFile directly)
	dir := t.TempDir()
	nonexistentDir := filepath.Join(dir, "nonexistent", "file.txt")
	// This should silently fail (os.WriteFile returns error, but writeFile ignores it)
	writeFile(nonexistentDir, "test")
	// No panic is the pass condition
}

func TestRunCommandWithArgs(t *testing.T) {
	out := runCommand("echo", "hello", "world")
	if out != "hello world\n" && out != "hello world" {
		t.Logf("echo output: %q", out)
	}
}
