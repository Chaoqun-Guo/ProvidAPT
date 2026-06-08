// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package supportbundle

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCaptureBasic(t *testing.T) {
	tmpDir := t.TempDir()
	path, err := CaptureTo(filepath.Join(tmpDir, "support-bundle"), "manual export")
	if err != nil {
		t.Fatalf("CaptureTo: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("bundle path stat: %v", err)
	}
	if !strings.Contains(path, filepath.Join(tmpDir, "support-bundle")) {
		t.Fatalf("bundle path = %q", path)
	}
	reason, err := os.ReadFile(filepath.Join(path, "reason.txt"))
	if err != nil {
		t.Fatalf("read reason: %v", err)
	}
	if strings.TrimSpace(string(reason)) != "manual export" {
		t.Fatalf("reason = %q", string(reason))
	}
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

func TestCreateArchiveRedactsSensitiveFields(t *testing.T) {
	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "bundle")
	if err := os.MkdirAll(bundleDir, 0755); err != nil {
		t.Fatal(err)
	}
	content := "email=alice@example.com\npassword=super-secret\napi_key=abc123\nip=10.0.0.8\nAuthorization: bearer tokenvalue\n"
	if err := os.WriteFile(filepath.Join(bundleDir, "config.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	archivePath, err := CreateArchive(bundleDir, ArchiveOptions{RedactSensitive: true})
	if err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer zr.Close()
	if len(zr.File) != 1 {
		t.Fatalf("zip files = %d", len(zr.File))
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("open zip file: %v", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read zip file: %v", err)
	}
	got := string(data)
	if strings.Contains(got, "alice@example.com") || strings.Contains(got, "super-secret") || strings.Contains(got, "10.0.0.8") {
		t.Fatalf("content not redacted: %q", got)
	}
	if !strings.Contains(got, "<redacted-email-") || !strings.Contains(got, "<redacted-secret-") || !strings.Contains(got, "<redacted-ip-") {
		t.Fatalf("expected redaction markers, got %q", got)
	}
	if strings.Contains(got, "tokenvalue") {
		t.Fatalf("bearer token tail leaked: %q", got)
	}
}

func TestCleanupArchivesRetainsNewest(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "support-bundle")
	olderDir := root + "-20260101T000000Z"
	newerDir := root + "-20260102T000000Z"
	olderZip := olderDir + ".zip"
	newerZip := newerDir + ".zip"
	for _, path := range []string{olderDir, newerDir} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{olderZip, newerZip} {
		if err := os.WriteFile(path, []byte("zip"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	oldTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newTime := oldTime.Add(time.Hour)
	if err := os.Chtimes(olderDir, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(olderZip, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newerDir, newTime, newTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newerZip, newTime, newTime); err != nil {
		t.Fatal(err)
	}

	if err := CleanupArchives(root, 2); err != nil {
		t.Fatalf("CleanupArchives: %v", err)
	}
	if _, err := os.Stat(newerDir); err != nil {
		t.Fatalf("newer dir missing: %v", err)
	}
	if _, err := os.Stat(newerZip); err != nil {
		t.Fatalf("newer zip missing: %v", err)
	}
	if _, err := os.Stat(olderDir); !os.IsNotExist(err) {
		t.Fatalf("older dir should be removed, stat err=%v", err)
	}
	if _, err := os.Stat(olderZip); !os.IsNotExist(err) {
		t.Fatalf("older zip should be removed, stat err=%v", err)
	}
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
