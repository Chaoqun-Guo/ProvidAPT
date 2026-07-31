// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package supportbundle

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type ArchiveOptions struct {
	RedactSensitive bool
}

var (
	jsonSecretPattern = regexp.MustCompile(`(?i)"(password|passwd|secret|token|api[_-]?key|authorization)"\s*:\s*"([^"]*)"`)
	textSecretPattern = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|authorization)\s*([:=])\s*([^\r\n]+)`)
	bearerPattern     = regexp.MustCompile(`(?i)bearer\s+([a-z0-9._\-]+)`)
	ipPattern         = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	emailPattern      = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
)

func CreateArchive(bundlePath string, opts ArchiveOptions) (string, error) {
	info, err := os.Stat(bundlePath)
	if err != nil {
		return "", fmt.Errorf("stat bundle: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("bundle path is not a directory: %s", bundlePath)
	}

	archivePath := bundlePath + ".zip"
	file, err := os.Create(archivePath)
	if err != nil {
		return "", fmt.Errorf("create archive: %w", err)
	}
	defer func() { _ = file.Close() }()

	zw := zip.NewWriter(file)
	defer func() { _ = zw.Close() }()

	err = filepath.WalkDir(bundlePath, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(bundlePath, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = src.Close() }()

		w, err := zw.Create(rel)
		if err != nil {
			return err
		}

		if !opts.RedactSensitive || !isRedactableFile(path) {
			_, err = io.Copy(w, src)
			return err
		}

		data, err := io.ReadAll(src)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, bytes.NewReader(redactContent(string(data))))
		return err
	})
	if err != nil {
		return "", fmt.Errorf("walk bundle: %w", err)
	}

	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("close archive: %w", err)
	}
	return archivePath, nil
}

func CleanupArchives(rootDir string, retain int) error {
	if strings.TrimSpace(rootDir) == "" || retain < 1 {
		return nil
	}
	baseDir := filepath.Dir(rootDir)
	prefix := filepath.Base(rootDir) + "-"
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read archive dir: %w", err)
	}

	type archiveEntry struct {
		path    string
		modTime time.Time
	}
	var matches []archiveEntry
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		matches = append(matches, archiveEntry{
			path:    filepath.Join(baseDir, name),
			modTime: info.ModTime(),
		})
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].modTime.After(matches[j].modTime)
	})
	if len(matches) <= retain {
		return nil
	}
	for _, item := range matches[retain:] {
		if err := os.RemoveAll(item.path); err != nil {
			return fmt.Errorf("cleanup archive %s: %w", item.path, err)
		}
	}
	return nil
}

func isRedactableFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".txt", ".log", ".json", ".yaml", ".yml", ".toml", ".conf":
		return true
	default:
		return strings.EqualFold(filepath.Base(path), "buildinfo.txt")
	}
}

func redactContent(content string) []byte {
	out := content
	out = jsonSecretPattern.ReplaceAllStringFunc(out, func(match string) string {
		parts := jsonSecretPattern.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		return fmt.Sprintf(`"%s":"%s"`, parts[1], pseudonymize("secret", parts[2]))
	})
	out = textSecretPattern.ReplaceAllStringFunc(out, func(match string) string {
		parts := textSecretPattern.FindStringSubmatch(match)
		if len(parts) != 4 {
			return match
		}
		return fmt.Sprintf("%s%s%s", parts[1], parts[2], pseudonymize("secret", parts[3]))
	})
	out = bearerPattern.ReplaceAllStringFunc(out, func(match string) string {
		parts := bearerPattern.FindStringSubmatch(match)
		if len(parts) != 2 {
			return match
		}
		return "Bearer " + pseudonymize("token", parts[1])
	})
	out = ipPattern.ReplaceAllStringFunc(out, func(match string) string {
		return pseudonymize("ip", match)
	})
	out = emailPattern.ReplaceAllStringFunc(out, func(match string) string {
		return pseudonymize("email", match)
	})
	return []byte(out)
}

func pseudonymize(kind, value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return fmt.Sprintf("<redacted-%s-%x>", strings.ToLower(strings.TrimSpace(kind)), sum[:4])
}
