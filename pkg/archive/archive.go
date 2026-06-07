// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package archive compresses and rotates old event NDJSON files and
// store data into tar.gz archives for long-term retention.
package archive

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Result summarizes an archive operation.
type Result struct {
	InputDir    string        `json:"input_dir"`
	OutputDir   string        `json:"output_dir"`
	FilesArchived int         `json:"files_archived"`
	FilesSkipped  int         `json:"files_skipped"`
	BytesBefore  int64        `json:"bytes_before"`
	BytesAfter   int64        `json:"bytes_after"`
	ArchivePath  string       `json:"archive_path,omitempty"`
	Duration     time.Duration `json:"duration"`
	DryRun       bool         `json:"dry_run"`
}

// Option configures the archive operation.
type Option struct {
	InputDir  string        // directory with NDJSON files to archive
	OutputDir string        // where to write the archive (default: InputDir)
	Age       time.Duration // archive files older than this (default: 24h)
	DryRun    bool          // preview without archiving
}

// Run compresses old NDJSON event files into a tar.gz archive.
func Run(opt Option) (*Result, error) {
	start := time.Now()

	if opt.Age <= 0 {
		opt.Age = 24 * time.Hour
	}
	if opt.OutputDir == "" {
		opt.OutputDir = opt.InputDir
	}

	res := &Result{
		InputDir:  opt.InputDir,
		OutputDir: opt.OutputDir,
		DryRun:    opt.DryRun,
	}

	// Collect old NDJSON files
	cutoff := time.Now().Add(-opt.Age)
	files, err := collectOldFiles(opt.InputDir, cutoff)
	if err != nil {
		return nil, fmt.Errorf("collect files: %w", err)
	}

	if len(files) == 0 {
		return res, nil
	}

	// Calculate total size
	for _, f := range files {
		fi, err := os.Stat(f)
		if err == nil {
			res.BytesBefore += fi.Size()
		}
	}
	res.FilesArchived = len(files)

	if opt.DryRun {
		res.Duration = time.Since(start)
		return res, nil
	}

	// Create archive
	archiveName := fmt.Sprintf("providapt-archive-%s.tar.gz",
		time.Now().UTC().Format("20060102T150405Z"))
	archivePath := filepath.Join(opt.OutputDir, archiveName)

	if err := createTarGz(archivePath, files); err != nil {
		return nil, fmt.Errorf("create archive: %w", err)
	}
	res.ArchivePath = archivePath

	// Remove originals
	for _, f := range files {
		if err := os.Remove(f); err != nil {
			res.FilesSkipped++
			continue
		}
	}

	// Calculate remaining size
	var remaining int64
	entries, _ := os.ReadDir(opt.InputDir)
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "providapt-") {
			fi, _ := e.Info()
			if fi != nil {
				remaining += fi.Size()
			}
		}
	}
	res.BytesAfter = remaining

	// Add archive size to after bytes count
	if fi, err := os.Stat(archivePath); err == nil {
		res.BytesAfter += fi.Size()
	}

	res.Duration = time.Since(start)
	return res, nil
}

// collectOldFiles finds NDJSON files older than cutoff, sorted oldest first.
func collectOldFiles(dir string, cutoff time.Time) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasPrefix(e.Name(), "providapt-") || !strings.HasSuffix(e.Name(), ".ndjson") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if fi.ModTime().Before(cutoff) {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}

	sort.Strings(files)
	return files, nil
}

// createTarGz creates a tar.gz archive containing the given files.
func createTarGz(path string, files []string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create archive file: %w", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	for _, file := range files {
		if err := addFileToTar(tw, file); err != nil {
			return err
		}
	}

	return nil
}

func addFileToTar(tw *tar.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	header, err := tar.FileInfoHeader(fi, "")
	if err != nil {
		return err
	}
	header.Name = filepath.Base(path)

	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}
