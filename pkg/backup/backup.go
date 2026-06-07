// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package backup provides backup and restore for the PebbleDB store.
// Backups are created as tar.gz archives of consistent snapshots.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/cockroachdb/pebble"
)

// Meta contains metadata about a backup.
type Meta struct {
	Path      string    `json:"path"`
	SizeBytes int64     `json:"size_bytes"`
	CreatedAt time.Time `json:"created_at"`
	StorePath string    `json:"store_path"`
}

// Create creates a consistent backup of a Pebble store by taking a
// checkpoint and archiving it to the output path. The store must not
// be actively written to (or should be opened read-only).
// Returns the backup metadata.
func Create(storePath, outputPath string) (*Meta, error) {
	// Open store read-only for consistent snapshot
	db, err := pebble.Open(storePath, &pebble.Options{
		ReadOnly: true,
	})
	if err != nil {
		return nil, fmt.Errorf("open store for backup: %w", err)
	}
	defer db.Close()

	// Create temporary checkpoint directory
	tmpDir, err := os.MkdirTemp("", "providapt-backup-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	checkpointPath := filepath.Join(tmpDir, "checkpoint")
	if err := db.Checkpoint(checkpointPath); err != nil {
		return nil, fmt.Errorf("checkpoint: %w", err)
	}

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("create backup file: %w", err)
	}
	defer outFile.Close()

	gzw := gzip.NewWriter(outFile)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	// Walk checkpoint directory and add to archive
	var totalSize int64
	err = filepath.Walk(checkpointPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, _ := filepath.Rel(checkpointPath, path)
		if relPath == "." {
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = relPath
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("write tar header: %w", err)
		}
		if !info.IsDir() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			n, err := io.Copy(tw, f)
			f.Close()
			if err != nil {
				return err
			}
			totalSize += n
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("archive snapshot: %w", err)
	}

	return &Meta{
		Path:      outputPath,
		SizeBytes: totalSize,
		CreatedAt: time.Now(),
		StorePath: storePath,
	}, nil
}

// Restore extracts a backup tar.gz to the target directory.
// The target directory should not exist or be empty (daemon must be stopped).
func Restore(backupPath, targetDir string) error {
	f, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("open backup: %w", err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("decompress backup: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		target := filepath.Join(targetDir, hdr.Name)
		if hdr.FileInfo().IsDir() {
			os.MkdirAll(target, 0755)
			continue
		}
		os.MkdirAll(filepath.Dir(target), 0755)
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, hdr.FileInfo().Mode())
		if err != nil {
			return fmt.Errorf("create file: %w", err)
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return fmt.Errorf("write file: %w", err)
		}
		out.Close()
	}
	return nil
}
