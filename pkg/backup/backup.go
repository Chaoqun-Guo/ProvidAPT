// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package backup provides backup and restore for the PebbleDB store.
// Backups are created as tar.gz archives of key-value pairs via a
// consistent snapshot.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
// database snapshot and writing all key-value pairs to the output path.
// The store must not be actively written to (or should be opened read-only).
// Returns the backup metadata.
func Create(storePath, outputPath string) (*Meta, error) {
	// Open store read-only for consistent snapshot
	db, err := pebble.Open(storePath, &pebble.Options{
		ReadOnly: true,
	})
	if err != nil {
		return nil, fmt.Errorf("open store for backup: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Take a consistent snapshot
	snapshot := db.NewSnapshot()
	defer func() { _ = snapshot.Close() }()

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("create backup file: %w", err)
	}
	defer func() { _ = outFile.Close() }()

	gzw := gzip.NewWriter(outFile)
	defer func() { _ = gzw.Close() }()

	tw := tar.NewWriter(gzw)
	defer func() { _ = tw.Close() }()

	// Iterate over all keys in the snapshot
	var totalSize int64
	var entryCount int

	iter, err := snapshot.NewIter(nil)
	if err != nil {
		return nil, fmt.Errorf("create iterator: %w", err)
	}
	defer func() { _ = iter.Close() }()

	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()
		value := iter.Value()

		// Each entry is stored as a separate file in the tar archive
		// named by its sequence number
		entryName := fmt.Sprintf("entry_%010d", entryCount)

		// Encode key length (4 bytes) + key + value
		hdr := &tar.Header{
			Name: entryName,
			Size: int64(4 + len(key) + len(value)),
			Mode: 0644,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("write tar header: %w", err)
		}

		// Write key length (big-endian uint32) followed by key and value
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(key)))
		if _, err := tw.Write(lenBuf); err != nil {
			return nil, fmt.Errorf("write key length: %w", err)
		}
		if _, err := tw.Write(key); err != nil {
			return nil, fmt.Errorf("write key: %w", err)
		}
		if _, err := tw.Write(value); err != nil {
			return nil, fmt.Errorf("write value: %w", err)
		}

		totalSize += int64(4 + len(key) + len(value))
		entryCount++
	}

	return &Meta{
		Path:      outputPath,
		SizeBytes: totalSize,
		CreatedAt: time.Now(),
		StorePath: storePath,
	}, nil
}

// Restore extracts a backup tar.gz to the target directory.
// The target directory must be empty or non-existent.
func Restore(backupPath, targetDir string) error {
	f, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("open backup: %w", err)
	}
	defer func() { _ = f.Close() }()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("decompress backup: %w", err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)

	// Open the target DB for writing
	db, err := pebble.Open(targetDir, &pebble.Options{})
	if err != nil {
		return fmt.Errorf("open target store: %w", err)
	}
	defer func() { _ = db.Close() }()

	batch := db.NewBatch()
	defer func() { _ = batch.Close() }()

	var entryCount int
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		if hdr.Size < 4 {
			continue
		}

		// Read key length prefix
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(tr, lenBuf); err != nil {
			return fmt.Errorf("read key length: %w", err)
		}
		keyLen := binary.BigEndian.Uint32(lenBuf)

		if keyLen > uint32(hdr.Size-4) {
			continue
		}

		key := make([]byte, keyLen)
		if _, err := io.ReadFull(tr, key); err != nil {
			return fmt.Errorf("read key: %w", err)
		}

		valueLen := hdr.Size - 4 - int64(keyLen)
		value := make([]byte, valueLen)
		if _, err := io.ReadFull(tr, value); err != nil {
			return fmt.Errorf("read value: %w", err)
		}

		if err := batch.Set(key, value, pebble.Sync); err != nil {
			return fmt.Errorf("batch set: %w", err)
		}
		entryCount++

		// Flush batch every 1000 entries
		if entryCount%1000 == 0 {
			if err := batch.Commit(pebble.Sync); err != nil {
				return fmt.Errorf("commit batch: %w", err)
			}
			batch = db.NewBatch()
			defer func() { _ = batch.Close() }()
		}
	}

	if entryCount > 0 {
		if err := batch.Commit(pebble.Sync); err != nil {
			return fmt.Errorf("final commit: %w", err)
		}
	}

	return nil
}

// CreateCheckpoint archives a live Pebble checkpoint into a tar.gz file.
// It is safe for an already-open database and preserves the raw on-disk
// representation, including encrypted values when storage encryption is used.
func CreateCheckpoint(db *pebble.DB, outputPath string) (*Meta, error) {
	if db == nil {
		return nil, fmt.Errorf("nil pebble database")
	}
	outputPath = strings.TrimSpace(outputPath)
	if outputPath == "" {
		return nil, fmt.Errorf("output path is required")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0700); err != nil {
		return nil, fmt.Errorf("create backup dir: %w", err)
	}
	checkpointDir := outputPath + ".checkpoint"
	if err := os.RemoveAll(checkpointDir); err != nil {
		return nil, fmt.Errorf("remove stale checkpoint: %w", err)
	}
	if err := db.Checkpoint(checkpointDir); err != nil {
		return nil, fmt.Errorf("create checkpoint: %w", err)
	}
	defer func() { _ = os.RemoveAll(checkpointDir) }()

	if err := archiveDirectory(checkpointDir, outputPath); err != nil {
		return nil, err
	}
	info, err := os.Stat(outputPath)
	if err != nil {
		return nil, fmt.Errorf("stat backup archive: %w", err)
	}
	return &Meta{
		Path:      outputPath,
		SizeBytes: info.Size(),
		CreatedAt: time.Now(),
		StorePath: checkpointDir,
	}, nil
}

// RestoreCheckpoint extracts a raw checkpoint archive into targetDir.
// The target directory must be empty or absent. Callers should restore into a
// staging directory first, then swap it into place while ProvidAPT is stopped.
func RestoreCheckpoint(backupPath, targetDir string) error {
	if strings.TrimSpace(backupPath) == "" {
		return fmt.Errorf("backup path is required")
	}
	if strings.TrimSpace(targetDir) == "" {
		return fmt.Errorf("target dir is required")
	}
	if entries, err := os.ReadDir(targetDir); err == nil && len(entries) > 0 {
		return fmt.Errorf("target dir is not empty: %s", targetDir)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect target dir: %w", err)
	}
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return fmt.Errorf("create target dir: %w", err)
	}

	f, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("open checkpoint backup: %w", err)
	}
	defer func() { _ = f.Close() }()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("decompress checkpoint backup: %w", err)
	}
	defer func() { _ = gr.Close() }()
	tr := tar.NewReader(gr)
	cleanTarget, err := filepath.Abs(targetDir)
	if err != nil {
		return fmt.Errorf("resolve target dir: %w", err)
	}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read checkpoint tar: %w", err)
		}
		if hdr == nil || strings.TrimSpace(hdr.Name) == "" {
			continue
		}
		dest, err := safeArchivePath(cleanTarget, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dest, 0700); err != nil {
				return fmt.Errorf("create restore dir: %w", err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
				return fmt.Errorf("create restore parent: %w", err)
			}
			out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				return fmt.Errorf("create restore file: %w", err)
			}
			if _, err := io.Copy(out, tr); err != nil {
				_ = out.Close()
				return fmt.Errorf("write restore file: %w", err)
			}
			if err := out.Close(); err != nil {
				return fmt.Errorf("close restore file: %w", err)
			}
		}
	}
	return nil
}

func archiveDirectory(root, outputPath string) error {
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create checkpoint archive: %w", err)
	}
	defer func() { _ = outFile.Close() }()
	gzw := gzip.NewWriter(outFile)
	defer func() { _ = gzw.Close() }()
	tw := tar.NewWriter(gzw)
	defer func() { _ = tw.Close() }()

	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = in.Close() }()
		_, err = io.Copy(tw, in)
		return err
	})
}

func safeArchivePath(targetDir, name string) (string, error) {
	cleanName := filepath.Clean(filepath.FromSlash(name))
	if cleanName == "." || filepath.IsAbs(cleanName) || strings.HasPrefix(cleanName, ".."+string(os.PathSeparator)) || cleanName == ".." {
		return "", fmt.Errorf("unsafe archive path: %s", name)
	}
	dest := filepath.Join(targetDir, cleanName)
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return "", fmt.Errorf("resolve archive path: %w", err)
	}
	if absDest != targetDir && !strings.HasPrefix(absDest, targetDir+string(os.PathSeparator)) {
		return "", fmt.Errorf("archive path escapes target: %s", name)
	}
	return absDest, nil
}

// CleanupArchives keeps the newest retain .tar.gz archives in dir and removes
// older backup archives. retain=0 removes all matching archives.
func CleanupArchives(dir string, retain int) error {
	if retain < 0 {
		return fmt.Errorf("retain must be non-negative")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read backup dir: %w", err)
	}
	type archiveInfo struct {
		path    string
		modTime time.Time
	}
	archives := []archiveInfo{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".tar.gz") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat backup archive: %w", err)
		}
		archives = append(archives, archiveInfo{
			path:    filepath.Join(dir, name),
			modTime: info.ModTime(),
		})
	}
	sort.Slice(archives, func(i, j int) bool {
		return archives[i].modTime.After(archives[j].modTime)
	})
	for index, archive := range archives {
		if index < retain {
			continue
		}
		if err := os.Remove(archive.path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove old backup archive: %w", err)
		}
	}
	return nil
}
