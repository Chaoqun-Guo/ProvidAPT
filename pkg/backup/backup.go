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
	"fmt"
	"io"
	"os"
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
	defer db.Close()

	// Take a consistent snapshot
	snapshot := db.NewSnapshot()
	defer snapshot.Close()

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

	// Iterate over all keys in the snapshot
	var totalSize int64
	var entryCount int

	iter, err := snapshot.NewIter(nil)
	if err != nil {
		return nil, fmt.Errorf("create iterator: %w", err)
	}
	defer iter.Close()

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
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("decompress backup: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	// Open the target DB for writing
	db, err := pebble.Open(targetDir, &pebble.Options{})
	if err != nil {
		return fmt.Errorf("open target store: %w", err)
	}
	defer db.Close()

	batch := db.NewBatch()
	defer batch.Close()

	var entryCount int
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
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
			defer batch.Close()
		}
	}

	if entryCount > 0 {
		if err := batch.Commit(pebble.Sync); err != nil {
			return fmt.Errorf("final commit: %w", err)
		}
	}

	return nil
}
