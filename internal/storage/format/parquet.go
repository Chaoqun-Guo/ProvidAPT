// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
)

// ParquetWriter writes provenance events as columnar binary data.
// Uses a structured binary format inspired by Parquet's column-oriented design:
// events are stored per-column (all timestamps together, all PIDs together, etc.)
// for efficient compression and analysis.
//
// Format layout:
//
//	[header] [column data] [footer]
//
// Header: magic bytes "PRVD", version uint32, schema-hash uint64
// Each column: length-prefixed fixed-size entries
// Footer: row count, column offsets, magic trailer
//
// In production, swap for github.com/xitongsys/parquet-go or segmentio/parquet-go.
type ParquetWriter struct {
	mu       sync.Mutex
	f        *os.File
	dir      string
	filename string
	rowCount uint64
	colBufs  [][]byte // one buffer per column
	colSizes []int    // fixed size per entry for each column
	colCount int
}

// column schema indices
const (
	colTimestamp = iota
	colPID
	colPPID
	colUID
	colCommLen
	colComm
	colFlags
	colFilenameLen
	colFilename
	numColumns
)

// magic constants
var magicHeader = []byte("PRVD")
var magicFooter = []byte("PRVDEND")

func NewParquetWriter(dir string) (*ParquetWriter, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create parquet dir: %w", err)
	}

	filename := filepath.Join(dir, fmt.Sprintf("providapt-%s.prvd",
		time.Now().UTC().Format("20060102T150405Z")))
	f, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("create parquet file: %w", err)
	}

	pw := &ParquetWriter{
		f:        f,
		dir:      dir,
		filename: filename,
		colCount: numColumns,
		colBufs:  make([][]byte, numColumns),
		colSizes: []int{
			8, // colTimestamp: int64
			4, // colPID: uint32
			4, // colPPID: uint32
			4, // colUID: uint32
			2, // colCommLen: uint16
			0, // colComm: variable
			4, // colFlags: int32
			2, // colFilenameLen: uint16
			0, // colFilename: variable
		},
	}

	// Write header
	if _, err := f.Write(magicHeader); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write header: %w", err)
	}
	// Version
	var ver [4]byte
	binary.LittleEndian.PutUint32(ver[:], 1)
	if _, err := f.Write(ver[:]); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write version: %w", err)
	}

	return pw, nil
}

// Write appends an event to the column buffers.
func (pw *ParquetWriter) Write(evt *collector.Event) error {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	var ts [8]byte
	binary.LittleEndian.PutUint64(ts[:], evt.TimestampNS)
	pw.colBufs[colTimestamp] = append(pw.colBufs[colTimestamp], ts[:]...)

	var pid [4]byte
	binary.LittleEndian.PutUint32(pid[:], evt.PID)
	pw.colBufs[colPID] = append(pw.colBufs[colPID], pid[:]...)

	var ppid [4]byte
	binary.LittleEndian.PutUint32(ppid[:], evt.PPID)
	pw.colBufs[colPPID] = append(pw.colBufs[colPPID], ppid[:]...)

	var uid [4]byte
	binary.LittleEndian.PutUint32(uid[:], evt.UID)
	pw.colBufs[colUID] = append(pw.colBufs[colUID], uid[:]...)

	comm := []byte(evt.Comm)
	var commLen [2]byte
	binary.LittleEndian.PutUint16(commLen[:], uint16(len(comm)))
	pw.colBufs[colCommLen] = append(pw.colBufs[colCommLen], commLen[:]...)
	pw.colBufs[colComm] = append(pw.colBufs[colComm], comm...)

	var flags [4]byte
	binary.LittleEndian.PutUint32(flags[:], evt.Flags)
	pw.colBufs[colFlags] = append(pw.colBufs[colFlags], flags[:]...)

	fname := []byte(evt.Pathname)
	var fnameLen [2]byte
	binary.LittleEndian.PutUint16(fnameLen[:], uint16(len(fname)))
	pw.colBufs[colFilenameLen] = append(pw.colBufs[colFilenameLen], fnameLen[:]...)
	pw.colBufs[colFilename] = append(pw.colBufs[colFilename], fname...)

	pw.rowCount++
	return nil
}

// Close flushes column buffers to disk and writes the footer.
func (pw *ParquetWriter) Close() {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	if pw.f == nil {
		return
	}

	// Write column offset table
	offset := uint64(len(magicHeader) + 4) // past header
	var offsets [numColumns]uint64
	for i := 0; i < numColumns; i++ {
		offsets[i] = offset
		colLen := uint64(len(pw.colBufs[i]))
		if _, err := pw.f.Write(pw.colBufs[i]); err != nil {
			break
		}
		offset += colLen
	}

	// Footer: row count + column offsets
	var footerBuf [8 + 8*numColumns + 8]byte
	binary.LittleEndian.PutUint64(footerBuf[0:8], pw.rowCount)
	for i := 0; i < numColumns; i++ {
		binary.LittleEndian.PutUint64(footerBuf[8+8*i:8+8*(i+1)], offsets[i])
	}
	// Magic trailer position
	trailerOff := offset
	binary.LittleEndian.PutUint64(footerBuf[8+8*numColumns:8+8*numColumns+8], trailerOff)
	if _, err := pw.f.Write(footerBuf[:]); err != nil {
		log.Printf("[format/parquet] write footer: %v", err)
	}
	if _, err := pw.f.Write(magicFooter); err != nil {
		log.Printf("[format/parquet] write magic footer: %v", err)
	}
	if err := pw.f.Close(); err != nil {
		log.Printf("[format/parquet] close file: %v", err)
	}
	pw.f = nil
}
