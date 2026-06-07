// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"fmt"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
)

// Writer writes provenance events to persistent storage.
type Writer struct {
	format  string
	dir     string
	json    *JSONWriter
	parquet *ParquetWriter
}

// NewWriter creates a storage writer.
func NewWriter(dir, format string) (*Writer, error) {
	w := &Writer{dir: dir, format: format}
	switch format {
	case "json":
		jw, err := NewJSONWriter(dir)
		if err != nil {
			return nil, err
		}
		w.json = jw
	case "parquet":
		pw, err := NewParquetWriter(dir)
		if err != nil {
			return nil, err
		}
		w.parquet = pw
	default:
		return nil, fmt.Errorf("unknown format: %s", format)
	}
	return w, nil
}

// Write persists a single event.
func (w *Writer) Write(evt *collector.Event) error {
	switch w.format {
	case "json":
		return w.json.Write(evt)
	case "parquet":
		return w.parquet.Write(evt)
	}
	return nil
}

// Close finalizes any open files.
func (w *Writer) Close() {
	if w.json != nil {
		w.json.Close()
	}
	if w.parquet != nil {
		w.parquet.Close()
	}
}
