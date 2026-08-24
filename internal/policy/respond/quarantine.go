// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package respond

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// File quarantining — permission-lock malicious files
// ═══════════════════════════════════════════════════════════════

// QuarantineLevel defines how a file is isolated.
type QuarantineLevel int

const (
	QuarantineNone   QuarantineLevel = 0
	QuarantineLock   QuarantineLevel = 1 // chmod 0000
	QuarantineMove   QuarantineLevel = 2 // move to quarantine dir
	QuarantineDelete QuarantineLevel = 3 // delete (high confidence)
)

// QuarantinedFile tracks an isolated file.
type QuarantinedFile struct {
	Path      string          `json:"path"`
	Size      int64           `json:"size"`
	WrittenBy uint32          `json:"written_by"` // PID that wrote it
	Level     QuarantineLevel `json:"level"`
	Action    string          `json:"action"` // "locked", "moved", "deleted"
	Time      time.Time       `json:"time"`
}

// FileQuarantineManager handles file isolation actions.
type FileQuarantineManager struct {
	mu            sync.Mutex
	quarantined   []*QuarantinedFile
	quarantineDir string
	dryRun        bool
}

// NewFileQuarantineManager creates a file quarantine manager.
func NewFileQuarantineManager(quarantineDir string, dryRun bool) *FileQuarantineManager {
	if quarantineDir == "" {
		quarantineDir = "/var/quarantine/providapt"
	}
	return &FileQuarantineManager{
		quarantineDir: quarantineDir,
		dryRun:        dryRun,
	}
}

// QuarantineFile isolates a file by changing permissions to 0000.
// Returns the quarantine record.
func (fqm *FileQuarantineManager) QuarantineFile(path string, writtenBy uint32, level QuarantineLevel) *QuarantinedFile {
	qf := &QuarantinedFile{
		Path:      path,
		WrittenBy: writtenBy,
		Level:     level,
		Time:      time.Now(),
	}

	if fqm.dryRun {
		qf.Action = "dry-run"
		log.Printf("[quarantine] DRY: would isolate %s (written by PID %d, level=%d)",
			path, writtenBy, level)
	} else {
		switch level {
		case QuarantineLock:
			if err := os.Chmod(path, 0000); err == nil {
				qf.Action = "locked"
				log.Printf("[quarantine] LOCKED %s (mode=0000)", path)
			} else {
				log.Printf("[quarantine] FAILED to lock %s: %v", path, err)
			}

		case QuarantineMove:
			dest := fmt.Sprintf("%s/%d_%s", fqm.quarantineDir, time.Now().Unix(), sanitize(path))
			if err := os.Rename(path, dest); err == nil {
				qf.Action = "moved"
				log.Printf("[quarantine] MOVED %s → %s", path, dest)
			} else {
				log.Printf("[quarantine] FAILED to move %s: %v", path, err)
			}

		case QuarantineDelete:
			if err := os.Remove(path); err == nil {
				qf.Action = "deleted"
				log.Printf("[quarantine] DELETED %s", path)
			} else {
				log.Printf("[quarantine] FAILED to delete %s: %v", path, err)
			}
		}
	}

	fqm.mu.Lock()
	fqm.quarantined = append(fqm.quarantined, qf)
	fqm.mu.Unlock()

	return qf
}

// QuarantineFilesByPID quarantines all files written by a given PID.
// In production, this would query the RocksDB store for edges where
// Source is the PID and Relation is "wasGeneratedBy".
func (fqm *FileQuarantineManager) QuarantineFilesByPID(pid uint32, files []string, level QuarantineLevel) []*QuarantinedFile {
	var results []*QuarantinedFile
	for _, path := range files {
		qf := fqm.QuarantineFile(path, pid, level)
		results = append(results, qf)
	}
	return results
}

// Stats returns quarantine statistics.
func (fqm *FileQuarantineManager) Stats() map[string]interface{} {
	fqm.mu.Lock()
	defer fqm.mu.Unlock()
	return map[string]interface{}{
		"total_quarantined": len(fqm.quarantined),
		"dry_run":           fqm.dryRun,
	}
}

func sanitize(path string) string {
	// Replace path separators for safe filenames
	result := ""
	for _, c := range path {
		if c == '/' || c == '\\' {
			result += "_"
		} else {
			result += string(c)
		}
	}
	return result
}
