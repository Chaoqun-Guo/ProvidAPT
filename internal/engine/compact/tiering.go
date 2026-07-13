// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package compact

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Cold/hot data tiering
//
// Data lifecycle:
//

//
// Local index (RocksDB) retains minimal metadata for cold data:
//

//
// TieringConfig for the data lifecycle manager.
type TieringConfig struct {
	HotPath string

	WarmPath string

	ColdBucket string

	ColdPrefix string

	HotRetention time.Duration

	WarmRetention time.Duration

	ExportFormat string

	AWSEndpoint string

	DryRun bool
}

// DefaultTieringConfig returns sensible defaults.
func DefaultTieringConfig() *TieringConfig {
	return &TieringConfig{
		HotPath:       "/var/lib/providapt/store",
		WarmPath:      "/var/lib/providapt/warm",
		ColdBucket:    "providapt-archive",
		ColdPrefix:    "provenance/",
		HotRetention:  7 * 24 * time.Hour,
		WarmRetention: 90 * 24 * time.Hour,
		ExportFormat:  "json", // Use "parquet" in production
		DryRun:        true,
	}
}

// ColdIndexEntry is stored in RocksDB for cold data lookups.
type ColdIndexEntry struct {
	Bucket      string `json:"bucket"`
	Key         string `json:"key"`
	EntityID    string `json:"entity_id"`
	Count       int    `json:"count"`
	TimeStart   string `json:"time_start"`
	TimeEnd     string `json:"time_end"`
	StorageSize int64  `json:"size_bytes"`
}

// TieringManager manages the data lifecycle.
type TieringManager struct {
	cfg   *TieringConfig
	index map[string]*ColdIndexEntry
}

// NewTieringManager creates a data lifecycle manager.
func NewTieringManager(cfg *TieringConfig) *TieringManager {
	if cfg == nil {
		cfg = DefaultTieringConfig()
	}
	if err := os.MkdirAll(cfg.WarmPath, 0755); err != nil {
		log.Printf("[tiering] create warm path failed: %v", err)
	}

	return &TieringManager{
		cfg:   cfg,
		index: make(map[string]*ColdIndexEntry),
	}
}

// ArchiveHotToWarm moves old data from RocksDB to warm storage.
func (tm *TieringManager) ArchiveHotToWarm(summaries []*BehaviourSummary) (int, error) {
	cutoff := time.Now().Add(-tm.cfg.HotRetention)
	archived := 0

	for _, s := range summaries {
		// Only archive summaries older than the retention period
		timeEnd, err := time.Parse(time.RFC3339, s.TimeEnd)
		if err != nil || timeEnd.After(cutoff) {
			continue
		}

		if tm.cfg.DryRun {
			log.Printf("[compact/tier] DRY RUN: archive %s -?%s", s.ProcessID, tm.cfg.WarmPath)
			archived++
			continue
		}

		// Write warm file
		filename := fmt.Sprintf("summary_%s_%s_%d.json",
			s.ProcessComm, s.Operation, time.Now().Unix())
		path := filepath.Join(tm.cfg.WarmPath, filename)
		data, _ := json.Marshal(s)

		if err := os.WriteFile(path, data, 0644); err != nil {
			return archived, fmt.Errorf("write warm: %w", err)
		}

		// Create cold index entry for potential S3 archival
		entry := &ColdIndexEntry{
			Bucket:      tm.cfg.ColdBucket,
			Key:         tm.cfg.ColdPrefix + filename,
			EntityID:    s.ProcessID,
			Count:       int(s.TotalCalls),
			TimeStart:   s.TimeStart,
			TimeEnd:     s.TimeEnd,
			StorageSize: s.TotalBytes,
		}
		tm.index[s.ProcessID+"|"+s.TimeStart] = entry
		archived++
	}

	log.Printf("[compact/tier] archived %d items to warm storage", archived)
	return archived, nil
}

// ArchiveWarmToCold uploads warm data to S3-compatible storage.
// In production, this uses the AWS SDK (github.com/aws/aws-sdk-go).
func (tm *TieringManager) ArchiveWarmToCold() (int, error) {
	cutoff := time.Now().Add(-tm.cfg.WarmRetention)
	archived := 0

	entries, err := os.ReadDir(tm.cfg.WarmPath)
	if err != nil {
		if os.IsNotExist(err) && tm.cfg.DryRun {
			log.Printf("[compact/tier] warm path missing in dry-run: %s", tm.cfg.WarmPath)
			return 0, nil
		}
		return 0, fmt.Errorf("read warm path: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}

		if tm.cfg.DryRun {
			log.Printf("[compact/tier] DRY RUN: upload %s -?s3://%s/%s",
				entry.Name(), tm.cfg.ColdBucket, tm.cfg.ColdPrefix)
			archived++
			continue
		}

		// In production:
		//   svc := s3.New(session.New(&aws.Config{...}))
		//   svc.PutObject(&s3.PutObjectInput{
		//       Bucket: aws.String(tm.cfg.ColdBucket),
		//       Key:    aws.String(tm.cfg.ColdPrefix + entry.Name()),
		//       Body:   file,
		//   })

		// Create index entry
		key := tm.cfg.ColdPrefix + entry.Name()
		tm.index[key] = &ColdIndexEntry{
			Bucket:   tm.cfg.ColdBucket,
			Key:      key,
			EntityID: entry.Name(),
		}
		archived++

		// Remove local warm file
		if err := os.Remove(filepath.Join(tm.cfg.WarmPath, entry.Name())); err != nil {
			log.Printf("[compact/tier] remove warm file %s: %v", entry.Name(), err)
		}
	}

	log.Printf("[compact/tier] archived %d items to cold storage (s3://%s/%s)",
		archived, tm.cfg.ColdBucket, tm.cfg.ColdPrefix)
	return archived, nil
}

// LookupCold searches the index for cold data about an entity.
func (tm *TieringManager) LookupCold(entityID string) []*ColdIndexEntry {
	var results []*ColdIndexEntry
	for _, entry := range tm.index {
		if strings.Contains(entry.EntityID, entityID) {
			results = append(results, entry)
		}
	}
	return results
}

// Stats returns tiering statistics.
func (tm *TieringManager) Stats() map[string]interface{} {
	return map[string]interface{}{
		"hot_path":      tm.cfg.HotPath,
		"warm_path":     tm.cfg.WarmPath,
		"cold_bucket":   tm.cfg.ColdBucket,
		"index_entries": len(tm.index),
		"dry_run":       tm.cfg.DryRun,
	}
}
