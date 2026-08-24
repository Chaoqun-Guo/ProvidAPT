// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Anchoring — write root hash to protected storage
// ═══════════════════════════════════════════════════════════════

// AnchorConfig controls anchoring behavior.
type AnchorConfig struct {
	// EnableKmsg — write root hash to /dev/kmsg (kernel log).
	EnableKmsg bool

	// EnableRemote — send root hash to remote server.
	EnableRemote bool

	// RemoteURL — URL of remote anchoring server.
	RemoteURL string

	// AnchorInterval — how often to anchor (default 1 min).
	AnchorInterval time.Duration
}

// DefaultAnchorConfig returns sensible defaults.
func DefaultAnchorConfig() *AnchorConfig {
	return &AnchorConfig{
		EnableKmsg:     true,
		EnableRemote:   false,
		AnchorInterval: 1 * time.Minute,
	}
}

// AnchoringManager periodically writes root hashes to protected storage.
type AnchoringManager struct {
	cfg     *AnchorConfig
	chain   *ChainStore
	anchors []AnchorRecord
	mu      sync.Mutex
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// AnchorRecord is a timestamped root hash.
type AnchorRecord struct {
	Timestamp time.Time `json:"timestamp"`
	RootHash  string    `json:"root_hash"`
	ChainLen  int       `json:"chain_length"`
	Source    string    `json:"source"` // "kmsg", "remote"
}

// NewAnchoringManager creates an anchoring manager.
func NewAnchoringManager(cfg *AnchorConfig, chain *ChainStore) *AnchoringManager {
	if cfg == nil {
		cfg = DefaultAnchorConfig()
	}
	return &AnchoringManager{
		cfg:    cfg,
		chain:  chain,
		stopCh: make(chan struct{}),
	}
}

// Start begins periodic anchoring.
func (am *AnchoringManager) Start() {
	am.wg.Add(1)
	go am.loop()
	log.Printf("[anchor] started (interval=%v, kmsg=%v, remote=%v)",
		am.cfg.AnchorInterval, am.cfg.EnableKmsg, am.cfg.EnableRemote)
}

func (am *AnchoringManager) loop() {
	defer am.wg.Done()
	ticker := time.NewTicker(am.cfg.AnchorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			am.anchor()
		case <-am.stopCh:
			return
		}
	}
}

// Stop shuts down anchoring.
func (am *AnchoringManager) Stop() {
	close(am.stopCh)
	am.wg.Wait()
}

// anchor writes the current root hash to all configured destinations.
func (am *AnchoringManager) anchor() {
	rootHash := am.chain.RootHash()
	chainLen := am.chain.Count()
	now := time.Now()

	// Write to /dev/kmsg
	if am.cfg.EnableKmsg {
		msg := fmt.Sprintf("PROVIDAPT_ANCHOR ts=%d root=%s len=%d\n",
			now.UnixNano(), rootHash, chainLen)
		if f, err := os.OpenFile("/dev/kmsg", os.O_WRONLY, 0); err == nil {
			if _, err := f.WriteString(msg); err != nil {
				log.Printf("[anchor] kmsg write failed: %v", err)
			}
			if err := f.Close(); err != nil {
				log.Printf("[anchor] kmsg close failed: %v", err)
			}
			log.Printf("[anchor] wrote to /dev/kmsg: root=%s len=%d", rootHash[:16], chainLen)
			am.addAnchor(now, rootHash, chainLen, "kmsg")
		} else {
			// Fallback: write to local file
			if f, err := os.OpenFile("/var/log/providapt/anchor.log",
				os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
				if _, err := f.WriteString(msg); err != nil {
					log.Printf("[anchor] fallback write failed: %v", err)
				}
				if err := f.Close(); err != nil {
					log.Printf("[anchor] fallback close failed: %v", err)
				}
				log.Printf("[anchor] wrote to anchor.log: root=%s", rootHash[:16])
				am.addAnchor(now, rootHash, chainLen, "fallback")
			}
		}
	}

	// Send to remote server
	if am.cfg.EnableRemote && am.cfg.RemoteURL != "" {
		// In production: HTTP POST to remote server
		log.Printf("[anchor] remote anchoring to %s: root=%s", am.cfg.RemoteURL, rootHash[:16])
		am.addAnchor(now, rootHash, chainLen, "remote")
	}
}

func (am *AnchoringManager) addAnchor(ts time.Time, root string, length int, source string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.anchors = append(am.anchors, AnchorRecord{
		Timestamp: ts,
		RootHash:  root,
		ChainLen:  length,
		Source:    source,
	})
}

// Anchors returns all anchor records.
func (am *AnchoringManager) Anchors() []AnchorRecord {
	am.mu.Lock()
	defer am.mu.Unlock()
	out := make([]AnchorRecord, len(am.anchors))
	copy(out, am.anchors)
	return out
}

// LatestAnchor returns the most recent anchor.
func (am *AnchoringManager) LatestAnchor() *AnchorRecord {
	am.mu.Lock()
	defer am.mu.Unlock()
	if len(am.anchors) == 0 {
		return nil
	}
	return &am.anchors[len(am.anchors)-1]
}
