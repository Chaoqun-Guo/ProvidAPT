// Package pipeline provides an efficient event ingestion pipeline for
// ProvidAPT that combines:
//
//   - LRU caching of hot (active) provenance nodes
//   - Sliding-window merge deduplication of edges
//   - RocksDB-backed persistence of cold nodes and all edges
//   - Memory pressure monitoring with automatic backpressure
//
// Architecture:
//
//   RingBuf → Pipeline.AddEvent()
//               │
//               ├→ cache.LRU (hot nodes)
//               │    └→ store.Store (cold nodes on eviction)
//               │
//               ├→ pipeline.MergeWindow (5s window dedup)
//               │    └→ store.Store (edges on flush)
//               │
//               ├→ provenance.Graph (in-memory DAG)
//               │
//               └→ pipeline.PressureMonitor (background)
//                      ├→ force eviction + flush at 70%
//                      └→ request slow-down at 85%
package pipeline

import (
	"log"
	"sync"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/storage/cache"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/storage/store"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/syscall"
	"github.com/Chaoqun-Guo/ProvidAPT/pkg/metrics"
)

// ─── Config ──────────────────────────────────────────────────

type Config struct {
	// MaxCacheSize is the maximum number of hot nodes kept in the LRU cache.
	MaxCacheSize int

	// MergeWindow is the sliding window duration for edge deduplication.
	MergeWindow time.Duration

	// MaxMemoryMB is the soft memory limit. 0 = auto-detect.
	MaxMemoryMB uint64

	// StorePath is the RocksDB (Pebble) database directory.
	StorePath string

	// FlushInterval controls periodic edge flush to RocksDB.
	FlushInterval time.Duration

	// EncryptionKey enables transparent AES-256-GCM encryption at rest.
	// Nil means no encryption.
	EncryptionKey []byte
}

func DefaultConfig() *Config {
	return &Config{
		MaxCacheSize:  4096,
		MergeWindow:   5 * time.Second,
		MaxMemoryMB:   0, // auto
		StorePath:     "/var/lib/providapt/store",
		FlushInterval: 5 * time.Second,
	}
}

// ─── Pipeline ────────────────────────────────────────────────

// Pipeline is the central event ingestion path.  It owns the cache,
// the persistent store, the merge window, the pressure monitor, and
// the in-memory provenance graph.
type Pipeline struct {
	graph    *provenance.Graph
	store    *store.Store
	hotCache *cache.Cache
	merger   *MergeWindow
	pressure *PressureMonitor
	cfg      *Config

	// ingest control
	pauseCh  chan struct{}
	resumeCh chan struct{}
	mu       sync.Mutex
	paused   bool

	// edge flush ticker
	flushTicker *time.Ticker
	stopCh      chan struct{}
	wg          sync.WaitGroup
}

// New creates a fully-wired pipeline.
func New(graph *provenance.Graph, cfg *Config) (*Pipeline, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	st, err := store.Open(cfg.StorePath, cfg.EncryptionKey)
	if err != nil {
		return nil, err
	}

	p := &Pipeline{
		graph:     graph,
		store:     st,
		cfg:       cfg,
		pauseCh:   make(chan struct{}, 1),
		resumeCh:  make(chan struct{}, 1),
		flushTicker: time.NewTicker(cfg.FlushInterval),
		stopCh:    make(chan struct{}),
	}

	// LRU cache: eviction persists nodes to RocksDB
	p.hotCache, err = cache.New(cfg.MaxCacheSize, func(id string) error {
		n, ok := p.graph.LookupNode(id)
		if !ok || n == nil {
			return nil
		}
		return p.store.PutNode(n)
	})
	if err != nil {
		st.Close()
		return nil, err
	}

	// Merge window: flush materialises merged edges to RocksDB
	p.merger = NewMergeWindow(cfg.MergeWindow, func(e *provenance.Edge) error {
		return p.store.PutEdge(e)
	})

	// Pressure monitor
	p.pressure = NewPressureMonitor(
		cfg.MaxMemoryMB,
		p.onMidPressure,
		p.onHighPressure,
	)
	p.pressure.Start()

	return p, nil
}

// ── Event ingestion ─────────────────────────────────────────

// AddEvent processes a single event through the entire pipeline.
func (p *Pipeline) AddEvent(evt *collector.Event) {
	// 1. Update the provenance DAG
	p.graph.AddEvent(evt)

	// 2. Touch active nodes in the LRU cache
	p.refreshCache(evt)

	// 3. Merge edges into the sliding window
	p.mergeEdges(evt)

	// 4. Check if we're paused (backpressure)
	p.checkPause()

	metrics.PipelineEventsProcessed.Inc()
}

// refreshCache ensures the event's process node is in the LRU cache.
func (p *Pipeline) refreshCache(evt *collector.Event) {
	procID := provenance.NodeIDProcess(evt.PID)
	if err := p.hotCache.Add(procID); err != nil {
		log.Printf("[pipeline] cache add %s: %v", procID, err)
	}

	// Also cache file nodes if present
	if evt.Pathname != "" && evt.Pathname != "?" {
		// Use inode-based or path-hash-based ID (same scheme as graph.go)
		var fileID string
		if evt.Inode > 0 {
			fileID = provenance.NodeIDFile(evt.Inode, evt.DevMajor, evt.DevMinor)
		} else {
			fileID = provenance.NodeIDFilePath(evt.Pathname)
		}
		if err := p.hotCache.Add(fileID); err != nil {
			log.Printf("[pipeline] cache add %s: %v", fileID, err)
		}
	}
}

// mergeEdges feeds the event's derived edges to the merge window.
func (p *Pipeline) mergeEdges(evt *collector.Event) {
	// Derive edges from event (same logic as graph.go)
	edges := deriveEdges(evt)
	for _, e := range edges {
		merged := p.merger.TryMerge(e)
		if merged {
			continue
		}
		// First occurrence in window — write to RocksDB directly
		if err := p.store.PutEdge(e); err != nil {
			log.Printf("[pipeline] put edge: %v", err)
		}
	}
}

// deriveEdges converts an event to provenance edges (same mapping as graph.go).
func deriveEdges(evt *collector.Event) []*provenance.Edge {
	ts := time.Now()
	procID := provenance.NodeIDProcess(evt.PID)

	switch evt.Type {
	case syscall.EventProcessFork:
		childID := provenance.NodeIDProcess(evt.ChildPID)
		return []*provenance.Edge{
			{Source: childID, Target: procID, Relation: provenance.ProvWasInformedBy, Timestamp: ts, Count: 1},
		}

	case syscall.EventProcessExec:
		if evt.Pathname == "" || evt.Pathname == "?" {
			return nil
		}
		fileID := fileIDFromEvent(evt)
		return []*provenance.Edge{
			{Source: procID, Target: fileID, Relation: provenance.ProvUsed, Timestamp: ts, Count: 1},
		}

	case syscall.EventFileOpen:
		if evt.Pathname == "" || evt.Pathname == "?" {
			return nil
		}
		fileID := fileIDFromEvent(evt)
		return []*provenance.Edge{
			{Source: procID, Target: fileID, Relation: provenance.ProvUsed, Timestamp: ts, Count: 1},
		}

	case syscall.EventFileCreate, syscall.EventFileModify:
		if evt.Pathname == "" || evt.Pathname == "?" {
			return nil
		}
		fileID := fileIDFromEvent(evt)
		return []*provenance.Edge{
			{Source: fileID, Target: procID, Relation: provenance.ProvWasGeneratedBy, Timestamp: ts, Count: 1},
		}
	}
	return nil
}

func fileIDFromEvent(evt *collector.Event) string {
	if evt.Inode > 0 {
		return provenance.NodeIDFile(evt.Inode, evt.DevMajor, evt.DevMinor)
	}
	return provenance.NodeIDFilePath(evt.Pathname)
}

// ── Backpressure handlers ───────────────────────────────────

func (p *Pipeline) onMidPressure() {
	log.Printf("[pipeline] mid pressure — evicting cold nodes from cache")
	cnt, err := p.hotCache.EvictColdSync(256)
	if err != nil {
		log.Printf("[pipeline] eviction error: %v", err)
	}
	log.Printf("[pipeline] evicted %d cold nodes", cnt)

	// Flush merge window + RocksDB batch
	if n, err := p.merger.Flush(); err != nil {
		log.Printf("[pipeline] merge flush error: %v", err)
	} else if n > 0 {
		log.Printf("[pipeline] flushed %d merged edges", n)
	}

	if err := p.store.Flush(); err != nil {
		log.Printf("[pipeline] store flush error: %v", err)
	}
}

func (p *Pipeline) onHighPressure() {
	// Request backpressure — pause the event ingestion loop
	p.mu.Lock()
	if !p.paused {
		p.paused = true
		p.pauseCh <- struct{}{}
	metrics.PipelineBackpressure.Inc()
		log.Printf("[pipeline] HIGH PRESSURE — pausing ingestion")
	}
	p.mu.Unlock()
}

// ── Pause / Resume control ──────────────────────────────────

func (p *Pipeline) checkPause() {
	p.mu.Lock()
	if p.paused {
		// Resume after one tick of flushing
		p.paused = false
		p.onMidPressure()
		select {
		case p.resumeCh <- struct{}{}:
		default:
		}
	}
	p.mu.Unlock()
}

// PauseCh returns the channel that receives a signal when ingestion
// should pause (high memory pressure).
func (p *Pipeline) PauseCh() <-chan struct{} { return p.pauseCh }

// ResumeCh returns the channel that receives a signal when ingestion
// can resume.
func (p *Pipeline) ResumeCh() <-chan struct{} { return p.resumeCh }

// ── Lifecycle ───────────────────────────────────────────────

// Start background goroutines (periodic edge flush).
func (p *Pipeline) Start() {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			select {
			case <-p.flushTicker.C:
				if n, err := p.merger.Flush(); err != nil {
					log.Printf("[pipeline] periodic flush error: %v", err)
				} else if n > 0 {
					log.Printf("[pipeline] periodic flush: %d edges", n)
				}
			case <-p.stopCh:
				return
			}
		}
	}()
}

// Stop cleanly shuts down the pipeline (flush + close store).
func (p *Pipeline) Stop() error {
	close(p.stopCh)
	p.wg.Wait()
	p.flushTicker.Stop()
	p.pressure.Stop()

	// Final flush
	p.onMidPressure()

	return p.store.Close()
}

// ── Stats ───────────────────────────────────────────────────

func (p *Pipeline) Stats() map[string]interface{} {
	stats := map[string]interface{}{
		"cache":   p.hotCache.Stats(),
		"merger":  p.merger.Stats(),
		"store":   p.store.Stats(),
		"graph":   p.graph.Stats(),
		"paused":  p.paused,
	}
	return stats
}
