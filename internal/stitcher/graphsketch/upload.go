package graphsketch

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════════
// Feature vector upload — compressed transmission to central server
//
// Design:
//   - Vectors are buffered and periodically flushed (default 60s).
//   - Each batch is JSON-serialized and gzip-compressed (< 1KB typical).
//   - An UploadSender interface allows plugging into any transport
//     (gRPC, HTTP, or the existing TransportManager).
//   - When an anomaly is detected, the buffer is flushed immediately
//     and the optional ForceUpload callback fires.
// ═══════════════════════════════════════════════════════════════════

// UploadSender sends serialized feature vector payloads.
type UploadSender interface {
	// SendPayload transmits a compressed feature vector batch.
	// The data is a gzip-compressed JSON blob.
	SendPayload(data []byte) error

	// SendFullGraph signals that full graph data should be uploaded
	// (called on entropy anomaly when ForceUploadOnAnomaly is true).
	SendFullGraph(reason string) error
}

// UploadConfig configures the feature vector uploader.
type UploadConfig struct {
	// HostID identifies this agent.
	HostID string

	// AgentID identifies this agent instance.
	AgentID string

	// FlushInterval is how often buffered vectors are sent (default 60s).
	FlushInterval time.Duration

	// BatchSize is the maximum vectors per upload (default 50).
	BatchSize int

	// CompressionLevel for gzip (default gzip.DefaultCompression).
	CompressionLevel int

	// EnableUpload enables periodic upload (default true).
	EnableUpload bool
}

// DefaultUploadConfig returns defaults.
func DefaultUploadConfig() *UploadConfig {
	return &UploadConfig{
		FlushInterval:    60 * time.Second,
		BatchSize:        50,
		CompressionLevel: gzip.DefaultCompression,
		EnableUpload:     true,
	}
}

// VectorUploader buffers feature vectors and sends them to the
// central server in compressed batches.
type VectorUploader struct {
	cfg    *UploadConfig
	sender UploadSender

	mu      sync.Mutex
	buffer  []*GraphFeatureVector
	stopCh  chan struct{}
	wg      sync.WaitGroup
	done    chan struct{}

	// Statistics.
	totalSent     int64
	totalBatches  int64
	totalBytes    int64
	anomalyCount  int64
}

// NewVectorUploader creates a vector uploader.
func NewVectorUploader(cfg *UploadConfig, sender UploadSender) *VectorUploader {
	if cfg == nil {
		cfg = DefaultUploadConfig()
	}
	return &VectorUploader{
		cfg:    cfg,
		sender: sender,
		buffer: make([]*GraphFeatureVector, 0, cfg.BatchSize),
		stopCh: make(chan struct{}),
		done:   make(chan struct{}),
	}
}

// Start begins the periodic flush loop.
func (vu *VectorUploader) Start() {
	if !vu.cfg.EnableUpload {
		return
	}
	vu.wg.Add(1)
	go vu.flushLoop()
	log.Printf("[graphsketch] uploader started (interval=%v, batch=%d)",
		vu.cfg.FlushInterval, vu.cfg.BatchSize)
}

// Stop terminates the flush loop and flushes remaining vectors.
func (vu *VectorUploader) Stop() {
	close(vu.stopCh)
	vu.wg.Wait()
	// Final flush of remaining vectors.
	vu.Flush()
	close(vu.done)
}

// Done returns a channel that's closed when the uploader has fully stopped.
func (vu *VectorUploader) Done() <-chan struct{} {
	return vu.done
}

// Enqueue adds a feature vector to the upload buffer.
// If the buffer reaches BatchSize, a flush is triggered.
func (vu *VectorUploader) Enqueue(fv *GraphFeatureVector) {
	if fv == nil || !vu.cfg.EnableUpload {
		return
	}

	vu.mu.Lock()
	vu.buffer = append(vu.buffer, fv)
	shouldFlush := len(vu.buffer) >= vu.cfg.BatchSize
	vu.mu.Unlock()

	if shouldFlush {
		vu.Flush()
	}
}

// Flush sends all buffered vectors immediately.
func (vu *VectorUploader) Flush() {
	vu.mu.Lock()
	batch := vu.buffer
	vu.buffer = make([]*GraphFeatureVector, 0, vu.cfg.BatchSize)
	vu.mu.Unlock()

	if len(batch) == 0 || vu.sender == nil {
		return
	}

	vecs := make([]GraphFeatureVector, len(batch))
	for i, p := range batch {
		vecs[i] = *p
	}
	payload := &UploadPayload{
		HostID:    vu.cfg.HostID,
		AgentID:   vu.cfg.AgentID,
		Vectors:   vecs,
		BatchSize: len(vecs),
		SentAt:    time.Now().UnixNano(),
	}

	data, err := serializePayload(payload, vu.cfg.CompressionLevel)
	if err != nil {
		log.Printf("[graphsketch] serialize error: %v", err)
		return
	}

	if err := vu.sender.SendPayload(data); err != nil {
		log.Printf("[graphsketch] send error: %v", err)
		// Re-queue on failure.
		vu.mu.Lock()
		vu.buffer = append(batch, vu.buffer...)
		// Trim to batch size limit.
		if len(vu.buffer) > vu.cfg.BatchSize*2 {
			vu.buffer = vu.buffer[:vu.cfg.BatchSize]
		}
		vu.mu.Unlock()
		return
	}

	vu.mu.Lock()
	vu.totalSent += int64(len(batch))
	vu.totalBatches++
	vu.totalBytes += int64(len(data))
	vu.mu.Unlock()

	log.Printf("[graphsketch] uploaded %d vectors (%d bytes, batch #%d)",
		len(batch), len(data), vu.totalBatches)
}

// ── Anomaly callback ─────────────────────────────────────────────

// AnomalyHandler creates an AnomalyCallback that forces an immediate
// flush and optionally triggers full graph upload.
func (vu *VectorUploader) AnomalyHandler() AnomalyCallback {
	return func(result *EntropyResult, fv *GraphFeatureVector) {
		vu.mu.Lock()
		vu.anomalyCount++
		vu.mu.Unlock()

		log.Printf("[graphsketch] ANOMALY: KL=%.4f (mean=%.4f, stddev=%.4f) reason=%s",
			result.KLDivergence, result.KLMean, result.KLStdDev, result.Reason)

		// Immediately enqueue the anomalous vector.
		vu.Enqueue(fv)

		// Force flush.
		vu.Flush()

		// Signal full graph upload.
		if vu.sender != nil {
			if err := vu.sender.SendFullGraph(result.Reason); err != nil {
				log.Printf("[graphsketch] SendFullGraph error: %v", err)
			}
		}
	}
}

// ── Serialization ────────────────────────────────────────────────

func serializePayload(payload *UploadPayload, compressionLevel int) ([]byte, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("json marshal: %w", err)
	}

	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, compressionLevel)
	if err != nil {
		return nil, fmt.Errorf("gzip init: %w", err)
	}

	if _, err := w.Write(jsonData); err != nil {
		return nil, fmt.Errorf("gzip write: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("gzip close: %w", err)
	}

	return buf.Bytes(), nil
}

// DeserializePayload decompresses and decodes an upload payload.
func DeserializePayload(data []byte) (*UploadPayload, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer r.Close()

	var payload UploadPayload
	if err := json.NewDecoder(r).Decode(&payload); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}

	return &payload, nil
}

// ── Default sender: logs to stdout ───────────────────────────────

// LogSender is a no-op UploadSender that logs payloads.
// Useful for testing and when no transport is configured.
type LogSender struct {
	// OnFullGraph, if set, is called when SendFullGraph is invoked.
	OnFullGraph func(reason string)
}

// NewLogSender creates a logging sender.
func NewLogSender() *LogSender {
	return &LogSender{}
}

func (s *LogSender) SendPayload(data []byte) error {
	log.Printf("[graphsketch] payload %d bytes (LogSender — replace with real transport)", len(data))
	return nil
}

func (s *LogSender) SendFullGraph(reason string) error {
	log.Printf("[graphsketch] FULL GRAPH UPLOAD triggered: %s", reason)
	if s.OnFullGraph != nil {
		s.OnFullGraph(reason)
	}
	return nil
}

// ── Flush loop ───────────────────────────────────────────────────

func (vu *VectorUploader) flushLoop() {
	defer vu.wg.Done()

	ticker := time.NewTicker(vu.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			vu.Flush()
		case <-vu.stopCh:
			return
		}
	}
}

// ── Stats ────────────────────────────────────────────────────────

// Stats returns upload statistics.
func (vu *VectorUploader) Stats() map[string]interface{} {
	vu.mu.Lock()
	defer vu.mu.Unlock()

	return map[string]interface{}{
		"total_sent":     vu.totalSent,
		"total_batches":  vu.totalBatches,
		"total_bytes":    vu.totalBytes,
		"buffer_size":    len(vu.buffer),
		"anomaly_count":  vu.anomalyCount,
	}
}

