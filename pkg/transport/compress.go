// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
)

// CompressionLevel controls the compression-speed tradeoff.
type CompressionLevel int

const (
	CompressSpeed   CompressionLevel = 0 // Zstd SpeedFastest
	CompressBalance CompressionLevel = 1 // Zstd SpeedDefault
	CompressSize    CompressionLevel = 2 // Zstd SpeedBestCompression
)

// mapLevel converts our CompressionLevel to zstd.EncoderLevel.
func (cl CompressionLevel) zstd() zstd.EncoderLevel {
	switch cl {
	case CompressSpeed:
		return zstd.SpeedFastest
	case CompressSize:
		return zstd.SpeedBestCompression
	default:
		return zstd.SpeedDefault
	}
}

// Dictionary is a pre-trained Zstd dictionary for provenance data.
// Training on protobuf-encoded Node/Edge messages significantly
// improves compression of small payloads where Zstd's static window
// would otherwise have limited context.
type Dictionary struct {
	Data        []byte    `json:"data"`
	TrainedAt   time.Time `json:"trained_at"`
	SampleCount int       `json:"sample_count"`
}

// Compressor manages Zstd compression for gRPC transport.
// It caches encoder/decoder instances with optional dictionary
// to avoid per-message allocation overhead.
type Compressor struct {
	mu              sync.Mutex
	enc             *zstd.Encoder
	dec             *zstd.Decoder
	dictData        []byte // raw Zstd dictionary data
	level           CompressionLevel
	originalBytes   int64
	compressedBytes int64
}

// NewCompressor creates a transport compressor with Zstd.
func NewCompressor() *Compressor {
	c := &Compressor{level: CompressBalance}
	c.initCodecs()
	return c
}

// NewCompressorWithLevel creates a compressor with the specified level.
func NewCompressorWithLevel(level CompressionLevel) *Compressor {
	c := &Compressor{level: level}
	c.initCodecs()
	return c
}

// initCodecs creates the cached encoder and decoder.
func (c *Compressor) initCodecs() {
	// Encoder with optional dictionary
	encOpts := []zstd.EOption{
		zstd.WithEncoderLevel(c.level.zstd()),
	}
	if c.dictData != nil {
		encOpts = append(encOpts, zstd.WithEncoderDict(c.dictData))
	}
	enc, err := zstd.NewWriter(nil, encOpts...)
	if err != nil {
		log.Printf("[compress] encoder init: %v (fallback to no-dict)", err)
		enc, err = zstd.NewWriter(nil, zstd.WithEncoderLevel(c.level.zstd()))
		if err != nil {
			log.Printf("[compress] encoder fallback also failed: %v", err)
			enc = nil
		}
	}
	c.enc = enc

	// Decoder with optional dictionary
	decOpts := []zstd.DOption{}
	if c.dictData != nil {
		decOpts = append(decOpts, zstd.WithDecoderDicts(c.dictData))
	}
	dec, err := zstd.NewReader(nil, decOpts...)
	if err != nil {
		log.Printf("[compress] decoder init: %v (fallback to no-dict)", err)
		dec, err = zstd.NewReader(nil)
		if err != nil {
			log.Printf("[compress] decoder fallback also failed: %v", err)
			dec = nil
		}
	}
	c.dec = dec
}

// TrainDictionary builds a Zstd dictionary from protobuf-encoded samples.
// Recommended dict size for Zstd is 110KB (112640 bytes).
func (c *Compressor) TrainDictionary(samples [][]byte) *Dictionary {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(samples) == 0 {
		log.Println("[compress] no samples for dictionary training")
		return nil
	}

	// Train using Zstd's native dictionary trainer.
	dictData, err := zstd.BuildDict(zstd.BuildDictOptions{
		Contents: samples,
		History:  make([]byte, 112640),
		Level:    c.level.zstd(),
	})
	if err != nil {
		log.Printf("[compress] dictionary training failed: %v", err)
		return nil
	}

	c.dictData = dictData

	// Recreate codecs with the new dictionary.
	_ = c.enc.Close()
	c.dec.Close()
	c.initCodecs()

	result := &Dictionary{
		Data:        dictData,
		TrainedAt:   time.Now(),
		SampleCount: len(samples),
	}

	log.Printf("[compress] dictionary trained on %d samples (%d bytes)",
		len(samples), len(dictData))
	return result
}

// SetDict loads a pre-trained dictionary from raw bytes.
func (c *Compressor) SetDict(dictData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.dictData = dictData

	// Recreate codecs.
	_ = c.enc.Close()
	c.dec.Close()
	c.initCodecs()
	return nil
}

// DictBytes returns the serialised dictionary data, or nil if not trained.
func (c *Compressor) DictBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dictData
}

// Compress compresses data using Zstd with optional dictionary.
func (c *Compressor) Compress(data []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.enc == nil {
		return nil, fmt.Errorf("compressor not initialized")
	}
	var buf bytes.Buffer
	c.enc.Reset(&buf)
	if _, err := c.enc.Write(data); err != nil {
		return nil, fmt.Errorf("compress: %w", err)
	}
	if err := c.enc.Close(); err != nil {
		return nil, fmt.Errorf("compress close: %w", err)
	}
	compressed := buf.Bytes()

	c.originalBytes += int64(len(data))
	c.compressedBytes += int64(len(compressed))

	return compressed, nil
}

// Decompress decompresses Zstd-compressed data.
func (c *Compressor) Decompress(data []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.dec == nil {
		return nil, fmt.Errorf("decompressor not initialized")
	}
	decoded, err := c.dec.DecodeAll(data, nil)
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}
	return decoded, nil
}

// CompressProtobuf compresses a protobuf message with a 4-byte length prefix.
// Wire format: [4 bytes original length][Zstd-compressed data].
func (c *Compressor) CompressProtobuf(data []byte) ([]byte, error) {
	compressed, err := c.Compress(data)
	if err != nil {
		return nil, err
	}

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(data)))
	return append(header, compressed...), nil
}

// DecompressProtobuf decompresses a length-prefixed protobuf message.
func (c *Compressor) DecompressProtobuf(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return c.Decompress(data)
	}
	return c.Decompress(data[4:])
}

// Ratio returns the compression ratio (compressed/original × 100).
func (c *Compressor) Ratio() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.originalBytes == 0 {
		return 0
	}
	return float64(c.compressedBytes) / float64(c.originalBytes) * 100.0
}

// Stats returns compressor statistics.
func (c *Compressor) Stats() map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]interface{}{
		"original_bytes":   c.originalBytes,
		"compressed_bytes": c.compressedBytes,
		"ratio":            fmt.Sprintf("%.1f%%", float64(c.compressedBytes)/float64(c.originalBytes+1)*100),
		"dict_trained":     c.dictData != nil,
		"level":            c.level,
	}
}

// Close releases encoder/decoder resources.
func (c *Compressor) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.enc != nil {
		_ = c.enc.Close()
	}
	if c.dec != nil {
		c.dec.Close()
	}
	return nil
}
