package analyzer

import (
	"log"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
	"github.com/Chaoqun-Guo/ProvidAPT/internal/stitcher/graphsketch"
)

// ═══════════════════════════════════════════════════════════════════
// Graph sketching integration — computes feature vectors during
// each analyzer scan and uploads them to the central server.
//
// Usage:
//
//	si := NewSketchIntegrator(cfg)
//	analyzer.SetSketchIntegrator(si)
//	analyzer.Start()
//	defer si.Stop()
// ═══════════════════════════════════════════════════════════════════

// SketchIntegrator wraps the graphsketch module for use by the analyzer.
// It converts v1 provenance snapshots into feature vectors, evaluates
// entropy against the historical baseline, and uploads vectors.
type SketchIntegrator struct {
	computer *graphsketch.SketchComputer
	detector *graphsketch.EntropyDetector
	uploader *graphsketch.VectorUploader
}

// SketchConfig configures the sketch integrator.
type SketchConfig struct {
	// Enabled enables graph sketching during scan loops.
	Enabled bool

	// EntropyCfg configures the entropy detector (nil = defaults).
	EntropyCfg *graphsketch.EntropyConfig

	// UploadCfg configures the vector uploader (nil = defaults).
	UploadCfg *graphsketch.UploadConfig

	// UploadSender is the transport for sending feature vectors.
	// If nil, a LogSender is used (logs only, no network).
	UploadSender graphsketch.UploadSender
}

// DefaultSketchConfig returns a default sketch configuration.
func DefaultSketchConfig() *SketchConfig {
	return &SketchConfig{
		Enabled:    true,
		EntropyCfg: graphsketch.DefaultEntropyConfig(),
		UploadCfg:  graphsketch.DefaultUploadConfig(),
	}
}

// NewSketchIntegrator creates an integrator wrapping the graphsketch
// computer, entropy detector, and vector uploader.
func NewSketchIntegrator(cfg *SketchConfig) *SketchIntegrator {
	if cfg == nil {
		cfg = DefaultSketchConfig()
	}

	sender := cfg.UploadSender
	if sender == nil {
		sender = graphsketch.NewLogSender()
	}

	uploadCfg := cfg.UploadCfg
	if uploadCfg == nil {
		uploadCfg = graphsketch.DefaultUploadConfig()
	}

	detector := graphsketch.NewEntropyDetector(cfg.EntropyCfg)
	uploader := graphsketch.NewVectorUploader(uploadCfg, sender)

	// Wire anomaly callback: flush uploader on entropy spike.
	detector.SetCallback(uploader.AnomalyHandler())

	return &SketchIntegrator{
		computer: graphsketch.NewSketchComputer(),
		detector: detector,
		uploader: uploader,
	}
}

// ProcessSnapshot converts a provenance graph snapshot to a feature
// vector, evaluates entropy, and enqueues the result for upload.
//
// This is called from the analyzer's scan loop.
func (si *SketchIntegrator) ProcessSnapshot(snap *Snapshot) *graphsketch.GraphFeatureVector {
	if snap == nil || len(snap.Nodes) == 0 {
		return nil
	}

	// 1. Convert snapshot to sketch-compatible types.
	sketchNodes := make([]graphsketch.SketchNode, 0, len(snap.Nodes))
	for _, n := range snap.Nodes {
		sketchNodes = append(sketchNodes, graphsketch.SketchNode{
			ID:   n.ID,
			Type: n.Subtype,
		})
	}

	sketchEdges := make([]graphsketch.SketchEdge, 0, len(snap.Edges))
	for _, e := range snap.Edges {
		sketchEdges = append(sketchEdges, graphsketch.SketchEdge{
			Source:   e.Source,
			Target:   e.Target,
			Relation: e.Relation,
		})
	}

	// 2. Compute feature vector.
	fv := si.computer.Compute(sketchNodes, sketchEdges)

	// 3. Evaluate entropy against baseline.
	si.detector.Evaluate(fv)

	// 4. Enqueue vector for upload.
	si.uploader.Enqueue(fv)

	return fv
}

// ProcessGraph is a convenience method that takes a *provenance.Graph
// directly, creates a snapshot internally, and processes it.
func (si *SketchIntegrator) ProcessGraph(g *provenance.Graph) *graphsketch.GraphFeatureVector {
	if g == nil {
		return nil
	}
	return si.ProcessSnapshot(SnapshotFromGraph(g))
}

// Start starts the uploader's periodic flush loop.
func (si *SketchIntegrator) Start() {
	si.uploader.Start()
	log.Println("[sketch] integrator started")
}

// Stop stops the uploader and flushes remaining vectors.
func (si *SketchIntegrator) Stop() {
	si.uploader.Stop()
	log.Println("[sketch] integrator stopped")
}

// Detector returns the underlying entropy detector for diagnostics.
func (si *SketchIntegrator) Detector() *graphsketch.EntropyDetector {
	return si.detector
}

// Uploader returns the underlying vector uploader for diagnostics.
func (si *SketchIntegrator) Uploader() *graphsketch.VectorUploader {
	return si.uploader
}

// ── Analyzer integration ─────────────────────────────────────────

// SetSketchIntegrator attaches a sketch integrator to the analyzer.
// The integrator's ProcessSnapshot is called automatically during
// each scan cycle. Must be called before Start().
func (a *Analyzer) SetSketchIntegrator(si *SketchIntegrator) {
	a.sketchIntegrator = si
}

