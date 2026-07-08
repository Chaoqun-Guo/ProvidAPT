// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package graphsketch computes lightweight graph feature vectors (sketches)
// from provenance graphs for local anomaly detection and compressed upload
// to the central server for global clustering analysis.
//
// Overview:
//
//	Graph Snapshot → SketchComputer → FeatureVector → Serialize → Upload
//	                                  ↓
//	                           EntropyDetector (KL vs baseline)
//	                                  ↓
//	                           Anomaly? → Force full data upload
package graphsketch

// ─────────────────────────────────────────────────────────────────
// Graph input types
// ─────────────────────────────────────────────────────────────────

// SketchNode is a minimal node representation for sketch computation.
type SketchNode struct {
	ID   string `json:"id"`
	Type string `json:"type"` // "process", "file", "network", "memory", "pipe"
}

// SketchEdge is a minimal edge representation for sketch computation.
type SketchEdge struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Relation string `json:"relation"` // "prov:used", "prov:wasGeneratedBy", "prov:wasInformedBy", "prov:wasDerivedFrom"
}

// ─────────────────────────────────────────────────────────────────
// Degree distribution
// ─────────────────────────────────────────────────────────────────

// DegreeInfo holds degree information for a single node.
type DegreeInfo struct {
	NodeID    string `json:"node_id"`
	InDegree  int    `json:"in_degree"`
	OutDegree int    `json:"out_degree"`
	Total     int    `json:"total"`
}

// DegreeDistribution is a histogram mapping degree → number of nodes.
type DegreeDistribution map[int]int

// DistributionStats summarizes a degree distribution.
type DistributionStats struct {
	Min    int     `json:"min"`
	Max    int     `json:"max"`
	Mean   float64 `json:"mean"`
	Median int     `json:"median"`
	StdDev float64 `json:"std_dev"`
}

// ─────────────────────────────────────────────────────────────────
// Path statistics
// ─────────────────────────────────────────────────────────────────

// PathStats summarizes path properties of the graph.
type PathStats struct {
	MaxDepth         int      `json:"max_depth"`
	AvgDepth         float64  `json:"avg_depth"`
	ComponentCount   int      `json:"component_count"`
	LongestPathNodes []string `json:"longest_path_nodes,omitempty"`
}

// ─────────────────────────────────────────────────────────────────
// Feature vector — the main output of graph sketching
// ─────────────────────────────────────────────────────────────────

// GraphFeatureVector is a compact numeric representation of a
// provenance graph snapshot for anomaly detection and upload.
type GraphFeatureVector struct {
	// Timestamp of the snapshot.
	TimestampNS int64 `json:"ts_ns"`

	// Size metrics.
	NodeCount int `json:"node_count"`
	EdgeCount int `json:"edge_count"`

	// Global graph metrics.
	Density    float64 `json:"density"`
	InOutRatio float64 `json:"in_out_ratio"`

	// Degree distribution.
	DegreeDist     DegreeDistribution `json:"degree_dist,omitempty"`
	InDegreeDist   DegreeDistribution `json:"in_degree_dist,omitempty"`
	OutDegreeDist  DegreeDistribution `json:"out_degree_dist,omitempty"`
	DegreeStats    DistributionStats  `json:"degree_stats"`
	InDegreeStats  DistributionStats  `json:"in_degree_stats"`
	OutDegreeStats DistributionStats  `json:"out_degree_stats"`

	// Path statistics.
	PathStats PathStats `json:"path_stats"`

	// Node type distribution: "process" → count, "file" → count, etc.
	NodeTypeDist map[string]int `json:"node_type_dist,omitempty"`

	// Edge relation distribution: "prov:used" → count, etc.
	EdgeTypeDist map[string]int `json:"edge_type_dist,omitempty"`

	// Entropy metrics (filled by EntropyDetector).
	EntropyScore  float64 `json:"entropy_score,omitempty"`
	KLDivergence  float64 `json:"kl_divergence,omitempty"`
	IsAnomaly     bool    `json:"is_anomaly,omitempty"`
	AnomalyReason string  `json:"anomaly_reason,omitempty"`
}

// ─────────────────────────────────────────────────────────────────
// Entropy baseline
// ─────────────────────────────────────────────────────────────────

// EdgeTypeBaseline tracks the historical distribution of edge types.
type EdgeTypeBaseline struct {
	// Smoothed probabilities (exponential moving average).
	Probabilities map[string]float64 `json:"probs"`
	// Number of updates applied (for warm-up).
	Count int `json:"count"`
	// Smoothing factor α (0.0–1.0), higher = more weight on recent data.
	Alpha float64 `json:"alpha"`
}

// NewEdgeTypeBaseline creates a baseline with the given smoothing factor.
// Alpha=0.3 means 30% weight on new observations, 70% on history.
func NewEdgeTypeBaseline(alpha float64) *EdgeTypeBaseline {
	return &EdgeTypeBaseline{
		Probabilities: make(map[string]float64),
		Alpha:         alpha,
	}
}

// DefaultEdgeTypeBaseline returns a baseline with α=0.3.
func DefaultEdgeTypeBaseline() *EdgeTypeBaseline {
	return NewEdgeTypeBaseline(0.3)
}

// EntropyConfig configures entropy anomaly detection.
type EntropyConfig struct {
	// Alpha is the EMA smoothing factor for baseline updates (default 0.3).
	Alpha float64

	// AnomalyThreshold is the number of standard deviations above the
	// moving-average KL divergence that triggers an anomaly (default 3.0).
	AnomalyThreshold float64

	// MinWindows is the minimum number of windows before anomaly detection
	// activates (default 5).
	MinWindows int

	// HistorySize is the number of recent KL values kept for std-dev
	// calculation (default 20).
	HistorySize int

	// ForceUploadOnAnomaly triggers full data upload when entropy spikes.
	ForceUploadOnAnomaly bool
}

// DefaultEntropyConfig returns sensible defaults.
func DefaultEntropyConfig() *EntropyConfig {
	return &EntropyConfig{
		Alpha:                0.3,
		AnomalyThreshold:     3.0,
		MinWindows:           5,
		HistorySize:          20,
		ForceUploadOnAnomaly: true,
	}
}

// EntropyResult is returned by the entropy detector after evaluation.
type EntropyResult struct {
	KLDivergence float64 `json:"kl_divergence"`
	IsAnomaly    bool    `json:"is_anomaly"`
	Reason       string  `json:"reason,omitempty"`

	// Running stats for diagnostics.
	KLMean    float64 `json:"kl_mean"`
	KLStdDev  float64 `json:"kl_stddev"`
	WindowNum int     `json:"window_num"`
}

// ─────────────────────────────────────────────────────────────────
// Upload payload
// ─────────────────────────────────────────────────────────────────

// UploadPayload is the wire format for sending feature vectors
// to the central server for global clustering analysis.
type UploadPayload struct {
	HostID    string               `json:"host_id"`
	AgentID   string               `json:"agent_id"`
	Vectors   []GraphFeatureVector `json:"vectors"`
	BatchSize int                  `json:"batch_size"`
	SentAt    int64                `json:"sent_at_ns"`
}

// ─────────────────────────────────────────────────────────────────
// Anomaly callback
// ─────────────────────────────────────────────────────────────────

// AnomalyCallback is invoked when the entropy detector finds an anomaly.
type AnomalyCallback func(result *EntropyResult, vector *GraphFeatureVector)
