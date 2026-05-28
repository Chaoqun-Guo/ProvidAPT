package ml

import (
	"log"

	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/provenance"
)

// ═══════════════════════════════════════════════════════════════
// Anomaly detection orchestrator
// ═══════════════════════════════════════════════════════════════

// DetectorConfig for the anomaly detection orchestrator.
type DetectorConfig struct {
	// AnomalyThreshold — score above this is flagged as anomalous.
	AnomalyThreshold float64

	// StrongAnomalyThreshold — score above this is a strong signal.
	StrongAnomalyThreshold float64

	// MinSubgraphNodes — skip subgraphs smaller than this.
	MinSubgraphNodes int

	// UseIsolationForest — if false, use statistical detector.
	UseIsolationForest bool
}

// DefaultDetectorConfig returns sensible defaults.
func DefaultDetectorConfig() *DetectorConfig {
	return &DetectorConfig{
		AnomalyThreshold:       0.55,
		StrongAnomalyThreshold: 0.65,
		MinSubgraphNodes:       3,
		UseIsolationForest:     true,
	}
}

// DetectorResult is returned by the detector for each analysed subgraph.
type DetectorResult struct {
	SubgraphRoot string       `json:"subgraph_root"`
	Features     FeatureVector `json:"features"`
	AnomalyScore float64       `json:"anomaly_score"`
	IsAnomaly    bool          `json:"is_anomaly"`
	IsStrong     bool          `json:"is_strong"`
}

// MLDetector orchestrates the full anomaly detection pipeline.
type MLDetector struct {
	cfg      *DetectorConfig
	detector AnomalyDetector
	trained  bool
}

// NewDetector creates an ML-based anomaly detector.
func NewDetector(cfg *DetectorConfig, detector AnomalyDetector) *MLDetector {
	if cfg == nil {
		cfg = DefaultDetectorConfig()
	}
	return &MLDetector{
		cfg:      cfg,
		detector: detector,
	}
}

// IsTrained returns true if the model has been trained.
func (md *MLDetector) IsTrained() bool {
	return md.trained
}

// Train from graph samples.
func (md *MLDetector) Train(graph *provenance.Graph) error {
	samples := SampleFromGraph(graph, 5000)
	if len(samples) == 0 {
		return nil
	}
	if err := md.detector.Train(samples); err != nil {
		return err
	}
	md.trained = true
	log.Printf("[ml] detector trained on %d samples", len(samples))
	return nil
}

// AnalyseSubgraph extracts features from a subgraph and scores it.
func (md *MLDetector) AnalyseSubgraph(nodes []*provenance.Node, edges []*provenance.Edge) *DetectorResult {
	if len(nodes) < md.cfg.MinSubgraphNodes {
		return nil
	}

	fv := ExtractFeatures(nodes, edges)
	score := md.detector.Predict(fv)

	root := ""
	if len(nodes) > 0 {
		root = nodes[0].ID
	}

	return &DetectorResult{
		SubgraphRoot: root,
		Features:     fv,
		AnomalyScore: score,
		IsAnomaly:    score >= md.cfg.AnomalyThreshold,
		IsStrong:     score >= md.cfg.StrongAnomalyThreshold,
	}
}

// AnalyseProcessSubgraph analyses the 1-hop neighbourhood of a process.
func (md *MLDetector) AnalyseProcessSubgraph(procID string, graph *provenance.Graph) *DetectorResult {
	edges := graph.Edges()
	var relevant []*provenance.Edge
	seenNodes := map[string]bool{procID: true}

	for _, e := range edges {
		if e.Source == procID || e.Target == procID {
			relevant = append(relevant, e)
			seenNodes[e.Source] = true
			seenNodes[e.Target] = true
		}
	}

	var nodes []*provenance.Node
	for id := range seenNodes {
		n, ok := graph.LookupNode(id)
		if ok && n != nil {
			nodes = append(nodes, n)
		} else {
			nodes = append(nodes, &provenance.Node{ID: id})
		}
	}

	return md.AnalyseSubgraph(nodes, relevant)
}

// AnalyseGraph partitions the full graph into per-process subgraphs
// and scores each one.
func (md *MLDetector) AnalyseGraph(graph *provenance.Graph) []*DetectorResult {
	nodes := graph.Nodes()
	var results []*DetectorResult

	for _, n := range nodes {
		if n.Subtype != "process" {
			continue
		}
		result := md.AnalyseProcessSubgraph(n.ID, graph)
		if result != nil {
			results = append(results, result)
		}
	}
	return results
}

// GlobalStats returns anomaly score statistics across the graph.
func (md *MLDetector) GlobalStats(graph *provenance.Graph) map[string]float64 {
	results := md.AnalyseGraph(graph)
	if len(results) == 0 {
		return map[string]float64{"count": 0}
	}
	var total, max, anomalyCount float64
	for _, r := range results {
		total += r.AnomalyScore
		if r.AnomalyScore > max {
			max = r.AnomalyScore
		}
		if r.IsAnomaly {
			anomalyCount++
		}
	}
	return map[string]float64{
		"count":          float64(len(results)),
		"mean_score":     total / float64(len(results)),
		"max_score":      max,
		"anomaly_count":  anomalyCount,
		"anomaly_ratio":  anomalyCount / float64(len(results)),
	}
}
