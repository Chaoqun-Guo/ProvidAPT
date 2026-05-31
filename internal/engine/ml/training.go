package ml

import (
	"encoding/csv"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/Chaoqun-Guo/ProvidAPT/internal/engine/provenance"
)

// ═══════════════════════════════════════════════════════════════
// Training data generation
//
// Samples normal behaviour from the provenance graph during a
// training period.  Produces feature vectors that represent the
// "normal" structural patterns of the system.
// ═══════════════════════════════════════════════════════════════

// TrainingConfig controls the training data generation.
type TrainingConfig struct {
	// SamplingMethod: "window" = sliding time window, "node" = per-node
	SamplingMethod string

	// WindowDuration for sliding window sampling.
	WindowDuration time.Duration

	// MaxSamples is the maximum number of feature vectors to collect.
	MaxSamples int

	// OutputFile for saving the training data (CSV).
	OutputFile string
}

// DefaultTrainingConfig returns sensible defaults.
func DefaultTrainingConfig() *TrainingConfig {
	return &TrainingConfig{
		SamplingMethod: "window",
		WindowDuration: 5 * time.Minute,
		MaxSamples:     10000,
		OutputFile:     "/var/lib/providapt/training_data.csv",
	}
}

// ── Sampling ────────────────────────────────────────────────

// SampleFromGraph extracts feature vectors from subgraphs centered
// on process nodes.  Each process node with its 1-hop neighborhood
// (direct edges) produces one training sample.
func SampleFromGraph(graph *provenance.Graph, maxSamples int) []FeatureVector {
	nodes := graph.Nodes()
	edges := graph.Edges()

	if len(nodes) == 0 {
		return nil
	}

	// Build adjacency index
	adj := make(map[string][]*provenance.Edge)
	for _, e := range edges {
		adj[e.Source] = append(adj[e.Source], e)
		adj[e.Target] = append(adj[e.Target], e)
	}

	var samples []FeatureVector
	for _, n := range nodes {
		if n.Subtype != "process" {
			continue
		}
		if maxSamples > 0 && len(samples) >= maxSamples {
			break
		}

		// Build 1-hop neighborhood: the process + all connected nodes
		subgraph := buildSubgraph(n.ID, adj)

		if len(subgraph.nodes) < 2 {
			continue
		}

		fv := ExtractFeatures(subgraph.nodes, subgraph.edges)
		samples = append(samples, fv)
	}

	return samples
}

// subgraph holds a set of nodes and edges.
type subgraph struct {
	nodes []*provenance.Node
	edges []*provenance.Edge
}

// buildSubgraph creates a subgraph containing the seed node and
// all its 1-hop neighbours.
func buildSubgraph(seedID string, adj map[string][]*provenance.Edge) *subgraph {
	seen := map[string]bool{seedID: true}
	var edges []*provenance.Edge

	// Add all edges from seed
	for _, e := range adj[seedID] {
		edges = append(edges, e)
		seen[e.Source] = true
		seen[e.Target] = true
	}

	// Build node list
	nodes := make([]*provenance.Node, 0, len(seen))
	for id := range seen {
		// In a real implementation, we'd look up the Node
		// from the graph.  Here we create minimal placeholders.
		nodes = append(nodes, &provenance.Node{ID: id})
	}

	return &subgraph{nodes: nodes, edges: edges}
}

// ── Persistence ─────────────────────────────────────────────

// SaveTrainingData writes feature vectors to a CSV file.
func SaveTrainingData(samples []FeatureVector, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	// Header
	names := FeatureNames()
	header := make([]string, int(NumFeatures)+1)
	header[0] = "timestamp"
	for i := 0; i < int(NumFeatures); i++ {
		header[i+1] = names[i]
	}
	writer.Write(header)

	// Data
	for _, fv := range samples {
		row := make([]string, int(NumFeatures)+1)
		row[0] = time.Now().UTC().Format(time.RFC3339)
		for i := 0; i < int(NumFeatures); i++ {
			row[i+1] = strconv.FormatFloat(fv[i], 'g', 4, 64)
		}
		writer.Write(row)
	}

	return nil
}

// LoadTrainingData reads feature vectors from a CSV file.
func LoadTrainingData(path string) ([]FeatureVector, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	if len(records) < 2 {
		return nil, fmt.Errorf("no data rows in %s", path)
	}

	var samples []FeatureVector
	for _, row := range records[1:] { // skip header
		if len(row) < int(NumFeatures)+1 {
			continue
		}
		var fv FeatureVector
		for i := 0; i < int(NumFeatures); i++ {
			fv[i], _ = strconv.ParseFloat(row[i+1], 64)
		}
		samples = append(samples, fv)
	}
	return samples, nil
}

// ── Normalisation bounds ────────────────────────────────────

// ComputeBounds computes min/max for each feature across samples.
func ComputeBounds(samples []FeatureVector) (mins, maxs [NumFeatures]float64) {
	if len(samples) == 0 {
		return
	}
	for i := 0; i < int(NumFeatures); i++ {
		mins[i] = math.MaxFloat64
		maxs[i] = -math.MaxFloat64
	}
	for _, fv := range samples {
		for i := 0; i < int(NumFeatures); i++ {
			if fv[i] < mins[i] {
				mins[i] = fv[i]
			}
			if fv[i] > maxs[i] {
				maxs[i] = fv[i]
			}
		}
	}
	return
}

// ── Training pipeline ───────────────────────────────────────

// TrainModelFromGraph samples the graph, trains the detector, and
// returns the trained model with statistics.
func TrainModelFromGraph(graph *provenance.Graph, cfg *TrainingConfig, detector AnomalyDetector) (*TrainingReport, error) {
	if cfg == nil {
		cfg = DefaultTrainingConfig()
	}

	log.Printf("[ml] sampling graph for training...")
	samples := SampleFromGraph(graph, cfg.MaxSamples)
	if len(samples) == 0 {
		return nil, fmt.Errorf("no training samples could be extracted")
	}
	log.Printf("[ml] extracted %d training samples", len(samples))

	if err := detector.Train(samples); err != nil {
		return nil, fmt.Errorf("train: %w", err)
	}
	log.Printf("[ml] model trained successfully")

	// Compute bounds for normalisation
	mins, maxs := ComputeBounds(samples)

	report := &TrainingReport{
		NumSamples:   len(samples),
		FeatureNames: FeatureNames(),
		MinValues:    mins,
		MaxValues:    maxs,
		MeanScore:    computeMeanScore(samples, detector),
		StdScore:     computeStdScore(samples, detector),
	}

	log.Printf("[ml] training report: %d samples, mean_score=%.4f, std_score=%.4f",
		report.NumSamples, report.MeanScore, report.StdScore)

	// Save training data if output file configured
	if cfg.OutputFile != "" {
		if err := SaveTrainingData(samples, cfg.OutputFile); err != nil {
			log.Printf("[ml] save training data: %v", err)
		}
	}

	return report, nil
}

// TrainingReport summarises the training results.
type TrainingReport struct {
	NumSamples   int
	FeatureNames [NumFeatures]string
	MinValues    [NumFeatures]float64
	MaxValues    [NumFeatures]float64
	MeanScore    float64
	StdScore     float64
}

func computeMeanScore(samples []FeatureVector, d AnomalyDetector) float64 {
	var total float64
	for _, s := range samples {
		total += d.Predict(s)
	}
	return total / float64(len(samples))
}

func computeStdScore(samples []FeatureVector, d AnomalyDetector) float64 {
	mean := computeMeanScore(samples, d)
	var sumSq float64
	for _, s := range samples {
		diff := d.Predict(s) - mean
		sumSq += diff * diff
	}
	return math.Sqrt(sumSq / float64(len(samples)))
}
