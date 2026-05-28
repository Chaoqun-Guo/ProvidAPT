package ml

import (
	"math"
	"math/rand"
	"testing"

	"github.com/Chaoqun-Guo/ProvidAPT/userspace/internal/syscall"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/collector"
	"github.com/Chaoqun-Guo/ProvidAPT/userspace/pkg/provenance"
)

// ── Feature extraction tests ─────────────────────────────────

func TestExtractFeaturesBasic(t *testing.T) {
	nodes := []*provenance.Node{
		{ID: "p:1", Subtype: "process"},
		{ID: "f:100", Subtype: "file"},
	}
	edges := []*provenance.Edge{
		{Source: "p:1", Target: "f:100", Relation: "prov:used"},
	}
	fv := ExtractFeatures(nodes, edges)

	if fv[FiNodeCount] != 2 {
		t.Errorf("node_count = %.0f", fv[FiNodeCount])
	}
	if fv[FiEdgeCount] != 1 {
		t.Errorf("edge_count = %.0f", fv[FiEdgeCount])
	}
	if fv[FiProcessRatio] != 0.5 {
		t.Errorf("process_ratio = %.2f", fv[FiProcessRatio])
	}
	if fv[FiFileRatio] != 0.5 {
		t.Errorf("file_ratio = %.2f", fv[FiFileRatio])
	}
}

func TestExtractFeaturesComplex(t *testing.T) {
	// Simulate an APT attack pattern: many edges, high network ratio
	edges := make([]*provenance.Edge, 20)
	for i := 0; i < 20; i++ {
		edges[i] = &provenance.Edge{
			Source: "p:1", Target: "f:100",
			Relation: "prov:wasGeneratedBy",
		}
	}
	// Add a fork chain
	edges = append(edges, &provenance.Edge{
		Source: "p:2", Target: "p:1", Relation: "prov:wasInformedBy",
	})

	nodes := []*provenance.Node{
		{ID: "p:1", Subtype: "process"},
		{ID: "p:2", Subtype: "process"},
		{ID: "f:100", Subtype: "file"},
	}

	fv := ExtractFeatures(nodes, edges)
	if fv[FiGeneratedByRatio] == 0 {
		t.Error("generated_by_ratio should be > 0")
	}
	if fv[FiGraphDensity] == 0 {
		t.Error("density should be > 0")
	}
	t.Logf("complex graph: density=%.3f avg_deg=%.1f entropy=%.3f",
		fv[FiGraphDensity], fv[FiAvgDegree], fv[FiInteractionEntropy])
}

func TestExtractFeaturesEmpty(t *testing.T) {
	fv := ExtractFeatures(nil, nil)
	for i := 0; i < NumFeatures; i++ {
		if fv[i] != 0 {
			t.Errorf("feature[%d] = %f, want 0", i, fv[i])
		}
	}
}

func TestFeatureDistance(t *testing.T) {
	a := FeatureVector{1, 2, 3}
	b := FeatureVector{1, 2, 3}
	if a.Distance(b) != 0 {
		t.Errorf("same vector distance = %f", a.Distance(b))
	}
}

func TestNormalise(t *testing.T) {
	fv := FeatureVector{50, 100, 200}
	mins := FeatureVector{0, 0, 0}
	maxs := FeatureVector{100, 200, 400}
	fv.Normalise(mins, maxs)
	if math.Abs(fv[0]-0.5) > 0.01 {
		t.Errorf("normalised[0] = %f", fv[0])
	}
}

// ── Statistical detector tests ──────────────────────────────

func TestStatisticalDetector(t *testing.T) {
	sd := &StatisticalDetector{}
	samples := []FeatureVector{
		{1, 2, 3},
		{2, 3, 4},
		{1, 2, 3},
		{2, 3, 4},
	}
	if err := sd.Train(samples); err != nil {
		t.Fatalf("Train: %v", err)
	}

	// Normal sample should have low score
	normal := FeatureVector{1.5, 2.5, 3.5}
	score := sd.Predict(normal)
	if score > 0.5 {
		t.Errorf("normal score = %.3f", score)
	}

	// Anomalous sample should have higher score
	anomaly := FeatureVector{100, 200, 300}
	ascore := sd.Predict(anomaly)
	if ascore < 0.5 {
		t.Errorf("anomaly score = %.3f", ascore)
	}
	t.Logf("normal=%.3f anomaly=%.3f", score, ascore)
}

// ── Isolation forest tests ──────────────────────────────────

func TestIsolationForest(t *testing.T) {
	forest := NewIsolationForest(50, 64)

	// Train on uniform random data
	rng := newRand()
	samples := make([]FeatureVector, 200)
	for i := range samples {
		for j := 0; j < NumFeatures; j++ {
			samples[i][j] = rng.Float64() * 10
		}
	}
	if err := forest.Train(samples); err != nil {
		t.Fatalf("Train: %v", err)
	}

	// Normal point near the mean
	normal := FeatureVector{}
	for j := 0; j < NumFeatures; j++ {
		normal[j] = 5
	}
	nscore := forest.Predict(normal)

	// Anomalous point far from the mean
	anomaly := FeatureVector{}
	for j := 0; j < NumFeatures; j++ {
		anomaly[j] = 1000
	}
	ascore := forest.Predict(anomaly)

	t.Logf("forest: normal=%.4f anomaly=%.4f", nscore, ascore)
	if ascore <= nscore {
		t.Error("anomaly should score higher than normal")
	}
}

func TestIsolationForestEmpty(t *testing.T) {
	forest := NewIsolationForest(10, 10)
	if err := forest.Train(nil); err != nil {
		t.Fatalf("Train nil: %v", err)
	}
	score := forest.Predict(FeatureVector{})
	if score != 0 {
		t.Errorf("score for empty forest = %f", score)
	}
}

// ── Detector integration tests ──────────────────────────────

func TestMLDetectorTrainAndDetect(t *testing.T) {
	forest := NewIsolationForest(50, 128)
	md := NewDetector(DefaultDetectorConfig(), forest)

	// Build a normal graph
	g := provenance.NewGraph()
	for i := 0; i < 50; i++ {
		g.AddEvent(&collector.Event{
			Type: syscall.EventFileOpen, TimestampNS: uint64(1000 + i),
			PID: uint32(100 + i%10), Comm: "bash",
			Pathname: "/var/log/syslog",
			Inode:    1000 + uint64(i), DevMajor: 8, DevMinor: 3,
		})
	}
	if err := md.Train(g); err != nil {
		t.Fatalf("Train: %v", err)
	}
	if !md.IsTrained() {
		t.Error("should be trained")
	}

	// Analyse a normal process subgraph
	result := md.AnalyseProcessSubgraph("p:100", g)
	if result == nil {
		t.Fatal("AnalyseProcessSubgraph returned nil")
	}
	t.Logf("normal subgraph: score=%.4f anomaly=%v strong=%v",
		result.AnomalyScore, result.IsAnomaly, result.IsStrong)
}

func TestMLDetectorGlobalStats(t *testing.T) {
	forest := NewIsolationForest(20, 32)
	md := NewDetector(DefaultDetectorConfig(), forest)

	g := provenance.NewGraph()
	g.AddEvent(&collector.Event{
		Type: syscall.EventFileOpen, TimestampNS: 1,
		PID: 100, Comm: "bash", Pathname: "/etc/hosts",
		Inode: 1000, DevMajor: 8, DevMinor: 3,
	})
	md.Train(g)

	stats := md.GlobalStats(g)
	if stats["count"] == 0 {
		t.Error("expected some results")
	}
	t.Logf("global stats: %v", stats)
}

// ── Training data tests ──────────────────────────────────

func TestSampleFromGraph(t *testing.T) {
	g := provenance.NewGraph()
	for i := 0; i < 5; i++ {
		g.AddEvent(&collector.Event{
			Type: syscall.EventFileOpen, TimestampNS: uint64(i),
			PID: 100, Comm: "bash",
			Pathname: "/etc/hosts",
			Inode: 1000, DevMajor: 8, DevMinor: 3,
		})
	}
	samples := SampleFromGraph(g, 10)
	t.Logf("samples from graph: %d", len(samples))
}

func TestSaveLoadTrainingData(t *testing.T) {
	samples := []FeatureVector{
		{1, 2, 3},
		{4, 5, 6},
	}
	path := t.TempDir() + "/training.csv"
	if err := SaveTrainingData(samples, path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := LoadTrainingData(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded) != 2 {
		t.Errorf("loaded %d, want 2", len(loaded))
	}
}

func TestComputeBounds(t *testing.T) {
	v := []FeatureVector{
		{1, 10, 100},
		{2, 20, 200},
	}
	mins, maxs := ComputeBounds(v)
	if mins[0] != 1 || maxs[0] != 2 {
		t.Errorf("bounds[0]: min=%f max=%f", mins[0], maxs[0])
	}
	if mins[2] != 100 || maxs[2] != 200 {
		t.Errorf("bounds[2]: min=%f max=%f", mins[2], maxs[2])
	}
}

func TestEnsembleDetector(t *testing.T) {
	sd1 := &StatisticalDetector{}
	sd2 := &StatisticalDetector{}
	ens := NewEnsemble([]AnomalyDetector{sd1, sd2})

	samples := []FeatureVector{{1, 2, 3}, {2, 3, 4}}
	if err := ens.Train(samples); err != nil {
		t.Fatalf("Train: %v", err)
	}
	score := ens.Predict(FeatureVector{1.5, 2.5, 3.5})
	if score < 0 || score > 1 {
		t.Errorf("ensemble score = %f", score)
	}
}

// ── Feature ranking tests ──────────────────────────────────

func TestFeatureContrib(t *testing.T) {
	means := FeatureVector{5, 5, 5}
	stds := FeatureVector{1, 1, 1}
	vec := FeatureVector{5, 10, 5}
	contribs := FeatureContrib(vec, means, stds, 2)
	if len(contribs) != 2 {
		t.Errorf("got %d contribs, want 2", len(contribs))
	}
	if contribs[0].Name != "edge_count" { // feature index 1 = 10, highest z-score
		t.Logf("top contributor: %s (score=%.2f)", contribs[0].Name, contribs[0].Score)
	}
}

// ── Helpers ─────────────────────────────────────────────────

func newRand() *rand.Rand {
	return rand.New(rand.NewSource(42))
}
