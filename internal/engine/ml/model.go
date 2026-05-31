package ml

import (
	"math"
	"math/rand"
	"sort"
)

// ═══════════════════════════════════════════════════════════════
// Isolation Forest — unsupervised anomaly detection
//
// Algorithm:
//   1. Build an ensemble of isolation trees, each recursively
//      splitting the feature space at random.
//   2. Anomalous points require fewer splits to isolate
//      (they live in sparse regions of the feature space).
//   3. Anomaly score = 2^(-E(h(x)) / c(n)), where:
//      h(x) = average path length across trees
//      c(n) = normalising constant for forest size n
// ═══════════════════════════════════════════════════════════════

// IsolationTree is a single tree in the forest.
type IsolationTree struct {
	SplitFeature int     // feature index to split on
	SplitValue   float64 // threshold value
	Left         *IsolationTree
	Right        *IsolationTree
	Size         int // number of samples at this node (leaf only)
}

// IsolationForest is an ensemble of isolation trees.
type IsolationForest struct {
	Trees      []*IsolationTree
	NumTrees   int
	SampleSize int
	HeightMax  int
	rng        *rand.Rand
}

// NewIsolationForest creates a forest with nTrees trees,
// each trained on subsamples of size sampleSize.
func NewIsolationForest(nTrees, sampleSize int) *IsolationForest {
	if nTrees <= 0 {
		nTrees = 100
	}
	if sampleSize <= 0 {
		sampleSize = 256
	}
	return &IsolationForest{
		NumTrees:   nTrees,
		SampleSize: sampleSize,
		HeightMax:  int(math.Ceil(math.Log2(float64(sampleSize)))),
		rng:        rand.New(rand.NewSource(42)), // fixed seed for repro
	}
}

// Train builds the forest from training samples.
func (f *IsolationForest) Train(samples []FeatureVector) error {
	n := len(samples)
	if n == 0 {
		return nil
	}

	sampleSize := f.SampleSize
	if sampleSize > n {
		sampleSize = n
	}

	f.Trees = make([]*IsolationTree, f.NumTrees)
	for i := 0; i < f.NumTrees; i++ {
		// Bootstrap sample
		subsample := make([]FeatureVector, sampleSize)
		for j := 0; j < sampleSize; j++ {
			subsample[j] = samples[f.rng.Intn(n)]
		}
		f.Trees[i] = buildTree(subsample, 0, f.HeightMax, f.rng)
	}
	return nil
}

// Predict returns the anomaly score for a sample.
// Score > 0.5 indicates anomaly, > 0.6 strong anomaly.
func (f *IsolationForest) Predict(vec FeatureVector) float64 {
	if len(f.Trees) == 0 {
		return 0
	}

	var totalPathLen float64
	for _, tree := range f.Trees {
		totalPathLen += pathLength(tree, vec, 0)
	}
	avgPathLen := totalPathLen / float64(len(f.Trees))

	// Normalising constant
	n := float64(f.SampleSize)
	c := normalisingConst(n)

	// Anomaly score: 2^(-E(h(x))/c(n))
	// Score → 0.5 for normal, → 1.0 for definite anomaly
	return math.Pow(2, -avgPathLen/c)
}

// ── Tree building ───────────────────────────────────────────

func buildTree(samples []FeatureVector, depth, heightMax int, rng *rand.Rand) *IsolationTree {
	if depth >= heightMax || len(samples) <= 1 {
		return &IsolationTree{Size: len(samples)}
	}

	nFeatures := NumFeatures
	if nFeatures == 0 {
		return &IsolationTree{Size: len(samples)}
	}

	// Random feature
	f := rng.Intn(int(nFeatures))

	// Find min/max for this feature
	minVal := samples[0][f]
	maxVal := minVal
	for _, s := range samples[1:] {
		if s[f] < minVal {
			minVal = s[f]
		}
		if s[f] > maxVal {
			maxVal = s[f]
		}
	}

	if minVal == maxVal {
		return &IsolationTree{Size: len(samples)}
	}

	// Random split point
	split := minVal + rng.Float64()*(maxVal-minVal)

	// Partition
	var left, right []FeatureVector
	for _, s := range samples {
		if s[f] < split {
			left = append(left, s)
		} else {
			right = append(right, s)
		}
	}

	if len(left) == 0 || len(right) == 0 {
		return &IsolationTree{Size: len(samples)}
	}

	return &IsolationTree{
		SplitFeature: f,
		SplitValue:   split,
		Left:         buildTree(left, depth+1, heightMax, rng),
		Right:        buildTree(right, depth+1, heightMax, rng),
	}
}

// pathLength computes the isolation path length for a sample.
func pathLength(tree *IsolationTree, vec FeatureVector, depth int) float64 {
	if tree.Left == nil && tree.Right == nil {
		// Leaf: adjust for sample size
		if tree.Size <= 1 {
			return float64(depth)
		}
		return float64(depth) + normalisingConst(float64(tree.Size))
	}
	if vec[tree.SplitFeature] < tree.SplitValue && tree.Left != nil {
		return pathLength(tree.Left, vec, depth+1)
	}
	if tree.Right != nil {
		return pathLength(tree.Right, vec, depth+1)
	}
	return float64(depth)
}

// normalisingConst = c(n) = 2*H(n-1) - 2*(n-1)/n, H = harmonic number.
func normalisingConst(n float64) float64 {
	if n <= 1 {
		return 0
	}
	if n <= 2 {
		return 1
	}
	return 2*harmonic(n-1) - 2*(n-1)/n
}

func harmonic(n float64) float64 {
	// Approximation: ln(n) + 0.5772156649 (Euler-Mascheroni constant)
	return math.Log(n) + 0.5772156649
}

// ═══════════════════════════════════════════════════════════════
// Statistical detector (z-score based) — lightweight alternative
// ═══════════════════════════════════════════════════════════════

// StatisticalDetector uses z-scores for anomaly detection.
type StatisticalDetector struct {
	means [NumFeatures]float64
	stds  [NumFeatures]float64
}

// Train computes mean and std for each feature.
func (sd *StatisticalDetector) Train(samples []FeatureVector) error {
	if len(samples) == 0 {
		return nil
	}
	n := float64(len(samples))

	// Means
	for _, s := range samples {
		for i := 0; i < int(NumFeatures); i++ {
			sd.means[i] += s[i]
		}
	}
	for i := 0; i < int(NumFeatures); i++ {
		sd.means[i] /= n
	}

	// Stddevs
	for _, s := range samples {
		for i := 0; i < int(NumFeatures); i++ {
			d := s[i] - sd.means[i]
			sd.stds[i] += d * d
		}
	}
	for i := 0; i < int(NumFeatures); i++ {
		sd.stds[i] = math.Sqrt(sd.stds[i] / (n - 1))
		if sd.stds[i] == 0 {
			sd.stds[i] = 1 // avoid division by zero
		}
	}
	return nil
}

// Predict returns anomaly score based on mean z-score across features.
func (sd *StatisticalDetector) Predict(vec FeatureVector) float64 {
	var totalZ float64
	for i := 0; i < int(NumFeatures); i++ {
		z := math.Abs(vec[i]-sd.means[i]) / sd.stds[i]
		totalZ += z
	}
	avgZ := totalZ / float64(NumFeatures)

	// Convert z-score to anomaly score (sigmoid-like mapping)
	// z=0 → score=0.1, z=2 → score=0.5, z=4 → score=0.9
	return 1.0 / (1.0 + math.Exp(-((avgZ - 2.0))))
}

// ═══════════════════════════════════════════════════════════════
// AnomalyDetector interface
// ═══════════════════════════════════════════════════════════════

// AnomalyDetector is the interface for anomaly detection models.
type AnomalyDetector interface {
	Train(samples []FeatureVector) error
	Predict(vec FeatureVector) (score float64)
}

// ── EnsembleDetector combines multiple detectors ───────────

// EnsembleDetector averages predictions from multiple detectors.
type EnsembleDetector struct {
	detectors []AnomalyDetector
}

func NewEnsemble(detectors []AnomalyDetector) *EnsembleDetector {
	return &EnsembleDetector{detectors: detectors}
}

func (ed *EnsembleDetector) Train(samples []FeatureVector) error {
	for _, d := range ed.detectors {
		if err := d.Train(samples); err != nil {
			return err
		}
	}
	return nil
}

func (ed *EnsembleDetector) Predict(vec FeatureVector) float64 {
	var total float64
	for _, d := range ed.detectors {
		total += d.Predict(vec)
	}
	return total / float64(len(ed.detectors))
}

// ═══════════════════════════════════════════════════════════════
// Feature ranking (for explainability)
// ═══════════════════════════════════════════════════════════════

// FeatureContrib returns the top-k features contributing most to
// an anomaly score, based on z-score deviation.
func FeatureContrib(vec FeatureVector, means, stds [NumFeatures]float64, topK int) []struct {
	Name  string
	Score float64
} {
	names := FeatureNames()
	type contrib struct {
		name  string
		score float64
	}
	var all []contrib
	for i := 0; i < int(NumFeatures); i++ {
		z := math.Abs(vec[i]-means[i]) / math.Max(stds[i], 1e-10)
		all = append(all, contrib{names[i], z})
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].score > all[j].score
	})
	if topK <= 0 || topK > len(all) {
		topK = len(all)
	}
	result := make([]struct {
		Name  string
		Score float64
	}, topK)
	for i := 0; i < topK; i++ {
		result[i].Name = all[i].name
		result[i].Score = all[i].score
	}
	return result
}
