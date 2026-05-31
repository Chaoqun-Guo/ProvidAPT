package graphsketch

import (
	"math"
	"sort"
)

// ═══════════════════════════════════════════════════════════════════
// Entropy detection — KL divergence against historical baseline
//
// Algorithm:
//   1. Build a probability distribution over edge types from the
//      current graph snapshot.
//   2. Update the historical baseline via exponential moving average.
//   3. Compute KL(P_current || P_baseline).
//   4. Track the running mean and std-dev of KL values.
//   5. If KL > mean + threshold * stddev, flag as anomaly.
// ═══════════════════════════════════════════════════════════════════

// EntropyDetector tracks historical behavior baselines and detects
// anomalous entropy spikes in process behavior.
type EntropyDetector struct {
	cfg        *EntropyConfig
	baseline   *EdgeTypeBaseline
	klHistory  []float64
	windowNum  int
	callback   AnomalyCallback
}

// NewEntropyDetector creates an entropy detector with the given config.
func NewEntropyDetector(cfg *EntropyConfig) *EntropyDetector {
	if cfg == nil {
		cfg = DefaultEntropyConfig()
	}
	return &EntropyDetector{
		cfg:       cfg,
		baseline:  NewEdgeTypeBaseline(cfg.Alpha),
		klHistory: make([]float64, 0, cfg.HistorySize),
	}
}

// SetCallback registers a function to call when an anomaly is detected.
func (ed *EntropyDetector) SetCallback(cb AnomalyCallback) {
	ed.callback = cb
}

// Evaluate computes the KL divergence between current edge type
// distribution and the baseline. Updates the baseline afterward.
//
// Returns the EntropyResult with KL divergence and anomaly flag.
func (ed *EntropyDetector) Evaluate(fv *GraphFeatureVector) *EntropyResult {
	ed.windowNum++

	if fv == nil || len(fv.EdgeTypeDist) == 0 {
		return &EntropyResult{
			KLDivergence: 0,
			IsAnomaly:    false,
			WindowNum:    ed.windowNum,
		}
	}

	// 1. Build current probability distribution from edge type counts.
	currentProbs := buildEdgeTypeProbabilities(fv.EdgeTypeDist)

	// 2. Compute KL divergence between current and baseline.
	kl := computeKLD(currentProbs, ed.baseline.Probabilities)

	// 3. Update baseline with current distribution.
	ed.updateBaseline(currentProbs)

	// 4. Update KL history.
	ed.klHistory = append(ed.klHistory, kl)
	if len(ed.klHistory) > ed.cfg.HistorySize {
		ed.klHistory = ed.klHistory[1:]
	}

	// 5. Evaluate anomaly if we have enough windows.
	result := &EntropyResult{
		KLDivergence: kl,
		WindowNum:    ed.windowNum,
	}

	if ed.windowNum >= ed.cfg.MinWindows && len(ed.klHistory) >= 2 {
		mean, stddev := computeMeanStdDev(ed.klHistory)
		result.KLMean = mean
		result.KLStdDev = stddev

		threshold := mean + ed.cfg.AnomalyThreshold*stddev
		if kl > threshold && stddev > 0 {
			result.IsAnomaly = true
			result.Reason = buildAnomalyReason(kl, mean, stddev, threshold, fv)
			fv.IsAnomaly = true
			fv.AnomalyReason = result.Reason

			if ed.callback != nil {
				ed.callback(result, fv)
			}
		}
	}

	// 6. Attach entropy metrics to the feature vector.
	fv.KLDivergence = kl
	fv.EntropyScore = computeEdgeTypeEntropy(currentProbs)

	return result
}

// Baseline returns the current edge type baseline.
func (ed *EntropyDetector) Baseline() *EdgeTypeBaseline {
	return ed.baseline
}

// Reset clears all history and baseline.
func (ed *EntropyDetector) Reset() {
	ed.baseline = NewEdgeTypeBaseline(ed.cfg.Alpha)
	ed.klHistory = make([]float64, 0, ed.cfg.HistorySize)
	ed.windowNum = 0
}

// Stats returns diagnostic statistics about the detector.
func (ed *EntropyDetector) Stats() map[string]interface{} {
	mean, stddev := computeMeanStdDev(ed.klHistory)
	return map[string]interface{}{
		"window_num":       ed.windowNum,
		"history_size":     len(ed.klHistory),
		"kl_mean":          mean,
		"kl_stddev":        stddev,
		"baseline_entries": len(ed.baseline.Probabilities),
	}
}

// ── Baseline update ──────────────────────────────────────────────

func (ed *EntropyDetector) updateBaseline(current map[string]float64) {
	alpha := ed.baseline.Alpha

	if ed.baseline.Count == 0 {
		// First window: initialize baseline with current distribution.
		for k, v := range current {
			ed.baseline.Probabilities[k] = v
		}
	} else {
		// Subsequent windows: EMA update.
		// Exponentially weight old entries that are no longer present.
		for k, prob := range ed.baseline.Probabilities {
			if _, ok := current[k]; !ok {
				ed.baseline.Probabilities[k] = (1 - alpha) * prob
			}
		}
		for k, v := range current {
			if oldProb, ok := ed.baseline.Probabilities[k]; ok {
				ed.baseline.Probabilities[k] = (1-alpha)*oldProb + alpha*v
			} else {
				ed.baseline.Probabilities[k] = alpha * v
			}
		}
	}

	ed.baseline.Count++
}

// ── KL divergence ────────────────────────────────────────────────

func computeKLD(current, baseline map[string]float64) float64 {
	if len(current) == 0 || len(baseline) == 0 {
		return 0
	}

	var kl float64
	for key, p := range current {
		if p == 0 {
			continue
		}
		q, ok := baseline[key]
		if !ok || q == 0 {
			// Baseline didn't see this event type. Use a small epsilon
			// to avoid division by zero and log(0).
			q = 1e-10
		}
		kl += p * math.Log(p/q)
	}

	// KL divergence is always >= 0.
	if kl < 0 {
		return 0
	}
	return kl
}

// ── Probability helpers ──────────────────────────────────────────

// buildEdgeTypeProbabilities converts counts to probabilities summing to 1.
func buildEdgeTypeProbabilities(counts map[string]int) map[string]float64 {
	probs := make(map[string]float64, len(counts))

	var total int
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		return probs
	}

	totalFloat := float64(total)
	for k, c := range counts {
		probs[k] = float64(c) / totalFloat
	}

	return probs
}

// computeEdgeTypeEntropy computes the Shannon entropy of the edge type
// distribution: H = -Σ P(i) * log(P(i))
func computeEdgeTypeEntropy(probs map[string]float64) float64 {
	var entropy float64
	for _, p := range probs {
		if p > 0 {
			entropy -= p * math.Log(p)
		}
	}
	return entropy
}

// computeMeanStdDev computes the mean and sample standard deviation.
func computeMeanStdDev(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}
	if len(values) == 1 {
		return values[0], 0
	}

	var sum float64
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))

	var varianceSum float64
	for _, v := range values {
		diff := v - mean
		varianceSum += diff * diff
	}
	stddev := math.Sqrt(varianceSum / float64(len(values)-1))

	return mean, stddev
}

// ── Anomaly reporting ────────────────────────────────────────────

func buildAnomalyReason(kl, mean, stddev, threshold float64, fv *GraphFeatureVector) string {
	// Find which edge types changed the most.
	var topChanges []string
	if fv != nil && len(fv.EdgeTypeDist) > 0 {
		// Sort edge types by count descending.
		type kv struct {
			key string
			val int
		}
		var sorted []kv
		for k, v := range fv.EdgeTypeDist {
			sorted = append(sorted, kv{k, v})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].val > sorted[j].val
		})

		for i, s := range sorted {
			if i >= 3 {
				break
			}
			topChanges = append(topChanges, s.key)
		}
	}

	reason := "行为熵异常激增"
	if len(topChanges) > 0 {
		reason += " (主要边类型: "
		for i, tc := range topChanges {
			if i > 0 {
				reason += ", "
			}
			reason += tc
		}
		reason += ")"
	}
	return reason
}
