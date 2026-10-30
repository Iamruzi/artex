package httpmeasure

import (
	"math"
	"sort"
)

type Analysis struct {
	Signal             string  `json:"signal"`
	Reason             string  `json:"reason"`
	CompletePairs      int     `json:"complete_pairs"`
	RepeatedPairs      int     `json:"repeated_pairs"`
	BaselineMedianMS   float64 `json:"baseline_median_ms"`
	MedianDifferenceMS float64 `json:"median_difference_ms"`
	BaselineMADMS      float64 `json:"baseline_mad_ms"`
	DifferenceMADMS    float64 `json:"difference_mad_ms"`
	ThresholdMS        float64 `json:"threshold_ms"`
}

// Analyze is an observation heuristic, not a calibrated statistical hypothesis
// test. Raw samples remain intact, including spikes and failed attempts.
func Analyze(r Result) Analysis {
	a := Analysis{Signal: "inconclusive", Reason: "incomplete_measurement"}
	if r.Status != "completed" || r.PairsRequested < 3 || r.PairsRequested > 6 || r.MinimumEffectMS < 200 || len(r.Samples) != 2+2*r.PairsRequested {
		return a
	}
	pairs := make(map[int]map[string]float64)
	status := 0
	for _, s := range r.Samples {
		if s.ErrorCode != "" || !s.BodyComplete || !s.RequestWritten || s.StatusCode < 200 || s.StatusCode >= 300 || math.IsNaN(s.ElapsedMS) || math.IsInf(s.ElapsedMS, 0) || s.ElapsedMS < 0 {
			a.Reason = "invalid_response"
			return a
		}
		if status == 0 {
			status = s.StatusCode
		}
		if s.StatusCode != status {
			a.Reason = "status_changed"
			return a
		}
		if s.Warmup {
			continue
		}
		if s.Pair < 1 || s.Pair > r.PairsRequested || (s.Variant != "baseline" && s.Variant != "test") {
			return a
		}
		if pairs[s.Pair] == nil {
			pairs[s.Pair] = map[string]float64{}
		}
		if _, duplicate := pairs[s.Pair][s.Variant]; duplicate {
			return a
		}
		pairs[s.Pair][s.Variant] = s.ElapsedMS
	}
	var baseline, difference []float64
	for i := 1; i <= r.PairsRequested; i++ {
		values := pairs[i]
		b, bok := values["baseline"]
		t, tok := values["test"]
		if !bok || !tok {
			return a
		}
		baseline = append(baseline, b)
		difference = append(difference, t-b)
		if t-b >= float64(r.MinimumEffectMS) {
			a.RepeatedPairs++
		}
	}
	a.CompletePairs = len(difference)
	a.BaselineMedianMS = median(baseline)
	a.MedianDifferenceMS = median(difference)
	a.BaselineMADMS = mad(baseline)
	a.DifferenceMADMS = mad(difference)
	noise := 6 * 1.4826 * math.Max(a.BaselineMADMS, a.DifferenceMADMS)
	a.ThresholdMS = math.Max(float64(r.MinimumEffectMS), noise)
	if a.MedianDifferenceMS >= a.ThresholdMS && a.RepeatedPairs*5 >= a.CompletePairs*4 {
		a.Signal = "repeatable_delay"
		a.Reason = "paired_difference_exceeds_noise"
		return a
	}
	if noise > float64(r.MinimumEffectMS) {
		a.Reason = "unstable_timing"
		return a
	}
	a.Signal = "no_repeatable_delay"
	a.Reason = "insufficient_repeated_difference"
	return a
}

func median(values []float64) float64 {
	copyValues := append([]float64(nil), values...)
	sort.Float64s(copyValues)
	n := len(copyValues)
	if n == 0 {
		return 0
	}
	if n%2 == 0 {
		return (copyValues[n/2-1] + copyValues[n/2]) / 2
	}
	return copyValues[n/2]
}
func mad(values []float64) float64 {
	m := median(values)
	deviations := make([]float64, len(values))
	for i, v := range values {
		deviations[i] = math.Abs(v - m)
	}
	return median(deviations)
}
