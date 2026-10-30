package httpmeasure

import (
	"math/rand"
	"testing"
)

func synthetic(base, test []float64) Result {
	r := Result{Status: "completed", PairsRequested: len(base), MinimumEffectMS: 1000}
	for i := 0; i < 2; i++ {
		r.Samples = append(r.Samples, Sample{Warmup: true, Variant: "baseline", StatusCode: 200, BodyComplete: true, RequestWritten: true, ElapsedMS: 100})
	}
	for i := range base {
		r.Samples = append(r.Samples, Sample{Pair: i + 1, Variant: "baseline", StatusCode: 200, BodyComplete: true, RequestWritten: true, ElapsedMS: base[i]}, Sample{Pair: i + 1, Variant: "test", StatusCode: 200, BodyComplete: true, RequestWritten: true, ElapsedMS: test[i]})
	}
	return r
}

func TestAnalysisPreservesSpikesAndRejectsMissingOrChangedResponses(t *testing.T) {
	base := []float64{100, 110, 90, 100, 105}
	probe := []float64{2100, 2110, 2090, 2100, 2105}
	r := synthetic(base, probe)
	if a := Analyze(r); a.Signal != "repeatable_delay" || a.CompletePairs != 5 {
		t.Fatalf("missed controlled delay: %+v", a)
	}
	r.Samples[2].ElapsedMS = 15000
	if a := Analyze(r); a.Signal != "repeatable_delay" {
		t.Fatalf("one baseline spike hid repeated delay: %+v", a)
	}
	if r.Samples[2].ElapsedMS != 15000 {
		t.Fatal("analysis discarded raw outlier")
	}
	r = synthetic(base, probe)
	r.Samples[3].StatusCode = 403
	if Analyze(r).Signal != "inconclusive" {
		t.Fatal("HTTP failure became delay evidence")
	}
	r = synthetic(base, probe)
	r.Samples = r.Samples[1:]
	if Analyze(r).Signal != "inconclusive" {
		t.Fatal("missing observation accepted")
	}
}

func TestSeededTimingCorpusReportsFalsePositivesAndMisses(t *testing.T) {
	rng := rand.New(rand.NewSource(20261030))
	totalFP, totalFN := 0, 0
	for _, class := range []string{"stable_delay", "jitter_only", "common_drift", "single_spike", "delay_with_large_jitter"} {
		tp, fp, fn, inconclusive := 0, 0, 0, 0
		for trial := 0; trial < 100; trial++ {
			var base, probe []float64
			positive := class == "stable_delay" || class == "delay_with_large_jitter"
			for pair := 0; pair < 5; pair++ {
				b := 1500 + rng.Float64()*60
				tst := 1500 + rng.Float64()*60
				switch class {
				case "stable_delay":
					tst += 2000
				case "jitter_only":
					b += rng.Float64() * 1600
					tst += rng.Float64() * 1600
				case "common_drift":
					b += float64(pair * 800)
					tst += float64(pair * 800)
					if pair%2 == 0 {
						tst += 400
					} else {
						b += 400
					}
				case "single_spike":
					if pair == trial%5 {
						tst += 9000
					}
				case "delay_with_large_jitter":
					b += rng.Float64() * 2400
					tst += 2000 + rng.Float64()*2400
				}
				base = append(base, b)
				probe = append(probe, tst)
			}
			result := Analyze(synthetic(base, probe))
			signal := result.Signal == "repeatable_delay"
			if signal && positive {
				tp++
			}
			if signal && !positive {
				fp++
			}
			if !signal && positive {
				fn++
			}
			if result.Signal == "inconclusive" {
				inconclusive++
			}
		}
		totalFP += fp
		totalFN += fn
		t.Logf("%s: trials=100 TP=%d FP=%d FN=%d inconclusive=%d attempts_per_full_run=12", class, tp, fp, fn, inconclusive)
		if class == "stable_delay" && tp != 100 {
			t.Fatal("stable controlled positives regressed")
		}
		if !(class == "stable_delay" || class == "delay_with_large_jitter") && fp != 0 {
			t.Fatal("negative fixture produced false latency signal")
		}
	}
	t.Logf("corpus totals: trials=500 known_positive=200 known_negative=300 FP=%d FN=%d (abstentions count as misses)", totalFP, totalFN)
}
