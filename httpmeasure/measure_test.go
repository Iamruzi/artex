package httpmeasure

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testPlan(base string) Plan {
	return Plan{BaselineURL: base + "/observe?q=base", TestURL: base + "/observe?q=test", Pairs: 3, MinimumEffectMS: 200}
}

func TestRunnerUsesRealRequestsInAlternatingOrderAndKeepsNoSecrets(t *testing.T) {
	var order []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, r.URL.Query().Get("q"))
		if r.Header.Get("Authorization") != "Bearer fixture-secret" {
			t.Error("session header lost")
		}
		w.Header().Set("Set-Cookie", "token=response-secret")
		_, _ = io.WriteString(w, "response-secret")
	}))
	defer srv.Close()
	p := testPlan(srv.URL)
	p.Headers = map[string]string{"Authorization": "Bearer fixture-secret"}
	r := New(srv.Client(), nil)
	r.gap = 0
	result, err := r.Run(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" || result.Attempts != 8 || result.RequestsWritten != 8 || result.VulnerabilityConfirmed {
		t.Fatalf("incorrect counters/verdict: %+v", result)
	}
	if strings.Join(order, ",") != "base,base,base,test,test,base,base,test" {
		t.Fatalf("unbalanced order: %v", order)
	}
	for _, s := range result.Samples {
		if s.ElapsedMS < s.TTFBMS || !s.BodyComplete || len(s.BodySHA256) != 64 || s.StatusCode != 200 {
			t.Fatalf("missing actual signal: %+v", s)
		}
	}
	encoded, _ := json.Marshal(result)
	for _, secret := range []string{"fixture-secret", "response-secret", "Authorization", srv.URL} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("measurement copied raw secret or URL")
		}
	}
}

func TestRedirectErrorAndOversizedResponseNeverBecomePositive(t *testing.T) {
	for _, mode := range []string{"redirect", "http-error", "oversized", "incomplete", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			var otherRequests atomic.Int32
			other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { otherRequests.Add(1) }))
			defer other.Close()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "redirect":
					http.Redirect(w, r, other.URL, 302)
				case "http-error":
					http.Error(w, "login required", 403)
				case "oversized":
					_, _ = io.WriteString(w, strings.Repeat("x", MaxResponseBytes+1))
				case "incomplete":
					w.Header().Set("Content-Length", "100")
					_, _ = io.WriteString(w, "partial")
				case "timeout":
					<-r.Context().Done()
				}
			}))
			defer srv.Close()
			p := testPlan(srv.URL)
			p.TimeoutMS = 100
			r := New(srv.Client(), nil)
			r.gap = 0
			result, err := r.Run(t.Context(), p)
			if err != nil {
				t.Fatal(err)
			}
			if result.Attempts != 1 || result.Status == "completed" || result.Analysis.Signal != "inconclusive" || otherRequests.Load() != 0 {
				t.Fatalf("failure became result: %+v", result)
			}
		})
	}
}

func TestCancellationAndResourceChangeKeepPartialSamples(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	releases := 0
	admissions := 0
	r := New(srv.Client(), func(context.Context, string) (func(), error) {
		admissions++
		if admissions == 4 {
			return nil, &StopError{Code: "resource_blocked"}
		}
		return func() { releases++ }, nil
	})
	r.gap = 0
	result, err := r.Run(t.Context(), testPlan(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "resource_blocked" || result.Attempts != 3 || releases != 3 || calls.Load() != 3 || result.Analysis.Signal != "inconclusive" {
		t.Fatalf("lost partial/resource state: %+v releases=%d", result, releases)
	}
	ctx, cancel := context.WithCancel(t.Context())
	r = New(srv.Client(), func(context.Context, string) (func(), error) { return func() { cancel() }, nil })
	r.gap = time.Second
	result, err = r.Run(ctx, testPlan(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "cancelled" || result.Attempts != 1 || len(result.Samples) != 1 {
		t.Fatalf("cancelled sampler kept dispatching: %+v", result)
	}
}

func TestInvalidPlanDispatchesNothing(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer srv.Close()
	base := testPlan(srv.URL)
	bad := []Plan{}
	p := base
	p.TestURL = "http://other.invalid/observe"
	bad = append(bad, p)
	p = base
	p.TestURL = srv.URL + "/different"
	bad = append(bad, p)
	p = base
	p.Pairs = 100
	bad = append(bad, p)
	p = base
	p.Method = "DELETE"
	bad = append(bad, p)
	p = base
	p.Headers = map[string]string{"Authorization": "bad\x01header"}
	bad = append(bad, p)
	p = base
	p.Headers = map[string]string{"Host": "elsewhere.invalid"}
	bad = append(bad, p)
	p = base
	p.Headers = map[string]string{"A": "one", "a": "two"}
	bad = append(bad, p)
	p = base
	p.Method = "POST"
	p.TestBody = strings.Repeat("x", 65537)
	bad = append(bad, p)
	for _, plan := range bad {
		if _, err := New(srv.Client(), nil).Run(t.Context(), plan); err == nil {
			t.Fatal("invalid plan accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid plan made requests")
	}
}

func TestBodyDurationIsMeasuredAfterHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		time.Sleep(30 * time.Millisecond)
		_, _ = io.WriteString(w, "complete")
	}))
	defer srv.Close()
	p, _ := testPlan(srv.URL).Validate()
	sample := New(srv.Client(), nil).sample(t.Context(), p, p.BaselineURL, "")
	if sample.ElapsedMS-sample.TTFBMS < 20 || !sample.BodyComplete {
		t.Fatalf("timed only response headers: %+v", sample)
	}
}

func TestPOSTBodiesAndMaximumRequestBudget(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Error("lost POST method")
		}
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		fmtBody := string(body)
		if fmtBody != "baseline-body" && fmtBody != "test-body" {
			t.Error("wrong variant body")
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	p := testPlan(srv.URL)
	p.Method = "POST"
	p.BaselineBody = "baseline-body"
	p.TestBody = "test-body"
	p.Pairs = 6
	r := New(srv.Client(), nil)
	r.gap = 0
	result, err := r.Run(t.Context(), p)
	if err != nil || result.Attempts != 14 || result.RequestsWritten != 14 || len(bodies) != 14 {
		t.Fatalf("POST request budget incorrect: %v %+v", err, result)
	}
	if bodies[0] != "baseline-body" || bodies[1] != "baseline-body" || bodies[4] != "test-body" || bodies[5] != "baseline-body" {
		t.Fatal("POST variants were not interleaved")
	}
}
