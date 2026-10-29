package resourceguard

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"
)

func healthy() Sample {
	return Sample{At: time.Now(), CPUPercent: 20, MemoryPercent: 40, MemoryAvailable: 4 << 30, MemoryTotal: 8 << 30, DiskFree: 10 << 30, DiskTotal: 20 << 30}
}

func TestAdmissionPressureRecoveryAndStaleness(t *testing.T) {
	g := New(Config{})
	if _, e := g.TryAcquire("worker"); e == nil {
		t.Fatal("admitted before first sample")
	}
	g.Observe(healthy(), nil)
	r, e := g.TryAcquire("worker")
	if e != nil {
		t.Fatal(e)
	}
	r()
	r()
	s := healthy()
	s.CPUPercent = 95
	if g.Observe(s, nil) == nil {
		t.Fatal("missing pressure alert")
	}
	if _, e := g.TryAcquire("tool"); e == nil {
		t.Fatal("admitted under CPU pressure")
	}
	if g.Observe(s, nil) != nil {
		t.Fatal("duplicate alert")
	}
	s.CPUPercent = 80
	g.Observe(s, nil)
	if g.Snapshot().State != "pressure" {
		t.Fatal("hysteresis lost")
	}
	g.Observe(healthy(), nil)
	if g.Snapshot().State != "normal" {
		t.Fatal("did not recover")
	}
	g.Observe(healthy(), errors.New("sampler failed"))
	if _, e := g.TryAcquire("worker"); e == nil {
		t.Fatal("admitted on sampling error")
	}
	s = healthy()
	s.At = time.Now().Add(-time.Minute)
	g.Observe(s, nil)
	if _, e := g.TryAcquire("tool"); e == nil {
		t.Fatal("admitted stale sample")
	}
	g.Observe(healthy(), nil)
	g.mu.Lock()
	g.last.At = time.Now().Add(-time.Minute)
	g.mu.Unlock()
	if _, e := g.TryAcquire("tool"); e == nil {
		t.Fatal("stopped sampler admitted work")
	}
}

func TestPressureSignalsAndInvalidSamples(t *testing.T) {
	for _, mutate := range []func(*Sample){func(s *Sample) { s.MemoryPercent = 90 }, func(s *Sample) { s.MemoryAvailable = 128 << 20 }, func(s *Sample) { s.DiskFree = 100 << 20 }, func(s *Sample) { s.CPUPercent = math.NaN() }, func(s *Sample) { s.MemoryTotal = 0 }} {
		g := New(Config{})
		g.Observe(healthy(), nil)
		s := healthy()
		mutate(&s)
		g.Observe(s, nil)
		if _, e := g.TryAcquire("worker"); e == nil {
			t.Fatalf("admitted invalid/pressure sample %+v", s)
		}
	}
}

func TestGlobalConcurrencyAndContextCancellation(t *testing.T) {
	g := New(Config{MaxWorkers: 1, MaxTools: 1})
	g.Observe(healthy(), nil)
	r, e := g.TryAcquire("tool")
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for range 40 {
		wg.Go(func() {
			if release, e := g.TryAcquire("tool"); e == nil {
				release()
				t.Error("oversubscribed tool slot")
			}
		})
	}
	wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := g.Acquire(ctx); !errors.Is(e, context.Canceled) {
		t.Fatalf("cancellation lost: %v", e)
	}
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		release, e := g.Acquire(ctx)
		if e == nil {
			release()
		}
		done <- e
	}()
	r()
	r()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if s := g.Snapshot(); s.Tools != 0 {
		t.Fatalf("lease leak %+v", s)
	}
}

func TestBoundedHistoryAndSnapshotIsolation(t *testing.T) {
	g := New(Config{})
	for i := range 200 {
		s := healthy()
		if i%2 == 0 {
			s.MemoryPercent = 95
		}
		g.Observe(s, nil)
	}
	s := g.Snapshot()
	if len(s.History) != 90 || len(s.Alerts) != 32 {
		t.Fatalf("unbounded history: %d/%d", len(s.History), len(s.Alerts))
	}
	s.History[0].CPUPercent = 999
	s.Alerts[0].Reason = "corrupted"
	s = g.Snapshot()
	if s.History[0].CPUPercent == 999 || s.Alerts[0].Reason == "corrupted" {
		t.Fatal("snapshot aliases live state")
	}
}

func TestNativeSampler(t *testing.T) {
	sampler := NewSampler(t.TempDir())
	_, _ = sampler.Sample(context.Background())
	time.Sleep(60 * time.Millisecond)
	s, e := sampler.Sample(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if !valid(s) {
		t.Fatalf("invalid real sample %+v", s)
	}
}
