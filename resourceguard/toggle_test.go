package resourceguard

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestProtectionToggleKeepsMonitoringAndCapacity(t *testing.T) {
	g := New(Config{MaxTools: 1, MaxWorkers: 1})
	if !g.Snapshot().ProtectionEnabled {
		t.Fatal("protection must default on")
	}
	bad := healthy()
	bad.MemoryPercent = 97
	g.Observe(bad, nil)
	if _, err := g.TryAcquire("tool"); err == nil {
		t.Fatal("pressure admitted with protection on")
	}
	g.SetProtectionEnabled(false)
	if snap := g.Snapshot(); snap.ProtectionEnabled || snap.State != "pressure" || snap.MemoryPercent != 97 {
		t.Fatal("disable hid monitoring", snap)
	}
	if err := g.CheckPressure(); err != nil {
		t.Fatal("pressure check ignored opt-out", err)
	}
	release, err := g.TryAcquire("tool")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = g.TryAcquire("tool"); err == nil || !strings.Contains(err.Error(), "resource_busy") {
		t.Fatal("disable lost concurrency cap", err)
	}
	g.SetProtectionEnabled(true)
	if g.Snapshot().Tools != 1 {
		t.Fatal("toggle discarded active lease")
	}
	if err = g.CheckPressure(); err == nil {
		t.Fatal("reenable did not restore pressure gate")
	}
	release()
	release()
	if g.Snapshot().Tools != 0 {
		t.Fatal("lease leaked after toggle")
	}
	// Monitoring failures/stale samples also become observations while disabled.
	g.Observe(Sample{}, errors.New("sampler fixture"))
	g.SetProtectionEnabled(false)
	release, err = g.TryAcquire("worker")
	if err != nil {
		t.Fatal("unknown reading blocked while disabled", err)
	}
	release()
	g.SetProtectionEnabled(true)
	if _, err = g.TryAcquire("worker"); err == nil {
		t.Fatal("unknown reading admitted after reenable")
	}
}

func TestProtectionToggleWakesWaiterButCancellationStillWins(t *testing.T) {
	g := New(Config{}) // no sample, protection initially blocks
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	type acquired struct {
		release func()
		err     error
	}
	done := make(chan acquired, 1)
	go func() { release, err := g.Acquire(ctx); done <- acquired{release, err} }()
	g.SetProtectionEnabled(false)
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatal(got.err)
		}
		got.release()
	case <-ctx.Done():
		t.Fatal("waiter not woken by toggle")
	}
	cancelled, stop := context.WithCancel(t.Context())
	stop()
	if _, err := g.Acquire(cancelled); err == nil {
		t.Fatal("disabled protection bypassed cancellation")
	}
	if g.Snapshot().Tools != 0 {
		t.Fatal("cancelled acquisition leaked lease")
	}
}
