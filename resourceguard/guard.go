// Package resourceguard provides bounded host-pressure sampling and atomic
// admission. It never mutates task states and is not a process sandbox.
package resourceguard

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"
)

const Interval = 2 * time.Second

type Config struct {
	MaxWorkers     int     `json:"max_workers"`
	MaxTools       int     `json:"max_tools"`
	CPUHigh        float64 `json:"cpu_high"`
	CPUResume      float64 `json:"cpu_resume"`
	MemoryHigh     float64 `json:"memory_high"`
	MemoryResume   float64 `json:"memory_resume"`
	MinAvailableMB uint64  `json:"min_available_mb"`
	MinDiskFreeMB  uint64  `json:"min_disk_free_mb"`
}

func (c Config) Defaults() Config {
	if c.MaxWorkers <= 0 {
		c.MaxWorkers = 2
	}
	if c.MaxTools <= 0 {
		c.MaxTools = 4
	}
	if c.CPUHigh <= 0 || c.CPUHigh > 100 || math.IsNaN(c.CPUHigh) {
		c.CPUHigh = 90
	}
	if c.CPUResume <= 0 || c.CPUResume >= c.CPUHigh || math.IsNaN(c.CPUResume) {
		c.CPUResume = c.CPUHigh * .83
	}
	if c.MemoryHigh <= 0 || c.MemoryHigh > 100 || math.IsNaN(c.MemoryHigh) {
		c.MemoryHigh = 85
	}
	if c.MemoryResume <= 0 || c.MemoryResume >= c.MemoryHigh || math.IsNaN(c.MemoryResume) {
		c.MemoryResume = c.MemoryHigh * .88
	}
	if c.MinAvailableMB == 0 {
		c.MinAvailableMB = 256
	}
	if c.MinDiskFreeMB == 0 {
		c.MinDiskFreeMB = 1024
	}
	// Reject implausible reserves before converting MB to bytes.
	if c.MinAvailableMB > 1<<30 {
		c.MinAvailableMB = 256
	}
	if c.MinDiskFreeMB > 1<<30 {
		c.MinDiskFreeMB = 1024
	}
	return c
}

type Sample struct {
	At              time.Time `json:"at"`
	CPUPercent      float64   `json:"cpu_percent"`
	MemoryPercent   float64   `json:"memory_percent"`
	MemoryAvailable uint64    `json:"memory_available"`
	MemoryTotal     uint64    `json:"memory_total"`
	DiskFree        uint64    `json:"disk_free"`
	DiskTotal       uint64    `json:"disk_total"`
	CgroupMemoryMax uint64    `json:"cgroup_memory_max,omitempty"`
	CgroupCPUQuota  string    `json:"cgroup_cpu_quota,omitempty"`
	CgroupPIDsMax   string    `json:"cgroup_pids_max,omitempty"`
}

type Alert struct {
	At     time.Time `json:"at"`
	State  string    `json:"state"`
	Reason string    `json:"reason"`
}

type Snapshot struct {
	Sample
	State   string   `json:"state"`
	Reason  string   `json:"reason"`
	Workers int      `json:"workers"`
	Tools   int      `json:"tools"`
	Limits  Config   `json:"limits"`
	Alerts  []Alert  `json:"alerts"`
	History []Sample `json:"history"`
}

type Sampler interface {
	Sample(context.Context) (Sample, error)
}

type Guard struct {
	mu             sync.Mutex
	cfg            Config
	last           Sample
	state, reason  string
	workers, tools int
	alerts         []Alert
	history        []Sample
	changed        chan struct{}
}

func New(c Config) *Guard {
	return &Guard{cfg: c.Defaults(), state: "unknown", reason: "等待资源采样", changed: make(chan struct{})}
}

// Run has one sampler and one fixed ticker, regardless of task/dashboard count.
func (g *Guard) Run(ctx context.Context, sampler Sampler, alert func(Alert)) {
	ticker := time.NewTicker(Interval)
	defer ticker.Stop()
	for {
		s, err := sampler.Sample(ctx)
		if a := g.Observe(s, err); a != nil && alert != nil {
			alert(*a)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (g *Guard) Observe(s Sample, err error) *Alert {
	g.mu.Lock()
	defer g.mu.Unlock()
	previous, oldReason := g.state, g.reason
	if err == nil && (!valid(s) || time.Since(s.At) > 3*Interval || s.At.After(time.Now().Add(Interval))) {
		err = fmt.Errorf("资源采样缺失或无效")
	}
	if err != nil {
		g.state, g.reason = "unknown", "资源采样不可用: "+err.Error()
		if len(g.reason) > 300 {
			g.reason = g.reason[:300]
		}
	} else {
		g.last = s
		g.history = append(g.history, s)
		if len(g.history) > 90 {
			g.history = append([]Sample(nil), g.history[len(g.history)-90:]...)
		}
		cpu, mem := g.cfg.CPUHigh, g.cfg.MemoryHigh
		reserve, disk := g.cfg.MinAvailableMB<<20, g.cfg.MinDiskFreeMB<<20
		if previous != "normal" {
			cpu, mem = g.cfg.CPUResume, g.cfg.MemoryResume
			reserve += reserve / 4
			disk += disk / 4
		}
		g.state, g.reason = "normal", "资源充足"
		switch {
		case s.MemoryAvailable < reserve:
			g.state, g.reason = "pressure", "可用内存不足，暂停派发"
		case s.MemoryPercent >= mem:
			g.state, g.reason = "pressure", "内存使用率过高，暂停派发"
		case s.CPUPercent >= cpu:
			g.state, g.reason = "pressure", "CPU 使用率过高，暂停派发"
		case s.DiskFree < disk:
			g.state, g.reason = "pressure", "数据盘剩余空间不足，暂停派发"
		}
	}
	close(g.changed)
	g.changed = make(chan struct{})
	if previous == g.state && oldReason == g.reason {
		return nil
	}
	a := Alert{At: time.Now().UTC(), State: g.state, Reason: g.reason}
	g.alerts = append(g.alerts, a)
	if len(g.alerts) > 32 {
		g.alerts = append([]Alert(nil), g.alerts[len(g.alerts)-32:]...)
	}
	return &a
}

func valid(s Sample) bool {
	return !s.At.IsZero() && s.MemoryTotal > 0 && s.MemoryAvailable <= s.MemoryTotal && s.DiskTotal > 0 && s.DiskFree <= s.DiskTotal &&
		!math.IsNaN(s.CPUPercent) && s.CPUPercent >= 0 && s.CPUPercent <= 100 && !math.IsNaN(s.MemoryPercent) && s.MemoryPercent >= 0 && s.MemoryPercent <= 100
}

func (g *Guard) stateLocked() (string, string) {
	if g.last.At.IsZero() || time.Since(g.last.At) > 3*Interval {
		return "unknown", "资源采样已过期，暂停派发"
	}
	return g.state, g.reason
}

func (g *Guard) Snapshot() Snapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	state, reason := g.stateLocked()
	return Snapshot{Sample: g.last, State: state, Reason: reason, Workers: g.workers, Tools: g.tools, Limits: g.cfg,
		Alerts: append([]Alert{}, g.alerts...), History: append([]Sample{}, g.history...)}
}

// TryAcquire never queues a worker after claiming an intent. A denied admission
// leaves the intent open; human-stopped/paused nodes are never revived here.
func (g *Guard) TryAcquire(kind string) (func(), error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	state, reason := g.stateLocked()
	if state != "normal" {
		return nil, fmt.Errorf("resource_blocked: %s", reason)
	}
	n, max := &g.tools, g.cfg.MaxTools
	if kind == "worker" {
		n, max = &g.workers, g.cfg.MaxWorkers
	} else if kind != "tool" {
		return nil, fmt.Errorf("invalid resource lease kind %q", kind)
	}
	if *n >= max {
		return nil, fmt.Errorf("resource_busy: %s 并发已达 %d", kind, max)
	}
	*n++
	var once sync.Once
	return func() {
		once.Do(func() { g.mu.Lock(); *n--; close(g.changed); g.changed = make(chan struct{}); g.mu.Unlock() })
	}, nil
}

// Acquire waits briefly for capacity/pressure recovery without consuming model
// turns. Cancellation always wins before the caller executes a tool.
func (g *Guard) Acquire(ctx context.Context) (func(), error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		g.mu.Lock()
		changed := g.changed
		g.mu.Unlock()
		release, err := g.TryAcquire("tool")
		if err == nil {
			if ctx.Err() != nil {
				release()
				return nil, ctx.Err()
			}
			return release, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w (%v)", ctx.Err(), err)
		case <-changed:
		}
	}
}
