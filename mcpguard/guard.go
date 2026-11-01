// Package mcpguard isolates MCP call failures without retrying or detaching work.
package mcpguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

type Config struct {
	Disabled         bool `json:"disabled"`
	MaxConcurrent    int  `json:"max_concurrent_per_server"`
	WaitMS           int  `json:"admission_wait_ms"`
	CallTimeoutMS    int  `json:"call_timeout_ms"`
	FailureThreshold int  `json:"failure_threshold"`
	CooldownSeconds  int  `json:"cooldown_seconds"`
}

func (c Config) normalized() Config {
	c.MaxConcurrent = bounded(c.MaxConcurrent, 2, 16)
	c.WaitMS = bounded(c.WaitMS, 5000, 30000)
	c.CallTimeoutMS = bounded(c.CallTimeoutMS, 120000, 3600000)
	c.FailureThreshold = bounded(c.FailureThreshold, 3, 20)
	c.CooldownSeconds = bounded(c.CooldownSeconds, 30, 3600)
	return c
}

func bounded(v, fallback, max int) int {
	if v <= 0 {
		return fallback
	}
	if v > max {
		return max
	}
	return v
}

type state struct {
	active, failures int
	generation       uint64
	openUntil        time.Time
	probing          bool
	changed          chan struct{}
}

type Manager struct {
	config      Config
	callTimeout time.Duration
	mu          sync.Mutex
	states      map[string]*state
	now         func() time.Time
}

func New(c Config) *Manager {
	c = c.normalized()
	return &Manager{config: c, callTimeout: time.Duration(c.CallTimeoutMS) * time.Millisecond, states: map[string]*state{}, now: time.Now}
}

type failureKey struct{}

// ErrBlocked is host-owned: a remote tool cannot forge it with output text.
var ErrBlocked = errors.New("mcp_blocked")

// NoteTransportFailure is called only by a transport adapter with a real
// connection/protocol failure. Never call it based on tool text or isError.
func NoteTransportFailure(ctx context.Context) {
	if flag, ok := ctx.Value(failureKey{}).(*atomic.Bool); ok {
		flag.Store(true)
	}
}

type guardedTool struct {
	actool.CoreTool
	manager *Manager
	key     string
}

// Wrap retains all permission, schema, read-only and deferred-tool behavior.
func (m *Manager) Wrap(key string, tool actool.CoreTool) actool.CoreTool {
	if m.config.Disabled {
		return tool
	}
	return &guardedTool{CoreTool: tool, manager: m, key: key}
}

func (g *guardedTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (res actool.Result, err error) {
	finish, err := g.manager.acquire(ctx, g.key)
	if err != nil {
		blocked := fmt.Errorf("%w: %s；本次未调用远端工具。请保留已有产物，换用可用路线或稍后重试。", ErrBlocked, err)
		return actool.Errorf(blocked.Error()), blocked
	}
	flag := &atomic.Bool{}
	completed := false
	timedOut := false
	defer func() {
		healthy := completed && err == nil && !timedOut
		neutral := !completed || ctx.Err() != nil || timedOut
		finish(flag.Load(), healthy, neutral)
	}()
	callCtx := context.WithValue(ctx, failureKey{}, flag)
	cancel := func() {}
	if g.manager.callTimeout > 0 {
		callCtx, cancel = context.WithTimeout(callCtx, g.manager.callTimeout)
	}
	defer cancel()
	res, err = g.CoreTool.Call(callCtx, in, tc)
	completed = true
	timedOut = errors.Is(callCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil
	if timedOut {
		return actool.Errorf(fmt.Sprintf("mcp_tool_timeout: 单次 MCP 工具调用超过 %s，已停止等待；远端操作是否结束尚未确认。请先核验当前状态，保留已有结果，改用更小且有自身超时的调用；不要直接重放可能修改状态的操作。", g.manager.callTimeout)), nil
	}
	return
}

func (m *Manager) acquire(ctx context.Context, key string) (func(bool, bool, bool), error) {
	timer := time.NewTimer(time.Duration(m.config.WaitMS) * time.Millisecond)
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m.mu.Lock()
		s := m.states[key]
		if s == nil {
			// A bounded registry, without a background cleanup goroutine. Active/open
			// states cannot be evicted, so a live lease or cooldown is never forgotten.
			if len(m.states) >= 256 {
				for k, v := range m.states {
					if v.active == 0 && !v.probing && (v.openUntil.IsZero() || !m.now().Before(v.openUntil)) {
						delete(m.states, k)
						break
					}
				}
			}
			if len(m.states) >= 256 {
				m.mu.Unlock()
				return nil, errors.New("MCP 隔离状态容量已满")
			}
			s = &state{changed: make(chan struct{})}
			m.states[key] = s
		}
		now := m.now()
		if !s.openUntil.IsZero() {
			if now.Before(s.openUntil) {
				m.mu.Unlock()
				return nil, errors.New("该 MCP 连续传输失败，正在冷却")
			}
			if s.probing || s.active > 0 {
				m.mu.Unlock()
				return nil, errors.New("该 MCP 正在等待单次恢复探测")
			}
			s.probing = true
		}
		if s.active < m.config.MaxConcurrent {
			s.active++
			generation := s.generation
			probe := s.probing
			m.mu.Unlock()
			var once sync.Once
			return func(failed, healthy, neutral bool) {
				once.Do(func() { m.finish(s, generation, probe, failed, healthy, neutral) })
			}, nil
		}
		changed := s.changed
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, errors.New("该 MCP 的并发槽位等待超时")
		case <-changed:
		}
	}
}

func (m *Manager) finish(s *state, generation uint64, probe, failed, healthy, neutral bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s.active--
	close(s.changed)
	s.changed = make(chan struct{})
	if generation != s.generation {
		return
	} // Late completions cannot close a new circuit.
	if probe {
		s.probing = false
	}
	if neutral {
		return
	} // Caller stop/panic must not poison server health.
	if failed {
		s.failures++
		if probe || s.failures >= m.config.FailureThreshold {
			s.openUntil = m.now().Add(time.Duration(m.config.CooldownSeconds) * time.Second)
			s.generation++
		}
	} else if healthy {
		s.failures = 0
		s.openUntil = time.Time{}
	}
}
