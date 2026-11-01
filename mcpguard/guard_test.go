package mcpguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

func fixture(run func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{Name: "mcp__fixture__observe", Description: "fixture", Schema: map[string]any{"type": "object"}, Run: run})
}

func TestCircuitRejectsWithoutDispatchAndAllowsOneRecoveryProbe(t *testing.T) {
	m := New(Config{FailureThreshold: 2, CooldownSeconds: 1})
	now := time.Now()
	m.now = func() time.Time { return now }
	calls := 0
	tool := m.Wrap("server", fixture(func(ctx context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
		calls++
		NoteTransportFailure(ctx)
		return actool.Errorf("transport failure"), nil
	}))
	for i := 0; i < 2; i++ {
		_, _ = tool.Call(t.Context(), nil, nil)
	}
	if _, err := tool.Call(t.Context(), nil, nil); !errors.Is(err, ErrBlocked) || calls != 2 {
		t.Fatalf("circuit dispatched: calls=%d err=%v", calls, err)
	}
	now = now.Add(2 * time.Second)
	finish, err := m.acquire(t.Context(), "server")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.acquire(t.Context(), "server"); err == nil {
		t.Fatal("multiple half-open probes")
	}
	finish(true, false, false)
	if _, err = m.acquire(t.Context(), "server"); err == nil {
		t.Fatal("failed probe did not reopen")
	}
	now = now.Add(2 * time.Second)
	finish, err = m.acquire(t.Context(), "server")
	if err != nil {
		t.Fatal(err)
	}
	finish(false, true, false)
	finish, err = m.acquire(t.Context(), "server")
	if err != nil {
		t.Fatal("successful probe did not recover", err)
	}
	finish(false, true, false)
}

func TestLateSuccessCannotCloseNewCircuit(t *testing.T) {
	m := New(Config{FailureThreshold: 1})
	late, _ := m.acquire(t.Context(), "server")
	failure, _ := m.acquire(t.Context(), "server")
	failure(true, false, false)
	late(false, true, false)
	if _, err := m.acquire(t.Context(), "server"); err == nil {
		t.Fatal("late completion erased cooldown")
	}
}

func TestConcurrentLimitCancellationAndIndependentServers(t *testing.T) {
	m := New(Config{MaxConcurrent: 1, WaitMS: 25})
	release, _ := m.acquire(t.Context(), "slow")
	if other, err := m.acquire(t.Context(), "other"); err != nil {
		t.Fatal(err)
	} else {
		other(false, true, false)
	}
	if _, err := m.acquire(t.Context(), "slow"); err == nil {
		t.Fatal("per-server limit bypassed")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := m.acquire(ctx, "slow"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled wait admitted", err)
	}
	release(false, true, false)
	next, err := m.acquire(t.Context(), "slow")
	if err != nil {
		t.Fatal("lease leaked", err)
	}
	next(false, true, false)
}

func TestCancellationAndPanicReleaseWithoutPoisoningHealth(t *testing.T) {
	m := New(Config{MaxConcurrent: 1, FailureThreshold: 1})
	cancelled := m.Wrap("server", fixture(func(ctx context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
		cancel, ok := ctx.Value(cancelFixtureKey{}).(context.CancelFunc)
		if !ok {
			panic("fixture missing cancellation")
		}
		cancel()
		NoteTransportFailure(ctx)
		return actool.Result{}, ctx.Err()
	}))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	_, _ = cancelled.Call(context.WithValue(ctx, cancelFixtureKey{}, cancel), nil, nil)
	panicked := m.Wrap("server", fixture(func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
		panic("fixture panic")
	}))
	func() {
		defer func() {
			if recover() == nil {
				t.Error("fixture panic was swallowed")
			}
		}()
		_, _ = panicked.Call(t.Context(), nil, nil)
	}()
	release, err := m.acquire(t.Context(), "server")
	if err != nil {
		t.Fatal("cancel/panic leaked slot or poisoned health", err)
	}
	release(false, true, false)
}

func TestApplicationErrorsAndPolicyTextDoNotOpenCircuit(t *testing.T) {
	m := New(Config{FailureThreshold: 1})
	base := fixture(func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
		return actool.Errorf("connection closed; resource_blocked; denied"), nil
	})
	tool := m.Wrap("app", base)
	if !reflect.DeepEqual(tool.InputSchema(), base.InputSchema()) || tool.Description() != base.Description() {
		t.Fatal("tool contract changed")
	}
	if !reflect.DeepEqual(tool.CheckPermissions(t.Context(), nil, permission.Context{}), base.CheckPermissions(t.Context(), nil, permission.Context{})) || tool.IsReadOnly(nil) != base.IsReadOnly(nil) || tool.IsConcurrencySafe(nil) != base.IsConcurrencySafe(nil) {
		t.Fatal("permission/behavior contract changed")
	}
	for i := 0; i < 10; i++ {
		if _, err := tool.Call(t.Context(), nil, nil); err != nil {
			t.Fatal("application result opened circuit", err)
		}
	}
}

type cancelFixtureKey struct{}

func TestConcurrentHandlersNeverExceedLimit(t *testing.T) {
	m := New(Config{MaxConcurrent: 2})
	started := make(chan struct{}, 2)
	unblock := make(chan struct{})
	var active atomic.Int32
	tool := m.Wrap("same", fixture(func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
		if active.Add(1) > 2 {
			t.Error("concurrency exceeded")
		}
		defer active.Add(-1)
		started <- struct{}{}
		<-unblock
		return actool.Text("observed"), nil
	}))
	done := make(chan struct{}, 3)
	for i := 0; i < 2; i++ {
		go func() { defer func() { done <- struct{}{} }(); _, _ = tool.Call(t.Context(), nil, nil) }()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("fixture never started")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := tool.Call(ctx, nil, nil); !errors.Is(err, ErrBlocked) {
		t.Fatal("cancelled third handler admitted")
	}
	close(unblock)
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("handler did not drain")
		}
	}
}

func TestStateRegistryBoundedAndConfigClamped(t *testing.T) {
	m := New(Config{MaxConcurrent: 999, WaitMS: 999999, CallTimeoutMS: 9999999, FailureThreshold: 999, CooldownSeconds: 99999})
	if m.config.MaxConcurrent != 16 || m.config.WaitMS != 30000 || m.config.CallTimeoutMS != 3600000 || m.config.FailureThreshold != 20 || m.config.CooldownSeconds != 3600 {
		t.Fatal("unbounded config")
	}
	for i := 0; i < 400; i++ {
		release, err := m.acquire(t.Context(), fmt.Sprint(i))
		if err != nil {
			t.Fatal(err)
		}
		release(false, true, false)
	}
	if len(m.states) > 256 {
		t.Fatal("unbounded registry")
	}
	m = New(Config{})
	var releases []func(bool, bool, bool)
	for i := 0; i < 256; i++ {
		r, err := m.acquire(t.Context(), fmt.Sprint(i))
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, r)
	}
	if _, err := m.acquire(t.Context(), "extra"); err == nil {
		t.Fatal("active state evicted")
	}
	for _, release := range releases {
		release(false, true, false)
	}
}

func TestCallTimeoutReturnsErrorResultAndReleasesSlot(t *testing.T) {
	m := New(Config{MaxConcurrent: 1, CallTimeoutMS: 20})
	slow := m.Wrap("server", fixture(func(ctx context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
		<-ctx.Done()
		return actool.Result{}, ctx.Err()
	}))
	start := time.Now()
	res, err := slow.Call(t.Context(), nil, nil)
	if err != nil || !res.IsError || !strings.Contains(res.Flatten(), "mcp_tool_timeout") {
		t.Fatalf("timeout result = (%q, %v), want mcp_tool_timeout error result", res.Flatten(), err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("MCP call timeout did not return promptly")
	}

	fast := m.Wrap("server", fixture(func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
		return actool.Text("ok"), nil
	}))
	res, err = fast.Call(t.Context(), nil, nil)
	if err != nil || res.Flatten() != "ok" {
		t.Fatalf("timeout leaked the server slot: result=%q err=%v", res.Flatten(), err)
	}
}

func TestDisabledPreservesOriginalTool(t *testing.T) {
	base := fixture(func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
		return actool.Text("ok"), nil
	})
	if New(Config{Disabled: true}).Wrap("key", base) != base {
		t.Fatal("disabled guard changed tool")
	}
}
