package agent

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func TestMainAgentTimeoutInterruptsToolAndPreservesSettlement(t *testing.T) {
	oldAugment, oldResolve := ToolAugment, ToolResolve
	t.Cleanup(func() { ToolAugment, ToolResolve = oldAugment, oldResolve })
	ToolAugment = nil
	var interrupted atomic.Bool
	ToolResolve = func(context.Context, string, []actool.CoreTool) []actool.CoreTool {
		return []actool.CoreTool{actool.Build(actool.Spec{
			Name: "Read", Schema: map[string]any{"type": "object"},
			Run: func(ctx context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
				<-ctx.Done()
				interrupted.Store(true)
				return actool.Result{}, ctx.Err()
			},
		})}
	}
	provider := &sideAgentProvider{path: "controlled-fixture"}
	main := NewMainAgent(provider, "fixture", t.TempDir(), nil, 100000, 0)
	main.SetNonStreaming(func() bool { return true })
	main.SetRunTimeout(100 * time.Millisecond)
	parent, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	text, err := main.Chat(parent, 1, 0, nil, &db.ExplorationStore{}, "local fixture", "read the fixture", nil, nil, nil, nil)
	if err != nil || !strings.Contains(text, "main finished") {
		t.Fatalf("budget prevented settlement: reply=%q err=%v", text, err)
	}
	if !interrupted.Load() || provider.calls != 2 || parent.Err() != nil {
		t.Fatalf("tool/settlement lifecycle: interrupted=%v calls=%d parent=%v", interrupted.Load(), provider.calls, parent.Err())
	}
}
