package agent

import (
	"context"
	"encoding/json"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func TestRepeatBudgetStopsCurrentRunWithoutCancellingTask(t *testing.T) {
	parent, tc, _ := learningFixture(t)
	ctx, cancel := withRepeatBudget(parent)
	defer cancel(nil)
	raw := json.RawMessage(`{"assets":[{"type":"endpoint","url":"https://example.com/"}]}`)
	observeExecutionLearning(ctx, "insert_assets", raw, tc, "method is required", true)
	observeExecutionLearning(ctx, "insert_assets", raw, tc, "method is required", true)
	calls := 0
	tool := governTool(actool.Build(actool.Spec{Name: "insert_assets", Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
		calls++
		return actool.Text("unexpected"), nil
	}}))
	tool.Call(ctx, raw, tc)
	if ctx.Err() != nil {
		t.Fatal("first blocked call cancelled before correction opportunity")
	}
	tool.Call(ctx, raw, tc)
	if calls != 0 || ctx.Err() == nil || context.Cause(ctx) != AbortRepeatedToolFailure || parent.Err() != nil {
		t.Fatal("loop was not stopped at the run boundary")
	}
	other, stop := withRepeatBudget(parent)
	defer stop(nil)
	if other.Err() != nil {
		t.Fatal("different run inherited cancellation")
	}
}
