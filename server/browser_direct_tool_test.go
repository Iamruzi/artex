package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

func TestDirectBrowserToolKeepsSkillGateAndSchema(t *testing.T) {
	const name = "mcp__browser__browser_navigate"
	called := false
	base := actool.Build(actool.Spec{
		Name: name,
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"url": map[string]any{"type": "string"}},
			"required":   []any{"url"},
		},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			called = true
			return actool.Text("navigated"), nil
		},
	})
	unlock := actool.NewUnlockSet()
	tool := &directBrowserTool{CoreTool: base, unlock: unlock}
	if tool.InputSchema()["properties"] == nil {
		t.Fatal("browser schema was hidden")
	}
	result, err := tool.Call(context.Background(), json.RawMessage(`{"url":"https://example.test"}`), nil)
	if err != nil || !result.IsError || called {
		t.Fatalf("locked browser tool ran: result=%+v err=%v called=%t", result, err, called)
	}
	unlock.Add(name)
	result, err = tool.Call(context.Background(), json.RawMessage(`{"url":"https://example.test"}`), nil)
	if err != nil || result.IsError || !called {
		t.Fatalf("unlocked browser tool did not run: result=%+v err=%v called=%t", result, err, called)
	}
}
