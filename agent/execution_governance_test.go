package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/norma/agentcore"
	actool "github.com/Autumn-27/norma/tool"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSDKNetworkToolsAreGovernedBeforeSessionConstruction(t *testing.T) {
	opts := agentcore.Options{EnableWebFetch: true, EnableWebSearch: true, WebSearchBackend: "ddgs"}
	governSessionOptions(&opts)
	if opts.EnableWebFetch || opts.EnableWebSearch {
		t.Fatal("SDK can append ungoverned network tools")
	}
	found := false
	for _, tool := range opts.Tools {
		if _, ok := tool.(*governedTool); !ok {
			t.Fatalf("unguarded %s", tool.Name())
		}
		if tool.Name() == "WebFetch" {
			found = true
		}
	}
	if !found {
		t.Fatal("WebFetch lost")
	}
}

func TestResourceGatePreservesPermissionAndBlocksHandler(t *testing.T) {
	old := ResourceAdmission
	defer func() { ResourceAdmission = old }()
	ResourceAdmission = func(context.Context, string) (func(), error) { return nil, fmt.Errorf("pressure") }
	called := false
	base := actool.Build(actool.Spec{Name: "Bash", Description: "schema preserved", Schema: map[string]any{"type": "object"}, Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
		called = true
		return actool.Text("ok"), nil
	}})
	tool := governTool(guardPanic(base))
	dir := t.TempDir()
	r, e := tool.Call(context.Background(), json.RawMessage(`{}`), &actool.ToolContext{WorkingDir: dir, ToolUseID: "call-1"})
	if e != nil || !r.IsError || called || tool.Description() != base.Description() {
		t.Fatal("resource gate bypass or schema changed")
	}
	b, e := os.ReadFile(filepath.Join(dir, "execution-events.jsonl"))
	if e != nil || !strings.Contains(string(b), `"status":"resource_blocked"`) {
		t.Fatalf("lost execution outcome: %s %v", b, e)
	}
	base = actool.Build(actool.Spec{Name: "TaskStop", Schema: map[string]any{"type": "object"}, Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
		called = true
		return actool.Text("stopped"), nil
	}})
	_, _ = governTool(guardPanic(base)).Call(context.Background(), json.RawMessage(`{}`), nil)
	if !called {
		t.Fatal("cleanup was resource blocked")
	}
}

func TestPanicRecordedAsFailureAndJournalBounded(t *testing.T) {
	base := actool.Build(actool.Spec{Name: "Read", Schema: map[string]any{"type": "object"}, Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) { panic("test") }})
	dir := t.TempDir()
	tool := governTool(guardPanic(base))
	r, e := tool.Call(context.Background(), json.RawMessage(`{}`), &actool.ToolContext{WorkingDir: dir})
	if e != nil || !r.IsError {
		t.Fatal("panic escaped")
	}
	path := filepath.Join(dir, "execution-events.jsonl")
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `"status":"failed"`) {
		t.Fatalf("panic not failed %s", b)
	}
	if e := os.WriteFile(path, []byte(strings.Repeat("x", (2<<20)+1)), 0600); e != nil {
		t.Fatal(e)
	}
	writeExecutionRecord(dir, ExecutionRecord{Status: "returned"})
	fi, e := os.Stat(path)
	if e != nil || fi.Size() > 1024 {
		t.Fatalf("journal not rotated %v", e)
	}
}
