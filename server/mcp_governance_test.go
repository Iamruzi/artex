package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/mcpguard"
	actool "github.com/Autumn-27/norma/tool"
)

func TestMCPAssemblySharesCircuitAcrossAgentRuns(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("requires explicit isolated test database")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Close() })
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method == "tools/call" {
			calls.Add(1)
			http.Error(w, "fixture unavailable", 503)
			return
		}
		if req.ID == 0 {
			w.WriteHeader(202)
			return
		}
		result := any(map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "serverInfo": map[string]any{"name": "fixture", "version": "1"}})
		if req.Method == "tools/list" {
			result = map[string]any{"tools": []any{map[string]any{"name": "observe", "description": "local fixture", "inputSchema": map[string]any{"type": "object"}}}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	defer srv.Close()
	item := &db.MCPServer{Name: "fixturegov", Transport: "http", URL: srv.URL, Enabled: true}
	item.ID, err = pg.SaveMCP(item)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.DeleteMCP(item.ID) })
	for _, key := range []string{"planner", "worker"} {
		role, err := pg.GetAgentByKey(key)
		if err != nil || role == nil {
			t.Fatal("missing fixture role", err)
		}
		if err = pg.ToggleVisibility(role.ID, "mcp", item.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	original := agent.ToolAugment
	t.Cleanup(func() { agent.ToolAugment = original })
	// Load defaults regardless of any developer machine config.
	t.Setenv("ARTEX_CONFIG", t.TempDir()+"/absent.json")
	wireAgentAugment(pg, t.TempDir(), nil)
	for i, key := range []string{"planner", "worker", "planner", "worker"} {
		tools, _, cleanup := agent.ToolAugment(t.Context(), key)
		if cleanup != nil {
			defer cleanup()
		}
		var selected actool.CoreTool
		for _, tool := range tools {
			if tool.Name() == "mcp__fixturegov__observe" {
				selected = tool
			}
		}
		if selected == nil {
			t.Fatal("MCP missing from assembled tools")
		}
		result, err := selected.Call(context.Background(), []byte(`{}`), nil)
		if !result.IsError {
			t.Fatal("transport failure became success")
		}
		if errors.Is(err, mcpguard.ErrBlocked) != (i == 3) {
			t.Fatalf("run %d: circuit not shared: %v", i, err)
		}
	}
	if calls.Load() != 3 {
		t.Fatalf("blocked run reached endpoint: %d", calls.Load())
	}
}

func TestMCPEndpointChangeUsesIndependentHealthIdentity(t *testing.T) {
	original := &db.MCPServer{ID: 11, Name: "fixture", Transport: "http", URL: "http://127.0.0.1/old", Env: []byte(`{"Authorization":"fixture-secret"}`)}
	key := mcpIsolationKey(original)
	if len(key) != 64 {
		t.Fatal("raw configuration leaked as identity")
	}
	changed := *original
	changed.URL = "http://127.0.0.1/new"
	if key == mcpIsolationKey(&changed) {
		t.Fatal("edited endpoint inherited old circuit")
	}
	changed = *original
	changed.Env = []byte(`{"Authorization":"replacement-secret"}`)
	if key == mcpIsolationKey(&changed) {
		t.Fatal("rotated credentials inherited old circuit")
	}
}
