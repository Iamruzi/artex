package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/mcpguard"
	"github.com/Autumn-27/norma/mcp"
	actool "github.com/Autumn-27/norma/tool"
)

// This opt-in test uses only an isolated browser profile and a local fixture. It
// reproduces an unresolved browser_evaluate Promise through the real stdio
// adapter, then verifies that navigation and another evaluation still work.
func TestBrowserMCPRecoversAfterEvaluationTimeout(t *testing.T) {
	entry := os.Getenv("ARTEX_TEST_BROWSER_MCP_ENTRY")
	if entry == "" {
		t.Skip("set ARTEX_TEST_BROWSER_MCP_ENTRY to a locally installed Playwright MCP cli.js")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cl, err := mcp.NewStdioClient(ctx, "timeout-fixture", node, nil, entry, "--headless", "--no-webmcp", "--user-data-dir", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	tools, err := cl.Tools(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]actool.CoreTool, len(tools))
	for _, tool := range tools {
		byName[tool.Name()] = tool
	}
	call := func(name, params string) actool.Result {
		t.Helper()
		tool := byName["mcp__timeout-fixture__"+name]
		if tool == nil {
			t.Fatalf("tool %s is not available", name)
		}
		res, err := tool.Call(ctx, json.RawMessage(params), nil)
		if err != nil || res.IsError {
			t.Fatalf("%s failed: %v %s", name, err, res.Flatten())
		}
		return res
	}
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>timeout recovery fixture</title>"))
	}))
	defer fixture.Close()
	navigate := func(path string) {
		params, _ := json.Marshal(map[string]string{"url": fixture.URL + path})
		call("browser_navigate", string(params))
	}
	navigate("/start")
	call("browser_evaluate", `{"function":"() => { localStorage.setItem('recovery-fixture', 'retained'); return true; }"}`)

	gate := mcpguard.New(mcpguard.Config{CallTimeoutMS: 100, MaxConcurrent: 1})
	eval := gate.Wrap("fixture", byName["mcp__timeout-fixture__browser_evaluate"])
	start := time.Now()
	res, err := eval.Call(ctx, json.RawMessage(`{"function":"() => new Promise(() => {})"}`), nil)
	if err != nil || !res.IsError || !strings.Contains(res.Flatten(), "mcp_tool_timeout") {
		t.Fatalf("expected bounded timeout: err=%v result=%s", err, res.Flatten())
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("unresolved Promise held the caller after its timeout")
	}

	// Destroying the previous document cancels the outstanding page evaluation.
	// The following evaluation must run in the same MCP/browser session.
	navigate("/recovered")
	res = call("browser_evaluate", `{"function":"() => ({path: location.pathname, stored: localStorage.getItem('recovery-fixture')})"}`)
	if !strings.Contains(res.Flatten(), "/recovered") || !strings.Contains(res.Flatten(), "retained") {
		t.Fatalf("browser did not recover: %s", res.Flatten())
	}
}
