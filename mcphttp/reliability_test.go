package mcphttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

func TestSSESetupCancellationClosesStalledConnection(t *testing.T) {
	for _, phase := range []string{"headers", "endpoint"} {
		t.Run(phase, func(t *testing.T) {
			started, released, disconnected := make(chan struct{}), make(chan struct{}), make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if phase == "endpoint" {
					w.Header().Set("Content-Type", "text/event-stream")
					w.(http.Flusher).Flush()
				}
				close(started)
				select {
				case <-r.Context().Done():
					close(disconnected)
				case <-released:
				}
			}))
			defer srv.Close()
			defer close(released)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				cl, err := NewSSE(ctx, "fixture", srv.URL, nil, false)
				if cl != nil {
					_ = cl.Close()
				}
				done <- err
			}()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("setup never reached endpoint")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("setup returned %v, want caller cancellation", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancelled SSE setup did not return")
			}
			select {
			case <-disconnected:
			case <-time.After(time.Second):
				t.Fatal("cancelled setup left its connection open")
			}
		})
	}
}

func TestToolsPaginationIsCompleteAndBounded(t *testing.T) {
	for _, mode := range []string{"two-pages", "empty-list", "missing-tools", "cursor-cycle", "duplicate-name", "too-many-tools", "too-many-pages", "oversized-cursor", "byte-budget", "second-page-error"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					ID     int `json:"id"`
					Params struct {
						Cursor string `json:"cursor"`
					} `json:"params"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
					return
				}
				n := calls.Add(1)
				if mode == "second-page-error" && n > 1 {
					http.Error(w, "fixture page unavailable", http.StatusServiceUnavailable)
					return
				}
				name, next := "first", "second-page"
				if n > 1 {
					if mode == "two-pages" && req.Params.Cursor != "second-page" {
						t.Error("pagination cursor not forwarded")
					}
					name, next = "second", ""
				}
				switch mode {
				case "cursor-cycle":
					next = "same-cursor"
				case "duplicate-name":
					name = "first"
				case "too-many-pages":
					name, next = fmt.Sprint(n), fmt.Sprint(n)
				case "oversized-cursor":
					next = strings.Repeat("x", 20*1024)
				}
				tools := []any{map[string]any{"name": name, "inputSchema": map[string]any{"type": "object"}}}
				switch mode {
				case "empty-list":
					tools, next = []any{}, ""
				case "missing-tools":
					tools = nil
				case "byte-budget":
					tools = []any{map[string]any{"name": name, "description": strings.Repeat("x", maxResponseBytes/2+512)}}
				}
				if mode == "too-many-tools" {
					for i := 0; i < 4096; i++ {
						tools = append(tools, map[string]any{"name": fmt.Sprintf("tool%d", i)})
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"tools": tools, "nextCursor": next}})
			}))
			defer srv.Close()
			cl := &Client{server: "fixture", url: srv.URL, http: srv.Client()}
			tools, err := cl.Tools(t.Context())
			if mode == "two-pages" {
				if err != nil || len(tools) != 2 || calls.Load() != 2 {
					t.Fatalf("incomplete discovery: tools=%d calls=%d err=%v", len(tools), calls.Load(), err)
				}
			} else if mode == "empty-list" {
				if err != nil || len(tools) != 0 || calls.Load() != 1 {
					t.Fatalf("valid empty list rejected: %v", err)
				}
			} else if err == nil || len(tools) != 0 {
				t.Fatalf("invalid pagination became partial success: tools=%d calls=%d err=%v", len(tools), calls.Load(), err)
			}
		})
	}
}

func TestMalformedToolResultsCannotBecomeSuccess(t *testing.T) {
	for _, payload := range []string{`null`, `{}`, `{"content":[null]}`, `{"content":[{"type":"text","text":4}]}`} {
		t.Run(payload, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req rpcRequest
				_ = json.NewDecoder(r.Body).Decode(&req)
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":%s}`, req.ID, payload)
			}))
			defer srv.Close()
			cl := &Client{server: "fixture", url: srv.URL, http: srv.Client()}
			if _, err := cl.Call(t.Context(), "observe", nil); err == nil {
				t.Fatal("malformed backend result became success")
			}
			res, err := cl.wrap(remoteTool{Name: "observe"}).Call(t.Context(), []byte(`{}`), nil)
			if err != nil || !res.IsError {
				t.Fatal("malformed Agent result became success", err)
			}
		})
	}
}

func TestStructuredToolResultsReachAgentAndBackend(t *testing.T) {
	for _, fixture := range []struct {
		name, result, want string
		isError            bool
	}{
		{"text", `{"content":[{"type":"text","text":"legacy"}]}`, "legacy", false},
		{"structured-only", `{"structuredContent":{"count":3,"items":["record-a"]}}`, `"count":3`, false},
		{"mixed", `{"content":[{"type":"text","text":"summary"}],"structuredContent":{"count":3}}`, `"count":3`, false},
		{"structured-error", `{"isError":true,"structuredContent":{"reason":"expired-session"}}`, "expired-session", true},
		{"resource-link", `{"content":[{"type":"resource_link","uri":"https://invalid.example/result.json","name":"evidence"}]}`, "https://invalid.example/result.json", false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req rpcRequest
				_ = json.NewDecoder(r.Body).Decode(&req)
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":%s}`, req.ID, fixture.result)
			}))
			defer srv.Close()
			cl := &Client{server: "fixture", url: srv.URL, http: srv.Client()}
			got, err := cl.Call(t.Context(), "observe", map[string]any{})
			if (err != nil) != fixture.isError || !strings.Contains(got, fixture.want) {
				t.Fatalf("backend lost result: %q, %v", got, err)
			}
			res, err := cl.wrap(remoteTool{Name: "observe"}).Call(t.Context(), []byte(`{}`), nil)
			if err != nil || res.IsError != fixture.isError || !strings.Contains(res.Flatten(), fixture.want) {
				t.Fatalf("Agent lost result: %+v, %v", res, err)
			}
			if fixture.name == "text" && (got != "legacy" || res.Flatten() != "legacy") {
				t.Fatal("plain-text compatibility changed")
			}
			if fixture.name == "mixed" {
				if !json.Valid([]byte(got)) || !strings.Contains(res.Flatten(), "summary") {
					t.Fatal("backend JSON contract or Agent summary was lost")
				}
			}
		})
	}
}

func TestCancelledSSECallDoesNotWaitForAnotherCall(t *testing.T) {
	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request any
		_ = json.NewDecoder(r.Body).Decode(&request)
		close(started)
		<-r.Context().Done()
	}))
	defer srv.Close()
	cl := &Client{server: "fixture", legacySSE: true, messageURL: srv.URL, http: srv.Client(),
		legacyGate: make(chan struct{}, 1), pending: map[int]chan *rpcResponse{}}
	firstCtx, firstCancel := context.WithCancel(t.Context())
	defer firstCancel()
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_, _ = cl.Call(firstCtx, "observe", nil)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first request never started")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	done := make(chan error, 1)
	go func() { _, err := cl.Call(ctx, "observe", nil); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiting call ignored cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled caller waited for occupied SSE gate")
	}
	firstCancel()
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first call did not release gate")
	}
}

func TestHTTPSessionCloseIsBoundedAndIdempotent(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		<-r.Context().Done()
	}))
	defer srv.Close()
	cl := &Client{url: srv.URL, http: srv.Client(), sessionID: "fixture-session"}
	start := time.Now()
	_ = cl.Close()
	_ = cl.Close()
	if requests.Load() != 1 || time.Since(start) > 4*time.Second {
		t.Fatalf("cleanup was unbounded or repeated: requests=%d elapsed=%s", requests.Load(), time.Since(start))
	}
}

func TestStructuredResultStillSpillsToArtifact(t *testing.T) {
	payload := `{"structuredContent":{"evidence":"` + strings.Repeat("x", 5000) + `"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":%s}`, req.ID, payload)
	}))
	defer srv.Close()
	dir := t.TempDir()
	cl := &Client{server: "fixture", url: srv.URL, http: srv.Client()}
	res, err := cl.wrap(remoteTool{Name: "observe"}).Call(t.Context(), []byte(`{}`), &actool.ToolContext{WorkingDir: dir, OutputDir: dir, MaxOutputChars: 80})
	if err != nil || res.IsError || !strings.Contains(res.Flatten(), "persisted-output") {
		t.Fatalf("structured output bypassed Capture: %v", err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "output-*.txt"))
	if err != nil || len(files) != 1 {
		t.Fatalf("missing full output: %v", err)
	}
	full, err := os.ReadFile(files[0])
	if err != nil || !strings.Contains(string(full), strings.Repeat("x", 5000)) {
		t.Fatal("artifact lost complete structured result", err)
	}
}
