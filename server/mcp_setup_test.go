package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/mcphttp"
)

func TestMCPSetupClosesFailedSessionsImmediately(t *testing.T) {
	for _, failedPhase := range []string{"initialize", "tools/list"} {
		t.Run(failedPhase, func(t *testing.T) {
			var deleted atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					if r.Header.Get("Mcp-Session-Id") != "fixture-session" {
						t.Error("cleanup omitted session identity")
					}
					deleted.Add(1)
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var req struct {
					ID     int    `json:"id"`
					Method string `json:"method"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				w.Header().Set("Mcp-Session-Id", "fixture-session")
				if req.Method == failedPhase {
					http.Error(w, "fixture failed", http.StatusServiceUnavailable)
					return
				}
				if req.ID == 0 {
					w.WriteHeader(http.StatusAccepted)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{}})
			}))
			defer srv.Close()
			cl, tools, err := connectAndListMCP(t.Context(), &db.MCPServer{Name: "fixture", Transport: "http", URL: srv.URL})
			if cl != nil || tools != nil || err == nil || deleted.Load() != 1 {
				t.Fatalf("failed session leaked or returned success: tools=%d deletes=%d err=%v", len(tools), deleted.Load(), err)
			}
		})
	}
}

func TestScopeSentryReadsMixedStructuredMCPAssets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.ID == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		result := any(map[string]any{})
		if req.Method == "tools/call" {
			result = map[string]any{
				"content":           []any{map[string]any{"type": "text", "text": "one asset found"}},
				"structuredContent": map[string]any{"list": []any{map[string]any{"host": "fixture.invalid"}}},
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	defer srv.Close()
	cl, err := mcphttp.New(t.Context(), "fixture", srv.URL, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	s := &Server{}
	items, truncated, err := s.ssPageAll(t.Context(), cl, "subdomain", nil, 100)
	if err != nil || truncated || len(items) != 1 {
		t.Fatalf("structured result broke asset sync: count=%d truncated=%v err=%v", len(items), truncated, err)
	}
	var item struct {
		Host string `json:"host"`
	}
	if err := json.Unmarshal(items[0], &item); err != nil || item.Host != "fixture.invalid" {
		t.Fatal("asset fields changed", err)
	}
}

func TestMCPSetupHonorsCallerCancellation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request any
		_ = json.NewDecoder(r.Body).Decode(&request)
		close(started)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := connectAndListMCP(ctx, &db.MCPServer{Name: "fixture", Transport: "http", URL: srv.URL})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("setup never started")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("setup ignored cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("setup did not stop")
	}
}
