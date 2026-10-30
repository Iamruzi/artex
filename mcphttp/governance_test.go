package mcphttp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/mcpguard"
)

func TestMCPHTTPTransportFailuresAreDistinctFromApplicationErrors(t *testing.T) {
	for _, mode := range []string{"server-error", "invalid-json", "mismatched-id", "invalid-version", "application-error", "rpc-error", "unauthorized"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				var req rpcRequest
				_ = json.NewDecoder(r.Body).Decode(&req)
				switch mode {
				case "server-error":
					http.Error(w, "fixture unavailable", 503)
				case "invalid-json":
					fmt.Fprint(w, "{malformed")
				case "unauthorized":
					http.Error(w, "login required", 401)
				case "rpc-error":
					_ = json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "bad arguments"}})
				case "mismatched-id":
					_ = json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: req.ID + 1, Result: json.RawMessage(`{"content":[{"type":"text","text":"another request succeeded"}]}`)})
				case "invalid-version":
					_ = json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "1.0", ID: req.ID, Result: json.RawMessage(`{"content":[]}`)})
				default:
					result, _ := json.Marshal(map[string]any{"isError": true, "content": []any{map[string]any{"type": "text", "text": "connection closed; rejected by user"}}})
					_ = json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result})
				}
			}))
			defer srv.Close()
			client := &Client{server: "fixture", url: srv.URL, http: srv.Client()}
			manager := mcpguard.New(mcpguard.Config{FailureThreshold: 2})
			tool := manager.Wrap("fixture", client.wrap(remoteTool{Name: "observe"}))
			for i := 0; i < 4; i++ {
				result, err := tool.Call(t.Context(), json.RawMessage(`{}`), nil)
				if !result.IsError {
					t.Fatal("failure lost error status")
				}
				transportFailure := mode == "server-error" || mode == "invalid-json" || mode == "mismatched-id" || mode == "invalid-version"
				shouldBlock := transportFailure && i >= 2
				if errors.Is(err, mcpguard.ErrBlocked) != shouldBlock {
					t.Fatalf("request %d: unexpected circuit state: %v", i, err)
				}
			}
			expected := int32(4)
			if mode == "server-error" || mode == "invalid-json" || mode == "mismatched-id" || mode == "invalid-version" {
				expected = 2
			}
			if requests.Load() != expected {
				t.Fatalf("blocked calls reached server: %d", requests.Load())
			}
		})
	}
}

func TestMCPResponseAllocationCaps(t *testing.T) {
	// An ordinary 60KB result still works; only transport-sized abuse is refused.
	for _, size := range []int{60000, maxResponseBytes + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req rpcRequest
				_ = json.NewDecoder(r.Body).Decode(&req)
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"content":[{"type":"text","text":"`, req.ID)
				_, _ = strings.NewReader(strings.Repeat("x", size)).WriteTo(w)
				fmt.Fprint(w, `"}]}}`)
			}))
			defer srv.Close()
			client := &Client{server: "fixture", url: srv.URL, http: srv.Client()}
			manager := mcpguard.New(mcpguard.Config{FailureThreshold: 1})
			tool := manager.Wrap("cap", client.wrap(remoteTool{Name: "observe"}))
			result, _ := tool.Call(t.Context(), []byte(`{}`), nil)
			if result.IsError != (size > maxResponseBytes) {
				t.Fatal("incorrect response size outcome")
			}
			_, err := tool.Call(t.Context(), []byte(`{}`), nil)
			if errors.Is(err, mcpguard.ErrBlocked) != (size > maxResponseBytes) {
				t.Fatal("oversized response did not affect transport health")
			}
		})
	}
	if _, err := readBoundedLine(bufio.NewReader(strings.NewReader(strings.Repeat("x", maxResponseBytes+1) + "\n"))); err == nil {
		t.Fatal("unbounded legacy SSE line")
	}
	// Multi-line events must not bypass a per-line cap.
	event := strings.Repeat("data: "+strings.Repeat("x", 4096)+"\n", maxResponseBytes/4096+1)
	if _, err := parseSSE(strings.NewReader(event), 1); err == nil {
		t.Fatal("unbounded multiline SSE event")
	}
}

func TestCallerCancellationDoesNotOpenTransportCircuit(t *testing.T) {
	started := make(chan struct{})
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if count.Add(1) == 1 {
			close(started)
			<-r.Context().Done()
			return
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"content":[{"type":"text","text":"ok"}]}}`, req.ID)
	}))
	defer srv.Close()
	client := &Client{server: "fixture", url: srv.URL, http: srv.Client()}
	tool := mcpguard.New(mcpguard.Config{FailureThreshold: 1}).Wrap("fixture", client.wrap(remoteTool{Name: "observe"}))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _, _ = tool.Call(ctx, []byte(`{}`), nil) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("request never started")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled request did not return")
	}
	result, err := tool.Call(t.Context(), []byte(`{}`), nil)
	if err != nil || result.IsError {
		t.Fatal("cancelled caller poisoned healthy endpoint", err)
	}
}
