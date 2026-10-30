package agent

import (
	"context"
	"encoding/json"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/modelprompt"
	"github.com/Autumn-27/norma/llm"
)

type promptCapture struct{ requests []llm.CompletionRequest }

func (p *promptCapture) Complete(_ context.Context, r llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.requests = append(p.requests, r)
	return llm.Message{}, "", llm.Usage{}, nil
}
func (p *promptCapture) Stream(_ context.Context, r llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) { p.requests = append(p.requests, r) }
}

func TestModelPromptRequestsPreserveHostAndDoNotAccumulate(t *testing.T) {
	inner := &promptCapture{}
	config := modelprompt.Config{Mode: "custom", Text: "supplement fixture"}
	provider, err := WithModelPrompt(inner, config)
	if err != nil {
		t.Fatal(err)
	}
	system := make([]string, 2, 8)
	system[0] = "host permissions"
	system[1] = "dynamic scope"
	req := llm.CompletionRequest{System: system, DynamicBoundary: 1, Tools: []llm.ToolSchema{{Name: "host_tool"}}}
	provider.Complete(context.Background(), req)
	provider.Complete(context.Background(), req)
	for range provider.Stream(context.Background(), req) {
	}
	for _, got := range inner.requests {
		if len(got.System) != 3 || got.System[0] != system[0] || got.System[1] != system[1] || got.DynamicBoundary != 1 || len(got.Tools) != 1 {
			t.Fatalf("host request mutated: %+v", got)
		}
		if !strings.Contains(got.System[2], config.Digest()) {
			t.Fatal("missing digest")
		}
	}
	if len(req.System) != 2 || system[:cap(system)][2] != "" {
		t.Fatal("modified caller's backing array")
	}
	p, err := WithModelPrompt(inner, modelprompt.Config{})
	if err != nil || p != inner {
		t.Fatal("disabled wrapper changed provider")
	}
}

func TestModelPromptActuallyTravelsOnWire(t *testing.T) {
	config := modelprompt.Config{Mode: "compact-tools"}
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]any
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Error(err)
		}
		bytes, _ := json.Marshal(raw)
		body = string(bytes)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"fixture"},"finish_reason":"stop"}]}`))
	}))
	defer server.Close()
	cfg := ConfigFrom("openai", "fixture", server.URL, "test-key", "")
	cfg.ModelPrompt = config
	provider, err := cfg.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = provider.Complete(context.Background(), llm.CompletionRequest{System: []string{"host-marker"}, Messages: []llm.Message{llm.UserText("fixture")}, MaxTokens: 8})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, config.Digest()) || !strings.Contains(body, "host-marker") {
		t.Fatal("wire request lacks prompt supplement or original instructions")
	}
}
