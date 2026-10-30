package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/modelprompt"
)

func TestModelPromptPreviewDoesNotNeedModelOrDatabase(t *testing.T) {
	s := &Server{}
	for _, body := range []string{`{"mode":"compact-tools"}`, `{"mode":"custom","text":"fixture"}`, `{"mode":""}`} {
		w := httptest.NewRecorder()
		s.modelPromptPreview(w, httptest.NewRequest("POST", "/", strings.NewReader(body)))
		if w.Code != 200 {
			t.Fatalf("preview %d %s", w.Code, w.Body.String())
		}
		var result map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result["inference_performed"] != false {
			t.Fatal("preview claims an inference")
		}
	}
	w := httptest.NewRecorder()
	s.modelPromptPreview(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"mode":"custom"}`)))
	if w.Code != 400 {
		t.Fatal("invalid config accepted")
	}
}

func TestModelPromptPreviewRequiresAuthentication(t *testing.T) {
	s := &Server{jwtKey: testJWTKey, authkv: newMemKV()}
	w := httptest.NewRecorder()
	s.requireAuth(http.HandlerFunc(s.modelPromptPreview)).ServeHTTP(w, httptest.NewRequest("POST", "/api/llm/prompt/preview", strings.NewReader(`{"mode":"compact-tools"}`)))
	if w.Code != 401 {
		t.Fatalf("unauthed preview returned %d", w.Code)
	}
}

func TestModelPromptEvaluationPersistsActualComparisonAndMarksStale(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	activeBefore, err := m.PG().ActiveProfile()
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	var adaptedRequests atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var body struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
			Tools []any `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			http.Error(w, "bad request", 400)
			return
		}
		if len(body.Messages) > 0 && strings.Contains(body.Messages[0].Content, (modelprompt.Config{Mode: "compact-tools"}).Digest()) {
			adaptedRequests.Add(1)
		}
		message := map[string]any{"role": "assistant"}
		if len(body.Tools) > 0 && body.Messages[len(body.Messages)-1].Role != "tool" {
			message["tool_calls"] = []any{map[string]any{"id": "fixture-tool", "type": "function", "function": map[string]any{"name": "add_numbers", "arguments": `{"a":19,"b":23}`}}}
		} else if len(body.Tools) > 0 {
			message["content"] = "42"
		} else if strings.Contains(body.Messages[len(body.Messages)-1].Content, "code 1") {
			message["content"] = `{"confirmed":false}`
		} else {
			message["content"] = `{"issue":"sql_injection","fix":"parameterized_query"}`
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": message, "finish_reason": "stop"}}})
	}))
	defer endpoint.Close()
	p := &db.LLMProfile{Name: "prompt-eval-fixture", Format: "openai", Model: "fixture", BaseURL: endpoint.URL, APIKey: "fixture-key", PoolExclude: true, ModelPrompt: modelprompt.Config{Mode: "compact-tools"}}
	id, err := m.PG().SaveProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	p.ID = id
	t.Cleanup(func() {
		m.PG().Exec(`DELETE FROM llm_profiles WHERE id=$1`, id)
	})
	s := newAdmissionTestServer(m, nil)
	req := httptest.NewRequest("POST", "/", nil)
	req.SetPathValue("id", strconv.FormatInt(id, 10))
	s.promptEvalMu.Lock()
	locked := httptest.NewRecorder()
	s.modelPromptEvaluate(locked, req)
	s.promptEvalMu.Unlock()
	if locked.Code != 409 || requests.Load() != 0 {
		t.Fatal("concurrent evaluation made a request")
	}
	w := httptest.NewRecorder()
	s.modelPromptEvaluate(w, req)
	if w.Code != 200 {
		t.Fatalf("evaluation %d %s", w.Code, w.Body.String())
	}
	var result modelprompt.Evaluation
	if err = json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Requests != 8 || requests.Load() != 8 || adaptedRequests.Load() != 4 || result.AdaptedPassed != 3 || result.BaselinePassed != 3 || !result.Completed || result.Digest != p.ModelPrompt.Digest() {
		t.Fatalf("bad result %+v calls=%d", result, requests.Load())
	}
	if strings.Contains(w.Body.String(), "fixture-key") {
		t.Fatal("response exposes API key")
	}
	activeAfter, err := m.PG().ActiveProfile()
	if err != nil {
		t.Fatal(err)
	}
	beforeID, afterID := int64(0), int64(0)
	if activeBefore != nil {
		beforeID = activeBefore.ID
	}
	if activeAfter != nil {
		afterID = activeAfter.ID
	}
	if beforeID != afterID {
		t.Fatal("evaluation changed the active profile")
	}
	get := httptest.NewRequest("GET", "/", nil)
	get.SetPathValue("id", strconv.FormatInt(id, 10))
	w = httptest.NewRecorder()
	s.modelPromptLastEvaluation(w, get)
	if !strings.Contains(w.Body.String(), `"stale":false`) {
		t.Fatal(w.Body.String())
	}
	p.BaseURL = endpoint.URL + "/changed"
	if _, err = m.PG().SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.modelPromptLastEvaluation(w, get)
	if !strings.Contains(w.Body.String(), `"stale":true`) {
		t.Fatal("endpoint edit did not invalidate comparison")
	}
	// Legacy profile clients must not erase model instructions by omitting them.
	legacy := map[string]any{"id": id, "name": p.Name, "format": p.Format, "model": p.Model, "base_url": p.BaseURL, "pool_exclude": true}
	body, _ := json.Marshal(legacy)
	w = httptest.NewRecorder()
	s.pgSaveProfile(w, httptest.NewRequest("POST", "/", bytes.NewReader(body)))
	if w.Code != 200 {
		t.Fatalf("legacy save %d %s", w.Code, w.Body.String())
	}
	got, err := m.PG().ProfileByID(id)
	if err != nil || got.ModelPrompt.Mode != "compact-tools" {
		t.Fatal("legacy client erased prompt")
	}
	if cfg, ok := s.loadProfileConfig(id); !ok || cfg.ModelPrompt.Mode != "compact-tools" {
		t.Fatal("profile binding lost prompt config")
	}
	if _, err = m.PG().Exec(`DELETE FROM llm_profiles WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err = m.PG().QueryRow(`SELECT count(*) FROM llm_prompt_evaluations WHERE profile_id=$1`, id).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatal("deleted profile left an evaluation result")
	}
}
