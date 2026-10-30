package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/pocsearch"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

type knowledgeTransport func(*http.Request) (*http.Response, error)

func (f knowledgeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

const fixtureCVE = "CVE-2099-90001"
const fixtureRepo = "fixture/CVE-2099-90001"
const fixtureSource = "# Synthetic PoC reference\nThis text must be read but never executed."
const knowledgeNVD = `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2099-90001","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"Synthetic fixture only."}],"references":[{"url":"https://github.com/fixture/CVE-2099-90001","tags":["Exploit"]}],"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:fixture:pan-os:*:*:*:*:*:*:*:*","versionStartIncluding":"10.0","versionEndExcluding":"11.0"}]}]}]}}]}`

func knowledgeFixture(t *testing.T) (*Server, *Task, *Task, *int) {
	t.Helper()
	s, task, other := measurementFixture(t)
	preflight, receipt := agent.KnowledgePreflight, agent.KnowledgeReceipt
	augment, resolve, admit := agent.ToolAugment, agent.ToolResolve, agent.ResourceAdmission
	t.Cleanup(func() {
		agent.KnowledgePreflight = preflight
		agent.KnowledgeReceipt = receipt
		agent.ToolAugment = augment
		agent.ToolResolve = resolve
		agent.ResourceAdmission = admit
	})
	s.initKnowledge()
	calls := 0
	s.knowledgeClient.HTTP.Transport = knowledgeTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		var body string
		switch {
		case r.URL.Host == "services.nvd.nist.gov":
			body = knowledgeNVD
		case r.URL.Host == "api.github.com" && r.URL.Path == "/search/repositories":
			body = `{"total_count":1,"items":[{"full_name":"fixture/CVE-2099-90001","html_url":"https://github.com/fixture/CVE-2099-90001","description":"Synthetic candidate, never a real exploit"}]}`
		case r.URL.Host == "api.github.com" && r.URL.Path == "/repos/fixture/CVE-2099-90001/readme":
			raw, _ := json.Marshal(map[string]any{"type": "file", "path": "README.md", "sha": strings.Repeat("a", 40), "html_url": "https://github.com/fixture/CVE-2099-90001/blob/main/README.md", "size": len(fixtureSource), "encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(fixtureSource))})
			body = string(raw)
		default:
			return nil, fmt.Errorf("unexpected request %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	keys := []string{lookupKey("nvd", pocsearch.Query{Product: "PAN-OS", Version: "10.2.3"}), lookupKey("nvd", pocsearch.Query{CVE: fixtureCVE}), lookupKey("github", fixtureCVE), lookupKey("github-source", []string{fixtureCVE, fixtureRepo, ""})}
	for _, key := range keys {
		s.m.pg.Exec(`DELETE FROM knowledge_lookup_cache WHERE key=$1`, key)
	}
	t.Cleanup(func() {
		for _, key := range keys {
			s.m.pg.Exec(`DELETE FROM knowledge_lookup_cache WHERE key=$1`, key)
		}
		s.m.pg.Exec(`DELETE FROM knowledge_events WHERE task_id IN ($1,$2)`, measurementTaskID(task), measurementTaskID(other))
	})
	return s, task, other, &calls
}

func TestKnowledgeNativeToolsDraftIsolationAndSourceProvenance(t *testing.T) {
	s, task, other, calls := knowledgeFixture(t)
	ctx := measurementContext(task)
	tools := s.knowledgeTools()
	add := workflowTool(t, tools, "kb_add")
	raw := workflowCall(t, ctx, add, map[string]any{"title": "fixture private experience", "kind": "negative", "product": "PAN-OS", "content": "A failed prerequisite is not proof of no vulnerability.", "source_ref": "synthetic fixture"}, false)
	var result struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal([]byte(raw), &result); err != nil || result.ID == 0 {
		t.Fatal(raw, err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM knowledge_entries WHERE id=$1`, result.ID) })
	entry, err := s.m.pg.GetKnowledge(t.Context(), result.ID, 0, true)
	if err != nil || entry.State != "draft" || entry.ScopeTaskID == nil || *entry.ScopeTaskID != measurementTaskID(task) {
		t.Fatal("draft scope not host-owned", err)
	}
	workflowCall(t, ctx, add, map[string]any{"title": "forged", "kind": "context", "content": "fixture", "source_ref": "fixture", "state": "active", "verified": true}, true)
	get := workflowTool(t, tools, "kb_get")
	workflowCall(t, measurementContext(other), get, map[string]any{"id": result.ID}, true)
	entry.State = "active"
	if _, err = s.m.pg.SaveKnowledge(t.Context(), *entry); err != nil {
		t.Fatal(err)
	}
	read := workflowCall(t, ctx, get, map[string]any{"id": result.ID}, false)
	if !strings.Contains(read, entry.SHA256) || !strings.Contains(read, "failed prerequisite") {
		t.Fatal("missing actual reference body")
	}
	workflowCall(t, measurementContext(other), get, map[string]any{"id": result.ID}, true)
	workflowCall(t, ctx, workflowTool(t, tools, "poc_get"), map[string]any{"cve": fixtureCVE, "repository": fixtureRepo}, true)
	workflowCall(t, ctx, workflowTool(t, tools, "poc_search"), map[string]any{"cve": fixtureCVE}, false)
	code := workflowCall(t, ctx, workflowTool(t, tools, "poc_get"), map[string]any{"cve": fixtureCVE, "repository": fixtureRepo}, false)
	if !strings.Contains(code, fixtureSource[:25]) || !strings.Contains(code, `"blob_sha"`) {
		t.Fatal("did not return source provenance")
	}
	workflowCall(t, ctx, workflowTool(t, tools, "poc_get"), map[string]any{"cve": fixtureCVE, "repository": "arbitrary/repo"}, true)
	if *calls != 2 {
		t.Fatalf("unexpected public requests %d", *calls)
	}
	workflowCall(t, ctx, workflowTool(t, tools, "poc_get"), map[string]any{"cve": fixtureCVE, "repository": fixtureRepo}, false)
	if *calls != 2 {
		t.Fatal("cached source was fetched repeatedly")
	}
}

func TestKnowledgePreflightUsesTaskAssetsAndHonorsDisabledTools(t *testing.T) {
	s, task, other, calls := knowledgeFixture(t)
	entry, err := s.m.pg.SaveKnowledge(t.Context(), db.KnowledgeEntry{Title: "CVE-only reference", Kind: "context", CVEs: []string{fixtureCVE}, Content: "Synthetic reference without product label", Summary: "CVE_ONLY_KNOWLEDGE_FIXTURE", SourceRef: "synthetic cve-only fixture", State: "active"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM knowledge_entries WHERE id=$1`, entry.ID) })
	asset, err := s.m.pg.Assets().UpsertHTTPService(db.UpsertHTTPServiceReq{URL: fmt.Sprintf("https://knowledge-%s.invalid/", task.ID), Technologies: []string{"PAN-OS:10.2.3"}, TaskID: measurementTaskID(task)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM assets WHERE id=$1`, asset) })
	ctx := measurementContext(task)
	if block := s.knowledgePreflight(ctx, "planner", nil); block != "" || *calls != 0 {
		t.Fatal("unbound tools still performed lookup")
	}
	block := s.knowledgePreflight(agent.WithRunInfo(t.Context(), agent.RunInfo{TaskID: measurementTaskID(task)}), "planner", s.knowledgeTools())
	if !strings.Contains(block, fixtureCVE) || !strings.Contains(block, fixtureRepo) || !strings.Contains(block, "CVE_ONLY_KNOWLEDGE_FIXTURE") || len(block) > 14000 || *calls != 2 {
		t.Fatalf("preflight missing candidates or over budget: %d calls=%d block=%s", len(block), *calls, block)
	}
	if got := s.knowledgePreflight(agent.WithRunInfo(t.Context(), agent.RunInfo{TaskID: measurementTaskID(other)}), "planner", s.knowledgeTools()); got != "" {
		t.Fatal("other task inherited unrelated asset hints")
	}
	if err = s.m.pg.SetPaused(measurementTaskID(task), true); err != nil {
		t.Fatal(err)
	}
	if got := s.knowledgePreflight(agent.WithRunInfo(t.Context(), agent.RunInfo{TaskID: measurementTaskID(task)}), "planner", s.knowledgeTools()); got != "" {
		t.Fatal("paused task queried public sources")
	}
	if *calls != 2 {
		t.Fatal("unrelated/paused work performed lookup")
	}
	if err = s.m.pg.SetPaused(measurementTaskID(task), false); err != nil {
		t.Fatal(err)
	}
	if s.m.egress != nil {
		s.m.egress.AddFingerprint("fixture", "PAN-OS")
	}
	// Platform secrets longer than the fingerprint minimum are blocked before HTTP.
	s.m.egress.AddFingerprint("fixture", "secret-product-fixture")
	if _, _, err = s.lookupCVEs(t.Context(), pocsearch.Query{Product: "secret-product-fixture"}); err == nil || !strings.Contains(err.Error(), "敏感信息") {
		t.Fatal("secret did not hit egress gate", err)
	}
}

type knowledgeProviderFixture struct {
	step                      int
	preflightSeen, sourceSeen bool
}

func (p *knowledgeProviderFixture) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	panic("non-streaming fixture")
}
func (p *knowledgeProviderFixture) Complete(_ context.Context, r llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.step++
	m := llm.Message{Role: llm.RoleAssistant}
	all, _ := json.Marshal(r.Messages)
	if p.step == 1 {
		p.preflightSeen = strings.Contains(string(all), "knowledge-preflight") && strings.Contains(string(all), fixtureCVE) && strings.Contains(string(all), fixtureRepo)
		if !p.preflightSeen {
			return m, "", llm.Usage{}, fmt.Errorf("automatic reference block absent from model request")
		}
		m.Content = []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "fixture-poc-read", Name: "poc_get", Input: []byte(`{"cve":"CVE-2099-90001","repository":"fixture/CVE-2099-90001"}`)}}
		return m, "tool_use", llm.Usage{}, nil
	}
	p.sourceSeen = strings.Contains(string(all), "This text must be read but never executed.") && strings.Contains(string(all), "blob_sha")
	if !p.sourceSeen {
		return m, "", llm.Usage{}, fmt.Errorf("source tool result absent from next request")
	}
	m.Content = []llm.ContentBlock{llm.TextBlock("REFERENCE_READ_NOT_EXECUTED")}
	return m, "end_turn", llm.Usage{}, nil
}

func TestKnowledgeAutomaticPlannerRequestAndSourceToolChain(t *testing.T) {
	s, task, _, calls := knowledgeFixture(t)
	asset, err := s.m.pg.Assets().UpsertHTTPService(db.UpsertHTTPServiceReq{URL: fmt.Sprintf("https://knowledge-chain-%s.invalid/", task.ID), Technologies: []string{"PAN-OS:10.2.3"}, TaskID: measurementTaskID(task)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM assets WHERE id=$1`, asset) })
	agent.ToolResolve = nil
	agent.ResourceAdmission = nil
	agent.ToolAugment = func(context.Context, string) ([]actool.CoreTool, agent.DeferredInfo, func()) {
		return s.knowledgeTools(), agent.DeferredInfo{}, func() {}
	}
	provider := &knowledgeProviderFixture{}
	planner := agent.NewPlanner(provider, "fixture", t.TempDir(), nil, 0, 4)
	planner.SetNonStreaming(func() bool { return true })
	met, _, err := planner.Plan(t.Context(), measurementTaskID(task), s.m.pg.Assets(), task.Store, "Synthetic reference fixture", nil, nil)
	if err != nil || met || !provider.preflightSeen || !provider.sourceSeen || provider.step != 2 || *calls != 3 {
		t.Fatalf("chain: met=%v err=%v steps=%d calls=%d", met, err, provider.step, *calls)
	}
	events, err := s.m.pg.KnowledgeEvents(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	prepared, observed := "", ""
	sourceReturned := false
	for _, e := range events {
		if e.TaskID == nil || *e.TaskID != measurementTaskID(task) {
			continue
		}
		if e.Action == "preflight" && e.Status == "prepared" {
			prepared = e.SHA256
		}
		if e.Action == "preflight" && e.Status == "model_request" {
			observed = e.SHA256
		}
		if e.Action == "poc_get" && e.Status == "returned" && e.Bytes > len(fixtureSource) {
			sourceReturned = true
		}
	}
	if prepared == "" || prepared != observed || !sourceReturned {
		t.Fatal("request receipt did not match prepared content")
	}
	var findings int
	if err = s.m.pg.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, measurementTaskID(task)).Scan(&findings); err != nil || findings != 0 {
		t.Fatal("search/source became finding", err)
	}
}

func TestKnowledgeHTTPRequiresLogin(t *testing.T) {
	s := &Server{}
	for _, path := range []string{"/api/knowledge", "/api/knowledge/public-search"} {
		w := httptest.NewRecorder()
		s.requireAuth(http.HandlerFunc(s.knowledgeList)).ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 401 {
			t.Fatal("knowledge endpoint exposed without login")
		}
	}
}

func TestKnowledgeAutomaticWorkerPreflightAndSourceChain(t *testing.T) {
	s, task, _, calls := knowledgeFixture(t)
	asset, err := s.m.pg.Assets().UpsertHTTPService(db.UpsertHTTPServiceReq{URL: fmt.Sprintf("https://knowledge-worker-%s.invalid/", task.ID), Technologies: []string{"PAN-OS:10.2.3"}, TaskID: measurementTaskID(task)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM assets WHERE id=$1`, asset) })
	id, err := task.Store.AddIntent(map[string]any{"summary": "Synthetic reference-only fixture", "asset_ids": []int64{asset}}, 5, []int64{asset}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := task.Store.GetNode(id)
	if err != nil {
		t.Fatal(err)
	}
	agent.ToolResolve = nil
	agent.ResourceAdmission = nil
	agent.ToolAugment = func(context.Context, string) ([]actool.CoreTool, agent.DeferredInfo, func()) {
		return s.knowledgeTools(), agent.DeferredInfo{}, func() {}
	}
	provider := &knowledgeProviderFixture{}
	worker := agent.NewWorker(provider, "fixture", t.TempDir(), nil, 0, 4)
	worker.SetNonStreaming(func() bool { return true })
	_, _, err = worker.Execute(t.Context(), "worker-fixture", measurementTaskID(task), s.m.pg.Assets(), task.Store, intent, nil, nil, nil, nil)
	if err != nil || !provider.preflightSeen || !provider.sourceSeen || provider.step != 2 || *calls != 3 {
		t.Fatalf("worker chain err=%v steps=%d calls=%d", err, provider.step, *calls)
	}
	events, err := s.m.pg.KnowledgeEvents(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	observed := false
	for _, e := range events {
		if e.TaskID != nil && *e.TaskID == measurementTaskID(task) && e.IntentID == id && e.Agent == "worker" && e.Status == "model_request" {
			observed = true
		}
	}
	if !observed {
		t.Fatal("worker model request not attributed to current intent")
	}
}

func TestKnowledgeCatalogOptOutCannotBeBypassedByPreflight(t *testing.T) {
	s, task, _, calls := knowledgeFixture(t)
	for _, key := range []string{"kb_search", "cve_search", "poc_search"} {
		var enabled bool
		if err := s.m.pg.QueryRow(`SELECT enabled FROM tools WHERE key=$1`, key).Scan(&enabled); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.m.pg.Exec(`UPDATE tools SET enabled=$1 WHERE key=$2`, enabled, key) })
		if _, err := s.m.pg.Exec(`UPDATE tools SET enabled=false WHERE key=$1`, key); err != nil {
			t.Fatal(err)
		}
	}
	wireTools(s.m.pg, nil)
	resolved := agent.ToolResolve(t.Context(), "planner", s.knowledgeTools())
	if block := s.knowledgePreflight(agent.WithRunInfo(t.Context(), agent.RunInfo{TaskID: measurementTaskID(task)}), "planner", resolved); block != "" || *calls != 0 {
		t.Fatal("disabled catalog tools still injected/searched")
	}
	for _, tool := range resolved {
		if tool.Name() == "kb_search" || tool.Name() == "cve_search" || tool.Name() == "poc_search" {
			t.Fatal("disabled native tool survived resolution")
		}
	}
}
