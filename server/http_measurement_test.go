package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/httpmeasure"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/artex/resourceguard"
	actool "github.com/Autumn-27/norma/tool"
)

func measurementFixture(t *testing.T) (*Server, *Task, *Task) {
	t.Helper()
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("explicit isolated database required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Close() })
	manager := &Manager{pg: pg, assets: pg.Assets(), egress: guard.NewEgressGuard(), tasks: map[string]*Task{}}
	tasks := []*Task{}
	for i := 0; i < 2; i++ {
		row, err := pg.CreateTask("HTTP measurement fixture", "independent proof required", nil, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		task := &Task{ID: strconv.FormatInt(row.ID, 10), Store: pg.Exploration(row.ExplorationID)}
		manager.tasks[task.ID] = task
		tasks = append(tasks, task)
		t.Cleanup(func() { pg.DeleteTask(row.ID) })
	}
	s := &Server{m: manager, ctx: t.Context(), engine: NewEngine(manager)}
	return s, tasks[0], tasks[1]
}

func allowMeasurementLocalhost(t *testing.T, s *Server, task *Task) {
	t.Helper()
	if _, err := s.m.pg.Assets().AddAgentScope(measurementTaskID(task), "ip", "127.0.0.1", "local fixture", "agent"); err != nil {
		t.Fatal(err)
	}
}

func measurementContext(t *Task) context.Context {
	return agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: measurementTaskID(t), ExplorationID: t.Store.ID(), IntentID: 123})
}

func TestHTTPMeasurementPersistsOnlyObservationAndCannotProveGoal(t *testing.T) {
	s, task, other := measurementFixture(t)
	allowMeasurementLocalhost(t, s, task)
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Query().Get("case") == "test" {
			time.Sleep(250 * time.Millisecond)
		}
		fmt.Fprint(w, "private response fixture")
	}))
	defer srv.Close()
	tools := s.httpMeasurementTools()
	measure := workflowTool(t, tools, "measure_http_pair")
	read := workflowTool(t, tools, "get_http_measurement")
	raw, _ := json.Marshal(httpmeasure.Plan{BaselineURL: srv.URL + "/observe?case=base", TestURL: srv.URL + "/observe?case=test", Pairs: 3, MinimumEffectMS: 200, Headers: map[string]string{"Authorization": "Bearer target-fixture-secret"}})
	output, err := measure.Call(measurementContext(task), raw, &actool.ToolContext{ToolUseID: "actual-measurement-call"})
	if err != nil || output.IsError {
		t.Fatal(err, output.Flatten())
	}
	var result struct {
		Saved       bool               `json:"saved"`
		ID          int64              `json:"measurement_node_id"`
		Measurement httpmeasure.Result `json:"measurement"`
	}
	if json.Unmarshal([]byte(output.Flatten()), &result) != nil || !result.Saved || result.ID <= 0 {
		t.Fatal("observation not saved")
	}
	if requests.Load() != 8 || result.Measurement.Analysis.Signal != "repeatable_delay" || result.Measurement.VulnerabilityConfirmed {
		t.Fatalf("incorrect measured observation: %+v", result)
	}
	node, err := task.Store.GetNode(result.ID)
	if err != nil || node == nil || node.Kind != db.KindHint || node.Origin != measurementOrigin {
		t.Fatal("measurement became a fact/finding", err)
	}
	for _, secret := range []string{"target-fixture-secret", "private response fixture", srv.URL} {
		if strings.Contains(string(node.Payload), secret) {
			t.Fatal("copied raw request/response into graph")
		}
	}
	readBack := workflowCall(t, measurementContext(task), read, map[string]any{"measurement_node_id": result.ID}, false)
	if !strings.Contains(readBack, "actual-measurement-call") {
		t.Fatal("lost call attribution on continuation")
	}
	workflowCall(t, measurementContext(other), read, map[string]any{"measurement_node_id": result.ID}, true)
	workflowCall(t, context.Background(), read, map[string]any{"measurement_node_id": result.ID}, true)
	goal, err := task.Store.AddGoal(map[string]any{"text": "prove actual vulnerability"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	toolset := agent.NewToolSet(task.Store, "fixture")
	prove := workflowTool(t, toolset.AllDomainTools(), "prove_goal")
	workflowCall(t, measurementContext(task), prove, map[string]any{"goal_id": goal, "evidence_id": result.ID, "reason": "a delay is not impact proof"}, true)
	goalNode, _ := task.Store.GetNode(goal)
	if goalNode.State != "open" || toolset.GoalMet {
		t.Fatal("latency observation completed a goal")
	}
	if err := s.m.pg.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.m.pg.SnapshotTaskArchive(measurementTaskID(task))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(snapshot.Tables["exploration_nodes"]), "actual-measurement-call") {
		t.Fatal("archive snapshot lost observations")
	}
	if s.engine.inflightCount(task.ID) != 0 {
		t.Fatal("task operation lease leaked")
	}
}

func TestHTTPMeasurementScopeResourcesAndSecretsBlockBeforeRequests(t *testing.T) {
	s, task, _ := measurementFixture(t)
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); fmt.Fprint(w, "ok") }))
	defer srv.Close()
	plan := httpmeasure.Plan{BaselineURL: srv.URL + "/", TestURL: srv.URL + "/?test=1", Pairs: 3}
	tool := workflowTool(t, s.httpMeasurementTools(), "measure_http_pair")
	workflowCall(t, measurementContext(task), tool, plan, true)
	allowMeasurementLocalhost(t, s, task)
	s.resources = resourceguard.New(resourceguard.Config{}) // unknown pressure, fail closed
	workflowCall(t, measurementContext(task), tool, plan, true)
	s.resources = nil
	s.m.egress.AddFingerprint("platform-key", "platform-secret-value")
	plan.Headers = map[string]string{"Authorization": "platform-secret-value"}
	workflowCall(t, measurementContext(task), tool, plan, true)
	plan.Headers = nil
	plan.TestURL = srv.URL + "/?secret=platform%2Dsecret%2Dvalue"
	workflowCall(t, measurementContext(task), tool, plan, true)
	if requests.Load() != 0 {
		t.Fatal("preflight refusal made a request")
	}
	if s.engine.inflightCount(task.ID) != 0 {
		t.Fatal("preflight leaked operation lease")
	}
}

func TestHTTPMeasurementSavesPartialAfterCancellation(t *testing.T) {
	s, task, _ := measurementFixture(t)
	allowMeasurementLocalhost(t, s, task)
	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer srv.Close()
	ctx, cancel := context.WithCancel(measurementContext(task))
	defer cancel()
	raw, _ := json.Marshal(httpmeasure.Plan{BaselineURL: srv.URL + "/", TestURL: srv.URL + "/?test=1", Pairs: 3})
	done := make(chan actool.Result, 1)
	go func() {
		result, _ := s.runHTTPMeasurement(ctx, raw, &actool.ToolContext{ToolUseID: "cancelled-call"})
		done <- result
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("fixture request not started")
	}
	cancel()
	select {
	case output := <-done:
		var result struct {
			Saved       bool               `json:"saved"`
			Measurement httpmeasure.Result `json:"measurement"`
		}
		if json.Unmarshal([]byte(output.Flatten()), &result) != nil || !output.IsError || !result.Saved || result.Measurement.Status != "cancelled" || result.Measurement.Attempts != 1 {
			t.Fatal("cancelled observation lost", output.Flatten())
		}
	case <-time.After(6 * time.Second):
		t.Fatal("cancelled measurement did not settle")
	}
	if s.engine.inflightCount(task.ID) != 0 {
		t.Fatal("cancelled measurement lease leaked")
	}
}

func TestHTTPMeasurementSeedPreservesOptOutAndVerifierTaskIdentity(t *testing.T) {
	s, task, _ := measurementFixture(t)
	s.seedHTTPMeasurementTools()
	if _, err := s.m.pg.Exec(`UPDATE tools SET enabled=false WHERE key='measure_http_pair'`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`UPDATE tools SET enabled=true WHERE key='measure_http_pair'`) })
	s.seedHTTPMeasurementTools()
	var enabled bool
	if err := s.m.pg.QueryRow(`SELECT enabled FROM tools WHERE key='measure_http_pair'`).Scan(&enabled); err != nil || enabled {
		t.Fatal("manual opt-out revived", err)
	}
	if _, err := s.m.pg.Exec(`INSERT INTO agents(key,name,role,enabled) VALUES('verifier','fixture verifier','assistant',true) ON CONFLICT(key) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	finding, err := s.m.pg.AddFinding(measurementTaskID(task), 0, "timing fixture", "candidate", db.SeverityLow, "candidate only", "fixture evidence", "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.DeleteFinding(finding) })
	check, conv, _, err := s.m.pg.CreateFindingCheck(t.Context(), finding, db.FindingCheckKindVerify)
	if err != nil || check == nil || conv == nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM conversations WHERE id=$1`, conv.ID) })
	linked, err := s.httpMeasurementTask(intercept.WithConvID(t.Context(), conv.ID))
	if err != nil || linked != task {
		t.Fatal("verifier lost source task scope", err)
	}
}

func TestHTTPMeasurementInvalidProxyNeverGoesDirect(t *testing.T) {
	s, task, _ := measurementFixture(t)
	s.m.globalProxy = "broken://host"
	if client, _, err := s.httpMeasurementClient(t.Context(), task); err == nil || client != nil {
		t.Fatal("invalid proxy fell back to direct")
	}
}

func TestHTTPMeasurementCatalogReadFailureDoesNotExposeTools(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("explicit isolated DB required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	oldResolve := agent.ToolResolve
	oldTraffic := agent.FindingTrafficBindingEnabled
	t.Cleanup(func() { agent.ToolResolve = oldResolve; agent.FindingTrafficBindingEnabled = oldTraffic })
	wireTools(pg, nil)
	pg.Close()
	tools := []actool.CoreTool{}
	for _, name := range []string{"Read", "measure_http_pair", "get_http_measurement"} {
		tools = append(tools, actool.Build(actool.Spec{Name: name}))
	}
	resolved := agent.ToolResolve(t.Context(), "worker", tools)
	if len(resolved) != 1 || resolved[0].Name() != "Read" {
		t.Fatal("failed catalog exposed a measurement tool")
	}
}
