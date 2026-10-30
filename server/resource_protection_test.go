package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/resourceguard"
	actool "github.com/Autumn-27/norma/tool"
)

func TestResourceProtectionTogglePersistsWithoutResumingTasks(t *testing.T) {
	s, task, _ := measurementFixture(t)
	s.resources = resourceguard.New(resourceguard.Config{})
	before, exists, err := s.m.pg.GetSetting(resourceProtectionSetting)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if exists {
			s.m.pg.SetSetting(resourceProtectionSetting, before)
		} else {
			s.m.pg.DeleteSetting(resourceProtectionSetting)
		}
	})
	s.m.pg.DeleteSetting(resourceProtectionSetting)
	s.restoreResourceProtection()
	if !s.resources.Snapshot().ProtectionEnabled {
		t.Fatal("missing setting should default on")
	}
	if err = s.m.pg.SetPaused(measurementTaskID(task), true); err != nil {
		t.Fatal(err)
	}
	intent, err := task.Store.AddIntent(map[string]any{"summary": "manual stop"}, 1, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err = task.Store.SetNodeState(intent, "stopped"); err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []string{"false", "true", "false"} {
		w := httptest.NewRecorder()
		s.setResourceProtection(w, httptest.NewRequest(http.MethodPut, "/api/resources/protection", strings.NewReader(`{"enabled":`+enabled+`}`)))
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"protection_enabled":`+enabled) {
			t.Fatalf("toggle failed: %d %s", w.Code, w.Body.String())
		}
		value, ok, err := s.m.pg.GetSetting(resourceProtectionSetting)
		if err != nil || !ok || value != enabled {
			t.Fatal("choice not durable", err)
		}
		restarted := &Server{m: s.m, resources: resourceguard.New(resourceguard.Config{})}
		restarted.restoreResourceProtection()
		if restarted.resources.Snapshot().ProtectionEnabled != (enabled == "true") {
			t.Fatal("restart lost choice")
		}
		row, err := s.m.pg.GetTask(measurementTaskID(task))
		if err != nil || !row.Paused {
			t.Fatal("toggle resumed task", err)
		}
		node, err := task.Store.GetNode(intent)
		if err != nil || node.State != "stopped" {
			t.Fatal("toggle revived stopped intent", err)
		}
	}
	// Per-request measurement checks with an existing outer lease must also
	// honor the toggle, rather than rejecting a raw pressure/unknown snapshot.
	previousAdmission, previousAugment, previousResolve := agent.ResourceAdmission, agent.ToolAugment, agent.ToolResolve
	t.Cleanup(func() {
		agent.ResourceAdmission = previousAdmission
		agent.ToolAugment = previousAugment
		agent.ToolResolve = previousResolve
	})
	agent.ToolAugment = nil
	agent.ToolResolve = nil
	agent.ResourceAdmission = func(context.Context, string) (func(), error) { return s.resources.TryAcquire("tool") }
	base := actool.Build(actool.Spec{Name: "measure_http_pair", Schema: map[string]any{"type": "object"}, Run: func(ctx context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
		if !agent.HasResourceLease(ctx) {
			t.Fatal("fixture did not traverse outer lease")
		}
		if _, err := s.admitMeasurement(ctx); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		s.resources.SetProtectionEnabled(true)
		if _, err := s.admitMeasurement(ctx); err == nil {
			t.Fatal("measurement missed reenabled protection")
		}
		return actool.Text("checked"), nil
	}})
	tools, _, cleanup := agent.AugmentTools(t.Context(), "worker", []actool.CoreTool{base})
	defer cleanup()
	result, err := tools[0].Call(t.Context(), json.RawMessage(`{}`), nil)
	if err != nil || result.IsError {
		t.Fatal("measurement ignored disabled protection", result.Flatten(), err)
	}
}

func TestResourceProtectionRejectsInvalidInputAndUnauthorized(t *testing.T) {
	s := &Server{resources: resourceguard.New(resourceguard.Config{})}
	for _, input := range []string{`{}`, `null`, `{"enabled":null}`, `{"enabled":"false"}`, `{"enabled":false,"extra":true}`, `{"enabled":false} {}`, strings.Repeat(" ", 1100) + `{"enabled":false}`} {
		w := httptest.NewRecorder()
		s.setResourceProtection(w, httptest.NewRequest(http.MethodPut, "/api/resources/protection", strings.NewReader(input)))
		if w.Code != 400 || !s.resources.Snapshot().ProtectionEnabled {
			t.Fatalf("bad input accepted: %d", w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.requireAuth(http.HandlerFunc(s.setResourceProtection)).ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/resources/protection", strings.NewReader(`{"enabled":false}`)))
	if w.Code != 401 || !s.resources.Snapshot().ProtectionEnabled {
		t.Fatal("unauthorized toggle accepted")
	}
}

func TestResourceProtectionSaveFailureDoesNotChangeLiveChoice(t *testing.T) {
	s, _, _ := measurementFixture(t)
	s.resources = resourceguard.New(resourceguard.Config{})
	closed, err := db.Open(os.Getenv("ARTEX_PG_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	s.m = &Manager{pg: closed}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.setResourceProtection(w, httptest.NewRequest(http.MethodPut, "/api/resources/protection", strings.NewReader(`{"enabled":false}`)))
	if w.Code != 500 || !s.resources.Snapshot().ProtectionEnabled {
		t.Fatal("failed save changed live choice")
	}
	s.restoreResourceProtection()
	if !s.resources.Snapshot().ProtectionEnabled {
		t.Fatal("unreadable setting disabled protection")
	}
}
