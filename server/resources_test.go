package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/resourceguard"
)

func TestResourceAdmissionBeforeClaimAndHumanResume(t *testing.T) {
	e := &Engine{resources: resourceguard.New(resourceguard.Config{})}
	// A denied admission must return before touching any task/database state.
	if e.runWorkerStep(context.Background(), nil, "test", nil) {
		t.Fatal("claimed under unknown pressure")
	}
	if err := e.runDetachedIntent(context.Background(), nil, 1, "id", "continue", "continue"); err == nil {
		t.Fatal("human continuation bypassed resource guard")
	}
}

func TestResourceEndpointAndCustomExecutorAdmission(t *testing.T) {
	s := &Server{resources: resourceguard.New(resourceguard.Config{})}
	w := httptest.NewRecorder()
	s.resourceStatus(w, httptest.NewRequest(http.MethodGet, "/api/resources", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"unknown"`) {
		t.Fatalf("bad resource snapshot %s", w.Body.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// No manager/DB needed: resource rejection precedes any process/http work.
	res, _ := s.runCommandTool(ctx, json.RawMessage(`{"command":"must not execute"}`), nil, nil)
	if !res.IsError || !strings.Contains(res.Flatten(), "resource_blocked") {
		t.Fatal("custom editor execution bypassed resource gate")
	}
}

func TestShellQuoteMatchesNativeShell(t *testing.T) {
	value := "a'b $(whoami); `x` & end"
	if got := shellQuoteForOS(value, "windows"); got != "'a''b $(whoami); `x` & end'" {
		t.Fatal(got)
	}
	if shellQuoteForOS(value, "linux") != shellQuote(value) {
		t.Fatal("changed POSIX quoting")
	}
}

func TestExecPythonExitAndTimeoutAreErrors(t *testing.T) {
	interp, err := exec.LookPath("python3")
	if err != nil {
		interp, err = exec.LookPath("python")
	}
	if err != nil {
		t.Skip("Python unavailable")
	}
	out, err := execPython(context.Background(), interp, "exit", "import sys; print('partial'); sys.exit(9)", nil, t.TempDir(), nil, 5*time.Second)
	if err == nil || !strings.Contains(out, "partial") {
		t.Fatalf("nonzero exit reported as success: %q %v", out, err)
	}
	_, err = execPython(context.Background(), interp, "timeout", "import time; time.sleep(10)", nil, t.TempDir(), nil, 150*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("timeout reported as success: %v", err)
	}
}
