package agent

import (
	"context"
	"errors"
	"github.com/Autumn-27/norma/agentcore"
	actool "github.com/Autumn-27/norma/tool"
	"testing"
	"time"
)

func TestPlannerCoordinationPreservesEvidenceAndDispatch(t *testing.T) {
	var tools []actool.CoreTool
	for _, name := range []string{"Bash", "WebFetch", "Read", "graph_overview", "add_intent", "steer_work", "shell_open", "shell_send"} {
		tools = append(tools, actool.Build(actool.Spec{Name: name, Schema: map[string]any{"type": "object"}}))
	}
	filtered := plannerCoordinationTools(tools)
	if len(filtered) != 4 || len(tools) != 8 {
		t.Fatal("lost coordination tools or mutated input")
	}
	for _, tool := range filtered {
		if tool.Name() == "Bash" || tool.Name() == "WebFetch" || tool.Name() == "shell_send" || tool.Name() == "shell_open" {
			t.Fatal("planner retained direct execution")
		}
	}
}

func TestPlannerHardBackstopCancelsHangingModelButKeepsTaskAlive(t *testing.T) {
	parent := context.Background()
	round, stop := plannerRoundContext(parent, 20*time.Millisecond, 20*time.Millisecond)
	defer stop()
	start := time.Now()
	_, _, err := captureRun(round, agentcore.Options{Provider: hangProv{}, MaxTurns: 1}, "hang", nil)
	if !errors.Is(err, context.DeadlineExceeded) || context.Cause(round) != AbortRunHardTimeout || parent.Err() != nil || time.Since(start) > time.Second {
		t.Fatalf("planning round did not stop safely: %v", err)
	}
}
