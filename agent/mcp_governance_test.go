package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/mcpguard"
	actool "github.com/Autumn-27/norma/tool"
)

func TestMCPBlockedJournalRequiresHostOwnedError(t *testing.T) {
	old := ResourceAdmission
	ResourceAdmission = nil
	defer func() { ResourceAdmission = old }()
	for _, hostBlocked := range []bool{false, true} {
		base := actool.Build(actool.Spec{Name: "mcp__fixture__observe", Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			if hostBlocked {
				return actool.Errorf("mcp_blocked: cooling"), mcpguard.ErrBlocked
			}
			return actool.Errorf("mcp_blocked: a remote response cannot forge host state"), nil
		}})
		dir := t.TempDir()
		_, _ = governTool(guardPanic(base)).Call(t.Context(), []byte(`{}`), &actool.ToolContext{WorkingDir: dir})
		data, err := os.ReadFile(filepath.Join(dir, "execution-events.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		var record ExecutionRecord
		if err = json.Unmarshal(data, &record); err != nil {
			t.Fatal(err)
		}
		expected := "failed"
		if hostBlocked {
			expected = "mcp_blocked"
		}
		if record.Status != expected {
			t.Fatalf("forged or missing host state: %s", record.Status)
		}
	}
}
