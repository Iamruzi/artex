package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
)

func TestEndpointHTMLSchemaMigrationPreservesBindingsAndOverrides(t *testing.T) {
	pg := openIntranetTestDB(t)
	before, err := pg.GetTool("insert_assets")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if before == nil {
			_, _ = pg.Exec(`DELETE FROM tools WHERE key='insert_assets'`)
			return
		}
		agents, _ := json.Marshal(before.Agents)
		_ = pg.UpsertToolForce(before.Key, before.Description, before.Schema, agents)
		_, _ = pg.Exec(`UPDATE tools SET enabled=$1 WHERE key='insert_assets'`, before.Enabled)
	})
	tool := agent.NewToolSet(nil, "").InsertAssetsTool()
	raw, _ := json.Marshal(tool.InputSchema())
	var schema map[string]any
	json.Unmarshal(raw, &schema)
	props := schema["properties"].(map[string]any)
	delete(props, "html_path")
	delete(props, "base_url")
	props["assets"].(map[string]any)["description"] = "custom description retained"
	schema["required"] = []string{"assets"}
	raw, _ = json.Marshal(schema)
	if err := pg.UpsertToolForce("insert_assets", "custom tool description", raw, json.RawMessage(`["custom-role"]`)); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exec(`UPDATE tools SET enabled=false WHERE key='insert_assets'`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := seedEndpointHTMLImportSchema(pg); err != nil {
			t.Fatal(err)
		}
	}
	after, err := pg.GetTool("insert_assets")
	if err != nil {
		t.Fatal(err)
	}
	if after.Enabled || len(after.Agents) != 1 || after.Agents[0] != "custom-role" || !strings.Contains(string(after.Schema), "custom description retained") {
		t.Fatal("catalog overrides lost")
	}
	if !strings.Contains(string(after.Schema), "html_path") || strings.Contains(string(after.Schema), `"required": ["assets"]`) {
		t.Fatal("new import mode not available")
	}
	if strings.Count(after.Description, "HTML 导入可只传") != 1 {
		t.Fatal("migration not idempotent")
	}
}
