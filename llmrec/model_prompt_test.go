package llmrec

import (
	"encoding/json"
	"github.com/Autumn-27/artex/modelprompt"
	"github.com/Autumn-27/norma/llm"
	"testing"
)

func TestModelPromptRecordedViewMatchesAppliedRequest(t *testing.T) {
	config := modelprompt.Config{Mode: "compact-tools"}
	recorder := Wrap(completeProvider{}, nil, "fixture", "fixture", "", "", nil).WithModelPrompt(config)
	req := llm.CompletionRequest{System: []string{"host"}}
	var recorded struct {
		System []string `json:"system"`
	}
	if err := json.Unmarshal([]byte(recorder.serializeRequest(req)), &recorded); err != nil {
		t.Fatal(err)
	}
	if len(recorded.System) != 2 || recorded.System[1] != config.Render() || len(req.System) != 1 {
		t.Fatal("recording diverges from provider prompt or modified caller")
	}
}
