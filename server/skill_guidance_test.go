package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"iter"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/skill"
	actool "github.com/Autumn-27/norma/tool"
)

type skillGuidanceFixture struct {
	step     int
	guidance string
	observed *bool
}

func (p *skillGuidanceFixture) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	panic("fixture uses non-streaming calls")
}
func (p *skillGuidanceFixture) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.step++
	message := llm.Message{Role: llm.RoleAssistant}
	switch p.step {
	case 1:
		message.Content = []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "fixture-skill-call", Name: "Skill", Input: []byte(`{"name":"model-jailbreak-assist","args":"nonce=skill-chain-proof"}`)}}
	case 2:
		for _, m := range req.Messages {
			if text := m.Text(); strings.Contains(text, "nonce=skill-chain-proof") && strings.Contains(text, "# 模型任务执行适配") {
				p.guidance = text
			}
		}
		if p.guidance == "" {
			return message, "", llm.Usage{}, fmt.Errorf("actual Skill guidance missing from next completion")
		}
		message.Content = []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "fixture-observation", Name: "fixture_observe", Input: []byte(`{}`)}}
	case 3:
		if !*p.observed {
			return message, "", llm.Usage{}, fmt.Errorf("fixture tool never ran")
		}
		message.Content = []llm.ContentBlock{llm.TextBlock("GUIDANCE_AND_TOOL_OBSERVED")}
		return message, "end_turn", llm.Usage{}, nil
	default:
		return message, "", llm.Usage{}, fmt.Errorf("unexpected extra model call")
	}
	return message, "tool_use", llm.Usage{}, nil
}

func loadTaskAdaptationFixture(t *testing.T) (*db.DB, *skill.Registry) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Fatal(err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Close() })
	all, err := skill.LoadDir(filepath.Join("..", "skills"))
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := all.Get("model-jailbreak-assist")
	if !ok {
		t.Fatal("shipped skill not discovered")
	}
	reg := skill.NewRegistry()
	reg.Add(entry)
	return pg, reg
}

func TestSkillGuidanceReachesNextModelCallAndLedger(t *testing.T) {
	pg, reg := loadTaskAdaptationFixture(t)
	const session = "fixture-skill-guidance-chain"
	t.Cleanup(func() { pg.Exec(`DELETE FROM skill_usage WHERE session_id=$1`, session) })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	loaded := meterSkillTool(reg.Tool(), pg, reg, "worker", agent.RunInfo{TaskID: 7241, IntentID: 7242, SessionID: session})
	observed := false
	fixture := &skillGuidanceFixture{observed: &observed}
	observation := actool.Build(actool.Spec{Name: "fixture_observe", Description: "Read a local constant fixture.", Schema: map[string]any{"type": "object", "properties": map[string]any{}}, Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
		observed = true
		return actool.Text("fixture-observed"), nil
	}})
	text, err := agentcore.Run(ctx, agentcore.Options{Provider: fixture, Tools: []actool.CoreTool{loaded, observation}, SystemPrompt: []string{"Local synthetic fixture; no network targets."}, PermissionMode: permission.ModeBypass, MaxTurns: 4, MaxTokens: 64, NonStreaming: true}, "Load model-jailbreak-assist, then observe the local fixture.")
	if err != nil || !observed || fixture.step != 3 || text != "GUIDANCE_AND_TOOL_OBSERVED" {
		t.Fatalf("chain failed: %q %v steps=%d", text, err, fixture.step)
	}
	var status, digest string
	var bytes int
	var intent int64
	err = pg.QueryRow(`SELECT load_status,guidance_bytes,content_sha256,intent_id FROM skill_usage WHERE session_id=$1 AND tool_use_id='fixture-skill-call'`, session).Scan(&status, &bytes, &digest, &intent)
	if err != nil {
		t.Fatal(err)
	}
	if status != "loaded" || bytes != len(fixture.guidance) || digest != fmt.Sprintf("%x", sha256.Sum256([]byte(fixture.guidance))) || intent != 7242 {
		t.Fatalf("incorrect load proof: %s bytes=%d sha=%s", status, bytes, digest)
	}
	calls, err := pg.RecentSkillCalls("model-jailbreak-assist", 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range calls {
		if call.SessionID == session {
			if call.LoadStatus != "loaded" || call.ToolUseID != "fixture-skill-call" {
				t.Fatal("API projection lost proof")
			}
			return
		}
	}
	t.Fatal("load proof missing from recent calls")
}

func TestSkillGuidanceAckFailureAndPanicAreNotSuccessfulLoads(t *testing.T) {
	pg, reg := loadTaskAdaptationFixture(t)
	const session = "fixture-skill-guidance-negative"
	t.Cleanup(func() { pg.Exec(`DELETE FROM skill_usage WHERE session_id=$1`, session) })
	for _, test := range []struct {
		name, want string
		run        func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error)
	}{
		{"ack", "no_guidance", func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			return actool.Text("Skill loaded"), nil
		}},
		{"failure", "failed", func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			return actool.Errorf("fixture failure"), nil
		}},
		{"panic", "panicked", func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			panic("fixture panic")
		}},
	} {
		tool := actool.Build(actool.Spec{Name: "Skill", Run: test.run})
		meter := meterSkillTool(tool, pg, reg, "worker", agent.RunInfo{SessionID: session})
		func() {
			defer func() {
				if value := recover(); test.name == "panic" && value == nil {
					t.Error("expected fixture panic")
				}
			}()
			meter.Call(t.Context(), []byte(`{"name":"model-jailbreak-assist"}`), &actool.ToolContext{ToolUseID: test.name})
		}()
		var status, digest string
		var bytes int
		if err := pg.QueryRow(`SELECT load_status,guidance_bytes,content_sha256 FROM skill_usage WHERE session_id=$1 AND tool_use_id=$2`, session, test.name).Scan(&status, &bytes, &digest); err != nil {
			t.Fatal(err)
		}
		if status != test.want || bytes != 0 || digest != "" {
			t.Fatalf("%s falsely recorded as success: %s", test.name, status)
		}
	}
}
