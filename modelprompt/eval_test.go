package modelprompt

import (
	"context"
	"errors"
	"iter"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

type fixtureProvider struct {
	calls        int
	replay       bool
	fail         bool
	wrongTool    bool
	falseSuccess bool
	cancel       context.CancelFunc
}

func (p *fixtureProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	panic("evaluation must use nonstreaming requests")
}
func (p *fixtureProvider) Complete(_ context.Context, r llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.calls++
	if p.cancel != nil {
		p.cancel()
	}
	if p.fail {
		return llm.Message{}, "", llm.Usage{}, errors.New("secret-key-must-not-appear")
	}
	text := ""
	if len(r.Tools) > 0 {
		if len(r.Messages) == 1 {
			name := "add_numbers"
			if p.wrongTool {
				name = "shell"
			}
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "fixture-1", Name: name, Input: []byte(`{"a":19,"b":23}`)}}}, "tool_use", llm.Usage{}, nil
		}
		blocks := r.Messages[len(r.Messages)-1].Content
		if len(blocks) != 1 || blocks[0].ToolUseID != "fixture-1" || len(blocks[0].Content) != 1 || blocks[0].Content[0].Text != "42" {
			return llm.Message{}, "", llm.Usage{}, errors.New("bad replay")
		}
		p.replay = true
		text = "42"
	} else if strings.Contains(r.Messages[0].Text(), "code 1") {
		text = `{"confirmed":false}`
		if p.falseSuccess {
			text = `{"confirmed":true}`
		}
	} else {
		text = `{"issue":"sql_injection","fix":"parameterized_query"}`
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(text)}}, "stop", llm.Usage{OutputTokens: 2}, nil
}

func TestModelPromptFalseSuccessDoesNotPassAndAdmissionPreventsRequests(t *testing.T) {
	p := &fixtureProvider{falseSuccess: true}
	result := Compare(context.Background(), &fixtureProvider{}, p)
	if result.AdaptedPassed != 2 {
		t.Fatal("false success counted as passing")
	}
	p = &fixtureProvider{}
	result = Compare(context.Background(), p, p, func(context.Context) (func(), error) { return nil, errors.New("resource pressure") })
	if result.Completed || result.Requests != 0 || p.calls != 0 || len(result.Samples) != 1 || result.Samples[0].Status != "resource_blocked" {
		t.Fatal("resource-blocked evaluation sent a request")
	}
}

func TestModelPromptCompareExecutesOnlyFixtureAndReplaysActualResult(t *testing.T) {
	base, adapted := &fixtureProvider{}, &fixtureProvider{}
	result := Compare(context.Background(), base, adapted)
	if !result.Completed || result.Requests != 8 || result.BaselinePassed != 3 || result.AdaptedPassed != 3 || !base.replay || !adapted.replay {
		t.Fatalf("unexpected comparison %+v", result)
	}
	for _, s := range result.Samples {
		if s.Case == "tool_roundtrip" && s.ToolExecutions != 1 {
			t.Fatal("tool was not executed")
		}
	}
}

func TestModelPromptCompareRejectsUnknownToolAndSanitizesTransportErrors(t *testing.T) {
	result := Compare(context.Background(), &fixtureProvider{fail: true}, &fixtureProvider{wrongTool: true})
	if result.BaselinePassed != 0 || result.AdaptedPassed != 2 || result.Requests != 6 {
		t.Fatalf("unexpected %+v", result)
	}
	for _, sample := range result.Samples {
		if strings.Contains(sample.Error, "secret-key") || sample.ToolExecutions != 0 {
			t.Fatal("unsafe tool executed or transport secret exposed")
		}
	}
}

func TestModelPromptCompareStopsAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &fixtureProvider{cancel: cancel}
	result := Compare(ctx, p, &fixtureProvider{})
	if result.Completed || result.Requests != 1 {
		t.Fatalf("continued after cancellation %+v", result)
	}
}
