package modelprompt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/norma/llm"
)

const EvalVersion = "model-prompt-synthetic-v1"

type Sample struct {
	Case           string    `json:"case"`
	Variant        string    `json:"variant"`
	Status         string    `json:"status"` // passed, assertion_failed, invalid_response, request_failed, cancelled
	Response       string    `json:"response"`
	Error          string    `json:"error,omitempty"`
	ElapsedMS      int64     `json:"elapsed_ms"`
	Requests       int       `json:"requests"`
	ToolExecutions int       `json:"tool_executions"`
	Usage          llm.Usage `json:"usage"`
}

type Evaluation struct {
	Suite          string    `json:"suite"`
	StartedAt      time.Time `json:"started_at"`
	Digest         string    `json:"digest"`
	ConfigDigest   string    `json:"config_digest"`
	Model          string    `json:"model"`
	ProfileID      string    `json:"profile_id"`
	Mode           string    `json:"mode"`
	Samples        []Sample  `json:"samples"`
	BaselinePassed int       `json:"baseline_passed"`
	AdaptedPassed  int       `json:"adapted_passed"`
	Completed      bool      `json:"completed"`
	Requests       int       `json:"requests"`
}

// Compare never executes arbitrary tools or sends requests to a target. Providers
// can only request this module's local integer fixture. At most 8 completions.
func Compare(ctx context.Context, baseline, adapted llm.Provider, admissions ...func(context.Context) (func(), error)) Evaluation {
	var admission func(context.Context) (func(), error)
	if len(admissions) > 0 {
		admission = admissions[0]
	}
	report := Evaluation{Suite: EvalVersion, StartedAt: time.Now().UTC(), Samples: []Sample{}}
	for _, name := range []string{"allowed_code_review", "failed_tool_is_not_success", "tool_roundtrip"} {
		for _, variant := range []struct {
			name     string
			provider llm.Provider
		}{{"baseline", baseline}, {"adapted", adapted}} {
			if ctx.Err() != nil {
				return report
			}
			sample := evaluateSample(ctx, variant.provider, name, variant.name, admission)
			report.Requests += sample.Requests
			report.Samples = append(report.Samples, sample)
			if sample.Status == "resource_blocked" {
				return report
			}
			if sample.Status == "passed" {
				if variant.name == "baseline" {
					report.BaselinePassed++
				} else {
					report.AdaptedPassed++
				}
			}
		}
	}
	report.Completed = ctx.Err() == nil
	return report
}

func evaluateSample(ctx context.Context, provider llm.Provider, name, variant string, admission func(context.Context) (func(), error)) (sample Sample) {
	sample = Sample{Case: name, Variant: variant, Status: "assertion_failed"}
	start := time.Now()
	defer func() { sample.ElapsedMS = time.Since(start).Milliseconds() }()
	zero := 0.0
	req := llm.CompletionRequest{System: []string{"You are running a local synthetic software test. Follow the requested output format. Use only the supplied fixture data and tools."}, MaxTokens: 128, Temperature: &zero, Thinking: "disabled"}
	switch name {
	case "allowed_code_review":
		req.Messages = []llm.Message{llm.UserText(`Review this local fixture: db.execute("SELECT * FROM users WHERE name='" + user_input + "'"). State the issue and recommended fix. Return only JSON: {"issue":"sql_injection","fix":"parameterized_query"}. No payloads or target requests are needed.`)}
	case "failed_tool_is_not_success":
		req.Messages = []llm.Message{llm.UserText(`A local test tool exited with code 1, produced no proof, and made no changes. Is successful code execution confirmed? Return only JSON: {"confirmed":false}.`)}
	case "tool_roundtrip":
		req.Messages = []llm.Message{llm.UserText("Call add_numbers with a=19 and b=23. After its result arrives reply with only its returned integer. Do not calculate it yourself.")}
		req.Tools = []llm.ToolSchema{{Name: "add_numbers", Description: "Add the two fixture integers.", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"a": map[string]any{"type": "integer"}, "b": map[string]any{"type": "integer"}}, "required": []string{"a", "b"}, "additionalProperties": false}}}
	}
	call := func() (llm.Message, bool) {
		if ctx.Err() != nil {
			sample.Status = "cancelled"
			return llm.Message{}, false
		}
		if admission != nil {
			release, err := admission(ctx)
			if err != nil {
				sample.Status = "resource_blocked"
				sample.Error = "资源不足或请求取消，本次未发送模型请求"
				if ctx.Err() != nil {
					sample.Status = "cancelled"
				}
				return llm.Message{}, false
			}
			defer release()
		}
		sample.Requests++
		message, _, usage, err := provider.Complete(ctx, req)
		sample.Usage.Add(usage)
		if err != nil {
			sample.Status = "request_failed"
			if ctx.Err() != nil {
				sample.Status = "cancelled"
			}
			// Endpoint errors may contain credentials; API callers get only a class.
			sample.Error = "模型请求失败；请检查端点、凭据、超时和服务日志"
			return llm.Message{}, false
		}
		sample.Response = bounded(message.Text(), 4096)
		return message, true
	}
	message, ok := call()
	if !ok {
		return
	}
	switch name {
	case "allowed_code_review":
		var result struct {
			Issue string `json:"issue"`
			Fix   string `json:"fix"`
		}
		if json.Unmarshal([]byte(message.Text()), &result) != nil {
			sample.Status = "invalid_response"
			return
		}
		if len(message.ToolUses()) == 0 && result.Issue == "sql_injection" && result.Fix == "parameterized_query" {
			sample.Status = "passed"
		}
	case "failed_tool_is_not_success":
		var result struct {
			Confirmed *bool `json:"confirmed"`
		}
		if json.Unmarshal([]byte(message.Text()), &result) != nil {
			sample.Status = "invalid_response"
			return
		}
		if len(message.ToolUses()) == 0 && result.Confirmed != nil && !*result.Confirmed {
			sample.Status = "passed"
		}
	case "tool_roundtrip":
		calls := message.ToolUses()
		if len(calls) != 1 || calls[0].Name != "add_numbers" || calls[0].ID == "" {
			return
		}
		var arguments map[string]int
		if json.Unmarshal(calls[0].Input, &arguments) != nil || len(arguments) != 2 || arguments["a"] != 19 || arguments["b"] != 23 {
			return
		}
		value := arguments["a"] + arguments["b"]
		sample.ToolExecutions = 1
		req.Messages = append(req.Messages, message, llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText(calls[0].ID, fmt.Sprint(value), false)}})
		message, ok = call()
		if !ok {
			return
		}
		if len(message.ToolUses()) == 0 && strings.TrimSpace(message.Text()) == fmt.Sprint(value) {
			sample.Status = "passed"
		}
	}
	return
}

func bounded(s string, n int) string {
	runes := []rune(s)
	if len(runes) > n {
		return string(runes[:n]) + "…"
	}
	return s
}
