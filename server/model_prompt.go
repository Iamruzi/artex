package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/modelprompt"
)

func (s *Server) modelPromptPreview(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var config modelprompt.Config
	if err := decode(r, &config); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := config.Validate(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"mode": config.Mode, "version": modelprompt.Version, "digest": config.Digest(), "text": config.Render(), "bytes": len(config.Render()), "inference_performed": false})
}

func promptEvaluationDigest(p *db.LLMProfile) string {
	// Deliberately omit credentials. Changes to endpoint or generation settings
	// invalidate old comparisons even if the displayed model name is unchanged.
	value, _ := json.Marshal([]any{p.Format, p.BaseURL, p.Proxy, p.Model, p.ReasoningEffort, p.MaxTokensField, p.RatePerSecond, p.RatePerMinute, p.ModelPrompt.Digest()})
	return fmt.Sprintf("%x", sha256.Sum256(value))
}

func (s *Server) modelPromptLastEvaluation(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, valid := pathInt(r, "id")
	if !valid {
		writeErr(w, 400, "无效的配置编号")
		return
	}
	profile, err := pg.ProfileByID(id)
	if err != nil {
		writeErr(w, 500, "读取配置失败")
		return
	}
	if profile == nil {
		writeErr(w, 404, "配置不存在")
		return
	}
	var value []byte
	err = pg.QueryRow(`SELECT result FROM llm_prompt_evaluations WHERE profile_id=$1`, id).Scan(&value)
	if err != nil && err != sql.ErrNoRows {
		writeErr(w, 500, "读取评测失败")
		return
	}
	if err == sql.ErrNoRows {
		writeJSON(w, 200, map[string]any{"result": nil, "stale": false})
		return
	}
	var result modelprompt.Evaluation
	if json.Unmarshal(value, &result) != nil {
		writeErr(w, 500, "评测记录损坏")
		return
	}
	writeJSON(w, 200, map[string]any{"result": result, "stale": result.ConfigDigest != promptEvaluationDigest(profile)})
}

func (s *Server) modelPromptEvaluate(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, valid := pathInt(r, "id")
	if !valid {
		writeErr(w, 400, "无效的配置编号")
		return
	}
	if !s.promptEvalMu.TryLock() {
		writeErr(w, 409, "已有提示词评测在运行，请稍后再试")
		return
	}
	defer s.promptEvalMu.Unlock()
	profile, err := pg.ProfileByID(id)
	if err != nil {
		writeErr(w, 500, "读取配置失败")
		return
	}
	if profile == nil {
		writeErr(w, 404, "配置不存在")
		return
	}
	if profile.ModelPrompt.Mode == "" {
		writeErr(w, 400, "请先保存已开启的提示词模式，再进行对照")
		return
	}
	if profile.APIKey == "" {
		writeErr(w, 400, "模型配置不完整")
		return
	}
	// Build from the same row snapshot used by the report, avoiding a concurrent
	// edit between two profile reads changing what is actually evaluated.
	cfg := agent.ConfigFrom(profile.Format, profile.Model, profile.BaseURL, profile.APIKey, profile.Proxy)
	cfg.RatePerSecond, cfg.RatePerMinute = profile.RatePerSecond, profile.RatePerMinute
	cfg.ReasoningEffort = profile.ReasoningEffort
	cfg.MaxTokensField = profile.MaxTokensField
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	// No failover or retries: both variants must use the same saved endpoint.
	cfg.Retry = agent.RetryConfig{ConnectAttempts: -1, EmptyAttempts: -1, StreamAttempts: -1}
	cfg.ThinkingType = "disabled"
	baseline, err := cfg.NewProvider()
	if err != nil {
		writeErr(w, 400, "无法构建模型配置")
		return
	}
	// Both variants share the exact same base provider and its rate limiter.
	adapted, err := agent.WithModelPrompt(baseline, profile.ModelPrompt)
	if err != nil {
		writeErr(w, 400, "无法构建基线配置")
		return
	}
	result := modelprompt.Compare(ctx, baseline, adapted, s.admitCustomTool)
	result.Digest = profile.ModelPrompt.Digest()
	result.ConfigDigest = promptEvaluationDigest(profile)
	result.Mode = profile.ModelPrompt.Mode
	result.ProfileID = i64s(id)
	result.Model = profile.Model
	bytes, err := json.Marshal(result)
	if err != nil {
		writeErr(w, 500, "无法序列化评测")
		return
	}
	if _, err = pg.Exec(`INSERT INTO llm_prompt_evaluations(profile_id,result) VALUES ($1,$2)
ON CONFLICT(profile_id) DO UPDATE SET result=EXCLUDED.result,updated_at=now()`, id, bytes); err != nil {
		writeErr(w, 500, "评测已结束，但保存结果失败")
		return
	}
	writeJSON(w, 200, result)
}
