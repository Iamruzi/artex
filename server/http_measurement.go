package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/httpmeasure"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

const measurementOrigin = "http-measurement/v1"

func (s *Server) httpMeasurementTools() []actool.CoreTool {
	schema := objSchema(map[string]any{
		"baseline_url": strParam("基线 URL，与 test_url 同协议、主机、端口和路径"), "test_url": strParam("测试 URL，只改变查询参数或 POST 正文；不会自动生成 payload"),
		"method":        map[string]any{"type": "string", "enum": []string{"GET", "HEAD", "POST"}},
		"headers":       map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "两个变体共用的请求头。不会自动更新 cookie，也不会返回或另存头部正文。"},
		"baseline_body": strParam("POST 基线正文，最多 64KiB"), "test_body": strParam("POST 测试正文，最多 64KiB"),
		"pairs":             map[string]any{"type": "integer", "minimum": 3, "maximum": 6, "description": "默认 5；另有 2 次基线预热，共最多 14 次客户端请求尝试"},
		"timeout_ms":        map[string]any{"type": "integer", "minimum": 100, "maximum": 10000, "description": "每次请求超时，默认 5000ms，总预算 60s"},
		"minimum_effect_ms": map[string]any{"type": "integer", "minimum": 200, "maximum": 10000, "description": "最小关注延迟差，默认 1000ms；不是漏洞确认阈值"},
	}, "baseline_url", "test_url")
	schema["additionalProperties"] = false
	measure := actool.Build(actool.Spec{Name: "measure_http_pair", Description: "在当前任务已登记范围内对两个 HTTP 变体做交错重复测量，返回真实耗时/状态/错误与观测线索编号。默认 12 次请求，最多 14 次，总计 60s；POST 也会重复，仅用于已授权的合适测试。无自动重试、重定向、payload 生成或漏洞确认。repeatable_delay 只是线索，不能据此宣称 SQLi/RCE 或目标达成。", Schema: schema,
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: s.runHTTPMeasurement,
	})
	read := roTool("get_http_measurement", "读取当前任务或当前漏洞复核关联任务中，由测量执行器保存的观测线索。measurement_node_id 是探索节点 ID。无网络请求，不读取其他任务或普通文字线索。", objSchema(map[string]any{"measurement_node_id": strParam("measure_http_pair 返回的 measurement_node_id")}, "measurement_node_id"), func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		task, err := s.httpMeasurementTask(ctx)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		var input struct {
			ID json.RawMessage `json:"measurement_node_id"`
		}
		if json.Unmarshal(raw, &input) != nil {
			return actool.Errorf("参数格式无效"), nil
		}
		node, err := task.Store.GetNode(parseProfileID(input.ID))
		if err != nil || node == nil || node.Kind != db.KindHint || node.Origin != measurementOrigin {
			return actool.Errorf("本任务不存在该测量观测"), nil
		}
		var payload map[string]any
		if json.Unmarshal(node.Payload, &payload) != nil {
			return actool.Errorf("测量观测数据无效"), nil
		}
		return jsonResult(map[string]any{"measurement_node_id": node.ID, "measurement": payload["measurement"], "tool_call_id": payload["tool_call_id"], "intent_id": payload["intent_id"]})
	})
	return []actool.CoreTool{measure, read}
}

func (s *Server) seedHTTPMeasurementTools() {
	bindings, _ := json.Marshal([]string{"worker", "verifier"})
	for _, tool := range s.httpMeasurementTools() {
		schema, _ := json.Marshal(tool.InputSchema())
		if err := s.m.pg.SeedTool(tool.Name(), tool.Description(), schema, bindings); err != nil {
			log.Printf("[measure] seed %s: %v", tool.Name(), err)
		}
	}
}

func (s *Server) httpMeasurementTask(ctx context.Context) (*Task, error) {
	if s.m == nil || s.m.pg == nil {
		return nil, errors.New("测量任务存储不可用")
	}
	id := agent.RunInfoFrom(ctx).TaskID
	if id <= 0 {
		convID := intercept.ConvIDFromContext(ctx)
		if convID > 0 {
			check, err := s.m.pg.FindingCheckForConversation(ctx, convID)
			if err != nil {
				return nil, errors.New("读取复核任务失败")
			}
			if check != nil {
				finding, err := s.m.pg.GetFinding(check.FindingID)
				if err == nil && finding != nil && finding.TaskID != nil {
					id = *finding.TaskID
				}
			}
		}
	}
	if id <= 0 {
		return nil, errors.New("需要当前任务或漏洞复核任务上下文，不能由入参指定其他任务")
	}
	task := s.m.ResolveTask(strconv.FormatInt(id, 10))
	if task == nil || task.Store == nil {
		return nil, errors.New("关联任务不可用")
	}
	return task, nil
}

func (s *Server) runHTTPMeasurement(ctx context.Context, raw json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	if len(raw) > 256<<10 {
		return actool.Errorf("测量参数超过 256KiB"), nil
	}
	var plan httpmeasure.Plan
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&plan) != nil {
		return actool.Errorf("测量参数无效或包含未知字段"), nil
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return actool.Errorf("测量参数必须是单个 JSON 对象"), nil
	}
	plan, err := plan.Validate()
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	task, err := s.httpMeasurementTask(ctx)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	if s.engine != nil {
		if !s.engine.beginTaskOperation(task.ID) {
			return actool.Errorf("任务正在删除或归档"), nil
		}
		defer s.engine.decInflight(task.ID)
	}
	runCtx, cancel := context.WithTimeout(ctx, httpmeasure.Budget)
	defer cancel()
	// Validate policy before proxy setup can create a recording instance.
	if err = s.measurementScope(runCtx, task, plan.BaselineURL); err != nil {
		return actool.Errorf(err.Error()), nil
	}
	if s.m.egress != nil {
		values := []string{plan.BaselineURL, plan.TestURL, plan.BaselineBody, plan.TestBody}
		for _, v := range plan.Headers {
			values = append(values, v)
		}
		for _, value := range values {
			decoded, _ := url.QueryUnescape(value)
			if _, hit := s.m.egress.Check(value); hit {
				return actool.Errorf("平台敏感信息禁止外发"), nil
			}
			if _, hit := s.m.egress.Check(decoded); hit {
				return actool.Errorf("平台敏感信息禁止外发"), nil
			}
		}
	}
	// Check resources even when this function is used outside normal assembly.
	release, err := s.admitMeasurement(runCtx)
	if err != nil {
		return actool.Errorf("resource_blocked: 测量未派发"), nil
	}
	release()
	client, mode, err := s.httpMeasurementClient(runCtx, task)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	defer client.CloseIdleConnections()
	if _, set := plan.Headers["User-Agent"]; !set {
		plan.Headers["User-Agent"] = s.uaForTask(measurementTaskID(task))
	}
	before := func(c context.Context, rawURL string) (func(), error) {
		if err := c.Err(); err != nil {
			return nil, err
		}
		if s.engine != nil && s.engine.IsDeleting(task.ID) {
			return nil, &httpmeasure.StopError{Code: "task_stopped"}
		}
		if err := s.measurementScope(c, task, rawURL); err != nil {
			return nil, &httpmeasure.StopError{Code: "scope_blocked"}
		}
		return s.admitMeasurement(c)
	}
	measured, err := httpmeasure.New(client, before).Run(runCtx, plan)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	label := map[string]string{"repeatable_delay": "存在重复耗时差异", "no_repeatable_delay": "未观察到稳定耗时差异", "inconclusive": "无法确认耗时差异"}[measured.Analysis.Signal]
	payload := map[string]any{"summary": "HTTP 对照测量：" + label + "（仅观测，非漏洞结论）", "text": "通过节点详情或可用的 get_http_measurement 回看逐次采样。独立漏洞复核与目标验收仍需另行完成。", "measurement": measured, "transport": mode, "intent_id": agent.RunInfoFrom(ctx).IntentID}
	if tc != nil {
		payload["tool_call_id"] = tc.ToolUseID
	}
	persistCtx, persistCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer persistCancel()
	nodeID, saveErr := task.Store.AddNodeContext(persistCtx, db.KindHint, payload, 0, "active", measurementOrigin, nil)
	if saveErr != nil {
		result, _ := jsonResult(map[string]any{"saved": false, "error": "测量已经执行，但观测保存失败；不要只为重存重复请求", "measurement": measured})
		result.IsError = true
		return result, nil
	}
	result, _ := jsonResult(map[string]any{"saved": true, "measurement_node_id": nodeID, "measurement": measured, "transport": mode})
	if measured.Status != "completed" {
		result.IsError = true
	}
	return result, nil
}

func measurementTaskID(task *Task) int64 { n, _ := strconv.ParseInt(task.ID, 10, 64); return n }

func (s *Server) measurementScope(ctx context.Context, task *Task, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("测量 URL 无效")
	}
	rows, err := s.m.pg.Assets().ListTaskScopeContext(ctx, measurementTaskID(task))
	if err != nil {
		return errors.New("测量范围读取失败，未派发请求")
	}
	matcher := guard.NewScopeMatcher(scopeRulesFromRows(rows))
	matcher.AllowLocal = false
	if matcher.Check(u.Hostname()) != guard.ScopeIn {
		return errors.New("测量目标不在本任务已登记范围内；需要先核对并登记任务范围")
	}
	return nil
}

func (s *Server) admitMeasurement(ctx context.Context) (func(), error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if s.resources == nil {
		return func() {}, nil
	}
	if agent.HasResourceLease(ctx) {
		if s.resources.CheckPressure() != nil {
			return nil, &httpmeasure.StopError{Code: "resource_blocked"}
		}
		return func() {}, nil
	}
	release, err := s.resources.TryAcquire("tool")
	if err != nil {
		return nil, &httpmeasure.StopError{Code: "resource_blocked"}
	}
	return release, nil
}

func (s *Server) httpMeasurementClient(ctx context.Context, task *Task) (*http.Client, string, error) {
	proxyAddr, caFile := s.m.ProxyAddr(), s.m.ProxyCACert()
	mode := "direct"
	if proxyAddr != "" {
		mode = "global_proxy"
		if caFile != "" {
			mode = "recording_proxy"
		}
	}
	if s.m.taskProxy != nil && s.m.TrafficEnabled() {
		proxyAddr, caFile = s.m.taskProxy.ForTask(ctx, measurementTaskID(task))
		if proxyAddr == "" {
			return nil, "", errors.New("任务代理准备失败，测量未回退直连")
		}
		mode = "task_proxy"
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DisableKeepAlives = true
	tr.DisableCompression = true
	tr.ForceAttemptHTTP2 = false
	tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	if proxyAddr != "" {
		if !strings.Contains(proxyAddr, "://") {
			proxyAddr = "http://" + proxyAddr
		}
		parsed, err := url.Parse(proxyAddr)
		if err != nil || parsed.Host == "" {
			return nil, "", errors.New("代理配置无效，测量未回退直连")
		}
		switch parsed.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return nil, "", errors.New("测量代理协议不支持")
		}
		tr.Proxy = http.ProxyURL(parsed)
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, "", errors.New("测量代理 CA 不可读")
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, "", errors.New("测量代理 CA 无效")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	return &http.Client{Transport: tr}, mode, nil
}
