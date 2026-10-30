// Package httpmeasure records bounded paired observations. It never verifies a vulnerability.
package httpmeasure

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

const Version = "paired-http-v1"
const MaxResponseBytes = 1 << 20
const Budget = 60 * time.Second

type Plan struct {
	BaselineURL     string            `json:"baseline_url"`
	TestURL         string            `json:"test_url"`
	Method          string            `json:"method,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	BaselineBody    string            `json:"baseline_body,omitempty"`
	TestBody        string            `json:"test_body,omitempty"`
	Pairs           int               `json:"pairs,omitempty"`
	TimeoutMS       int               `json:"timeout_ms,omitempty"`
	MinimumEffectMS int               `json:"minimum_effect_ms,omitempty"`
}

func (p Plan) Validate() (Plan, error) {
	p.Method = strings.ToUpper(strings.TrimSpace(p.Method))
	if p.Method == "" {
		p.Method = "GET"
	}
	if p.Method != "GET" && p.Method != "HEAD" && p.Method != "POST" {
		return p, errors.New("method 仅支持 GET / HEAD / POST")
	}
	if p.Pairs == 0 {
		p.Pairs = 5
	}
	if p.Pairs < 3 || p.Pairs > 6 {
		return p, errors.New("pairs 必须为 3–6")
	}
	if p.TimeoutMS == 0 {
		p.TimeoutMS = 5000
	}
	if p.TimeoutMS < 100 || p.TimeoutMS > 10000 {
		return p, errors.New("timeout_ms 必须为 100–10000")
	}
	if p.MinimumEffectMS == 0 {
		p.MinimumEffectMS = 1000
	}
	if p.MinimumEffectMS < 200 || p.MinimumEffectMS > 10000 {
		return p, errors.New("minimum_effect_ms 必须为 200–10000")
	}
	if len(p.BaselineBody) > 64<<10 || len(p.TestBody) > 64<<10 {
		return p, errors.New("请求正文超过 64KiB")
	}
	if p.Method != "POST" && (p.BaselineBody != "" || p.TestBody != "") {
		return p, errors.New("GET/HEAD 不接受请求正文")
	}
	a, err := parseURL(p.BaselineURL)
	if err != nil {
		return p, err
	}
	b, err := parseURL(p.TestURL)
	if err != nil {
		return p, err
	}
	if a.Scheme != b.Scheme || !strings.EqualFold(a.Host, b.Host) || a.EscapedPath() != b.EscapedPath() {
		return p, errors.New("基线与测试必须是同协议、主机、端口和路径；只改变查询或 POST 正文")
	}
	if len(p.Headers) > 64 {
		return p, errors.New("请求头最多 64 项")
	}
	total := 0
	clean := map[string]string{}
	for k, v := range p.Headers {
		total += len(k) + len(v)
		if total > 16<<10 || !validHeaderName(k) || !validHeaderValue(v) {
			return p, errors.New("请求头无效或超过 16KiB")
		}
		switch strings.ToLower(k) {
		case "host", "content-length", "connection", "transfer-encoding", "proxy-authorization", "proxy-connection":
			return p, errors.New("不允许覆盖连接、代理或传输控制头")
		}
		canonical := http.CanonicalHeaderKey(k)
		if _, ok := clean[canonical]; ok {
			return p, errors.New("请求头名称大小写重复")
		}
		clean[canonical] = v
	}
	p.Headers = clean
	return p, nil
}

func validHeaderValue(s string) bool {
	for _, b := range []byte(s) {
		if b == 127 || b < 32 && b != '\t' {
			return false
		}
	}
	return true
}

func parseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 8192 || u == nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("URL 必须是无内嵌凭据/片段的有效 HTTP(S) 地址，最多 8192 字节")
	}
	return u, nil
}

func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}

type Sample struct {
	Sequence       int       `json:"sequence"`
	Pair           int       `json:"pair"`
	Variant        string    `json:"variant"`
	Warmup         bool      `json:"warmup"`
	StartedAt      time.Time `json:"started_at"`
	ElapsedMS      float64   `json:"elapsed_ms"`
	TTFBMS         float64   `json:"ttfb_ms"`
	StatusCode     int       `json:"status_code"`
	BodyBytes      int       `json:"body_bytes"`
	BodyComplete   bool      `json:"body_complete"`
	BodySHA256     string    `json:"body_sha256,omitempty"`
	RequestWritten bool      `json:"request_written"`
	ErrorCode      string    `json:"error_code,omitempty"`
}

type Result struct {
	Version                string   `json:"version"`
	PlanSHA256             string   `json:"plan_sha256"`
	Status                 string   `json:"status"`
	PairsRequested         int      `json:"pairs_requested"`
	TimeoutMS              int      `json:"timeout_ms"`
	MinimumEffectMS        int      `json:"minimum_effect_ms"`
	MaximumAttempts        int      `json:"maximum_attempts"`
	Attempts               int      `json:"attempts"`
	RequestsWritten        int      `json:"requests_written"`
	ElapsedMS              float64  `json:"elapsed_ms"`
	Samples                []Sample `json:"samples"`
	Analysis               Analysis `json:"analysis"`
	VulnerabilityConfirmed bool     `json:"vulnerability_confirmed"`
}

// Before rechecks host policy/resource pressure for every individual request.
type Before func(context.Context, string) (func(), error)
type StopError struct{ Code string }

func (e *StopError) Error() string { return e.Code }

type Runner struct {
	client *http.Client
	before Before
	gap    time.Duration
}

func New(client *http.Client, before Before) *Runner {
	copyClient := *client
	transport := copyClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if tr, ok := transport.(*http.Transport); ok {
		cloned := tr.Clone()
		cloned.DisableKeepAlives = true
		cloned.DisableCompression = true
		cloned.ForceAttemptHTTP2 = false
		cloned.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		copyClient.Transport = cloned
	}
	copyClient.Jar = nil
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Runner{client: &copyClient, before: before, gap: 100 * time.Millisecond}
}

func (r *Runner) Run(parent context.Context, p Plan) (Result, error) {
	p, err := p.Validate()
	if err != nil {
		return Result{}, err
	}
	ctx, cancel := context.WithTimeout(parent, Budget)
	defer cancel()
	start := time.Now()
	encoded, _ := json.Marshal(p)
	out := Result{Version: Version, PlanSHA256: fmt.Sprintf("%x", sha256.Sum256(encoded)), Status: "completed", PairsRequested: p.Pairs, TimeoutMS: p.TimeoutMS, MinimumEffectMS: p.MinimumEffectMS, MaximumAttempts: 2 + 2*p.Pairs, Samples: []Sample{}}
	for index := 0; index < out.MaximumAttempts; index++ {
		if index > 0 && r.gap > 0 {
			timer := time.NewTimer(r.gap)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
		}
		if ctx.Err() != nil {
			out.Status = stopStatus(ctx, parent)
			break
		}
		warmup := index < 2
		pair := 0
		variant := "baseline"
		if !warmup {
			pair = (index-2)/2 + 1
			test := (index-2)%2 == 1
			if pair%2 == 0 {
				test = !test
			}
			if test {
				variant = "test"
			}
		}
		rawURL := p.BaselineURL
		body := p.BaselineBody
		if variant == "test" {
			rawURL = p.TestURL
			body = p.TestBody
		}
		release := func() {}
		if r.before != nil {
			release, err = r.before(ctx, rawURL)
			if err != nil {
				if ctx.Err() != nil {
					out.Status = stopStatus(ctx, parent)
					break
				}
				out.Status = "policy_blocked"
				var stopped *StopError
				if errors.As(err, &stopped) {
					switch stopped.Code {
					case "resource_blocked", "scope_blocked", "task_stopped":
						out.Status = stopped.Code
					}
				}
				break
			}
			if release == nil {
				return out, errors.New("测量准入没有返回释放函数")
			}
		}
		sample := func() Sample { defer release(); return r.sample(ctx, p, rawURL, body) }()
		sample.Sequence = index + 1
		sample.Pair = pair
		sample.Variant = variant
		sample.Warmup = warmup
		out.Samples = append(out.Samples, sample)
		out.Attempts++
		if sample.RequestWritten {
			out.RequestsWritten++
		}
		if ctx.Err() != nil {
			out.Status = stopStatus(ctx, parent)
			break
		}
		if sample.ErrorCode != "" {
			out.Status = "request_failed"
			break
		}
		if sample.StatusCode < 200 || sample.StatusCode >= 300 {
			out.Status = "http_precondition_failed"
			break
		}
	}
	out.ElapsedMS = milliseconds(time.Since(start))
	out.Analysis = Analyze(out)
	return out, nil
}

func stopStatus(ctx, parent context.Context) string {
	if parent.Err() != nil {
		if errors.Is(parent.Err(), context.DeadlineExceeded) {
			return "budget_exhausted"
		}
		return "cancelled"
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "budget_exhausted"
	}
	return "cancelled"
}

func (r *Runner) sample(ctx context.Context, p Plan, rawURL, body string) Sample {
	start := time.Now()
	out := Sample{StartedAt: start.UTC(), TTFBMS: -1}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutMS)*time.Millisecond)
	defer cancel()
	var firstByte atomic.Int64
	var written atomic.Bool
	trace := &httptrace.ClientTrace{GotFirstResponseByte: func() { firstByte.CompareAndSwap(0, time.Since(start).Microseconds()+1) }, WroteRequest: func(i httptrace.WroteRequestInfo) {
		if i.Err == nil {
			written.Store(true)
		}
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(runCtx, trace), p.Method, rawURL, strings.NewReader(body))
	if err != nil {
		out.ErrorCode = "invalid_request"
		return out
	}
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	// Prevent a caller-provided body from enabling replay through redirects.
	req.GetBody = nil
	resp, err := r.client.Do(req)
	if err != nil {
		out.ErrorCode = errorCode(runCtx, err)
	} else {
		out.StatusCode = resp.StatusCode
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
		resp.Body.Close()
		out.BodyBytes = len(data)
		switch {
		case readErr != nil:
			out.ErrorCode = errorCode(runCtx, readErr)
		case len(data) > MaxResponseBytes:
			out.ErrorCode = "response_too_large"
		default:
			out.BodyComplete = true
			out.BodySHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
		}
	}
	out.RequestWritten = written.Load()
	if us := firstByte.Load(); us > 0 {
		out.TTFBMS = float64(us-1) / 1000
	}
	out.ElapsedMS = milliseconds(time.Since(start))
	return out
}

func errorCode(ctx context.Context, err error) string {
	if errors.Is(ctx.Err(), context.Canceled) {
		return "cancelled"
	}
	var n net.Error
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.As(err, &n) && n.Timeout() {
		return "timeout"
	}
	return "transport_error"
}
func milliseconds(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
