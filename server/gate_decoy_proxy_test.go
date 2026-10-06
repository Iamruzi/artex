package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// decoyEcho 记录最后一次请求的伪装后端,并把记录值回显在响应里。
type decoyEcho struct {
	method, path, rawQuery, host, xff, realIP, body string
}

func (e *decoyEcho) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.method, e.path, e.rawQuery, e.host = r.Method, r.URL.Path, r.URL.RawQuery, r.Host
		e.xff, e.realIP = r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP")
		b, _ := io.ReadAll(r.Body)
		e.body = string(b)
		w.Header().Set("Server", "openresty/1.21.4.1")
		w.Header().Set("X-Backend", "echo")
		w.WriteHeader(http.StatusTeapot) // 418:便于确认状态码也透传
		_, _ = w.Write([]byte("BACKEND:" + e.method + " " + e.path))
	})
}

// gatedDecoy 装配"env 指向 backend 的门控",返回 handler 与 backend 记录器。
func gatedDecoy(t *testing.T) (http.Handler, *decoyEcho, *httptest.Server) {
	t.Helper()
	e := &decoyEcho{}
	backend := httptest.NewServer(e.handler())
	t.Cleanup(backend.Close)
	t.Setenv("ARTEX_GATE_DECOY_PROXY", backend.URL)
	return newTestGate().wrap(innerReached()), e, backend
}

// TestGateDecoyProxyGetPost 反代模式:GET/POST 全路径透传(含 query 与 body),
// Host 重写为目标 host,响应状态码/body/头(含 Server)原样回写,不加 ARTEX 特征头。
func TestGateDecoyProxyGetPost(t *testing.T) {
	h, e, backend := gatedDecoy(t)
	targetHost := strings.TrimPrefix(backend.URL, "http://")

	// GET 带 query
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/some/path?a=1&b=2", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("GET: status = %d, want 418(目标透传)", rec.Code)
	}
	if e.method != http.MethodGet || e.path != "/some/path" || e.rawQuery != "a=1&b=2" {
		t.Fatalf("GET 透传不对: %s %s?%s", e.method, e.path, e.rawQuery)
	}
	if e.host != targetHost {
		t.Fatalf("Host 未重写为目标: %q, want %q", e.host, targetHost)
	}
	if got := rec.Header().Get("Server"); got != "openresty/1.21.4.1" {
		t.Fatalf("Server 头未与目标一致: %q", got)
	}
	if !strings.HasPrefix(rec.Body.String(), "BACKEND:GET /some/path") {
		t.Fatalf("GET body 非目标响应: %q", rec.Body.String())
	}

	// POST 带 body(静态模式下本应是 405,反代模式必须透传)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader("p=1&p=2")))
	if rec2.Code != http.StatusTeapot {
		t.Fatalf("POST: status = %d, want 418", rec2.Code)
	}
	if e.method != http.MethodPost || e.path != "/submit" || e.body != "p=1&p=2" {
		t.Fatalf("POST 透传不对: %s %s body=%q", e.method, e.path, e.body)
	}
}

// TestGateDecoyProxyXFF 真实来源经 X-Forwarded-For/X-Real-IP 带给目标;
// 客户端已带 XFF 时按代理惯例追加。
func TestGateDecoyProxyXFF(t *testing.T) {
	h, e, _ := gatedDecoy(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:4567"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if e.xff != "203.0.113.9" || e.realIP != "203.0.113.9" {
		t.Fatalf("XFF/X-Real-IP = %q/%q, want 203.0.113.9", e.xff, e.realIP)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "203.0.113.9:4567"
	req2.Header.Set("X-Forwarded-For", "198.51.100.1")
	h.ServeHTTP(httptest.NewRecorder(), req2)
	if e.xff != "198.51.100.1, 203.0.113.9" {
		t.Fatalf("已有 XFF 未追加: %q", e.xff)
	}
}

// TestGateDecoyProxyFallback 目标不可达时回落静态 decoy 页——与未设 env 时
// 逐字节一致,不泄露"后端挂了"的任何迹象(状态码/头/body 全部按方法仿真)。
func TestGateDecoyProxyFallback(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close() // 立即关闭,连接被拒
	t.Setenv("ARTEX_GATE_DECOY_PROXY", deadURL)
	h := newTestGate().wrap(innerReached())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), decoyPage) {
		t.Fatalf("GET 回落失败: code=%d", rec.Code)
	}
	if got := rec.Header().Get("Server"); got != "nginx" {
		t.Fatalf("回落静态页 Server = %q, want nginx", got)
	}
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec2.Code != http.StatusMethodNotAllowed || !bytes.Equal(rec2.Body.Bytes(), decoyErrorPage) {
		t.Fatalf("POST 回落失败: code=%d", rec2.Code)
	}
}

// TestGateDecoyProxyInvalidFallsBack 非法 env 值不启用反代,静态 decoy 行为不变。
func TestGateDecoyProxyInvalidFallsBack(t *testing.T) {
	t.Setenv("ARTEX_GATE_DECOY_PROXY", "not-a-url")
	rec := httptest.NewRecorder()
	newTestGate().wrap(innerReached()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !bytes.Equal(rec.Body.Bytes(), decoyPage) {
		t.Fatalf("非法 env 后行为改变: %q", rec.Body.String())
	}
}

// TestGateDecoyProxyUnsetStatic 不设 env 时行为完全不变(静态 decoy)。
func TestGateDecoyProxyUnsetStatic(t *testing.T) {
	t.Setenv("ARTEX_GATE_DECOY_PROXY", "")
	h := newTestGate().wrap(innerReached())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), decoyPage) {
		t.Fatalf("env 未设置时 GET decoy 变了: code=%d", rec.Code)
	}
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec2.Code != http.StatusMethodNotAllowed || !bytes.Equal(rec2.Body.Bytes(), decoyErrorPage) {
		t.Fatalf("env 未设置时 POST decoy 变了: code=%d", rec2.Code)
	}
}

// TestGateDecoyProxyTargetBasePath 目标带 base path 时正确拼接(不双斜杠)。
func TestGateDecoyProxyTargetBasePath(t *testing.T) {
	e := &decoyEcho{}
	backend := httptest.NewServer(e.handler())
	t.Cleanup(backend.Close)
	t.Setenv("ARTEX_GATE_DECOY_PROXY", backend.URL+"/base/")
	h := newTestGate().wrap(innerReached())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/a/b/c?x=1", nil))
	if e.path != "/base/a/b/c" || e.rawQuery != "x=1" {
		t.Fatalf("拼接不对: %s?%s, want /base/a/b/c?x=1", e.path, e.rawQuery)
	}
}
