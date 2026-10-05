package session

// ua_test.go 批 7 P0-2:webshell 流量的 User-Agent 不再自报家门——建会话时从
// 浏览器 UA 池(agent/uapool.go 与 worker 流量同池)随机选一个,会话期间稳定,
// 随 Secret 落库,恢复后不换。

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/agent"
)

func inUAPool(ua string) bool {
	for _, v := range agent.DefaultUAPool() {
		if v == ua {
			return true
		}
	}
	return false
}

// TestSessionUAFromPool:新建会话的 UA 来自浏览器池,且不含产品名字样。
func TestSessionUAFromPool(t *testing.T) {
	for i := 0; i < 16; i++ {
		sh, err := NewHTTPShell("http://127.0.0.1/x.php", "cmd", "php")
		if err != nil {
			t.Fatal(err)
		}
		if !inUAPool(sh.ua) {
			t.Fatalf("UA 不在浏览器池内: %q", sh.ua)
		}
		if strings.Contains(strings.ToLower(sh.ua), "artex") {
			t.Fatalf("UA 含产品名字样: %q", sh.ua)
		}
	}
}

// uaCapture 记录每个请求的 User-Agent 后转交内层 handler。
type uaCapture struct {
	inner http.Handler
	mu    sync.Mutex
	uas   []string
}

func (c *uaCapture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.uas = append(c.uas, r.Header.Get("User-Agent"))
	c.mu.Unlock()
	c.inner.ServeHTTP(w, r)
}

func (c *uaCapture) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.uas...)
}

// TestSessionUAStableOnWire:明文马全链路(探测+Exec)所有请求的 UA 与会话
// 持有的 UA 逐一相同——稳定不换(换来换去才是异常流量)。
func TestSessionUAStableOnWire(t *testing.T) {
	cap := &uaCapture{inner: newPHPMock("eval")}
	u := probeURL(t, cap)
	sh, _, err := Probe(context.Background(), u, "cmd", "php")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if _, _, err := sh.Exec(context.Background(), "id", 0); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	uas := cap.snapshot()
	if len(uas) == 0 {
		t.Fatal("模拟目标未收到任何请求")
	}
	for i, ua := range uas {
		if ua != sh.ua {
			t.Fatalf("第 %d 个请求 UA = %q, want 会话 UA %q(会话期间不得更换)", i, ua, sh.ua)
		}
	}
}

// TestEncSessionUAOnWire:加密马通道(独立请求构造点)同样用会话 UA。
func TestEncSessionUAOnWire(t *testing.T) {
	key := randKey(t)
	cap := &uaCapture{inner: newEncMock(key, "gcm", newPHPMock("eval"))}
	u := probeURL(t, cap)
	sh, err := NewEncShell(u, "phpenc", base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	if err := sh.Test(context.Background()); err != nil {
		t.Fatalf("Test: %v", err)
	}
	for i, ua := range cap.snapshot() {
		if ua != sh.ua {
			t.Fatalf("加密通道第 %d 个请求 UA = %q, want %q", i, ua, sh.ua)
		}
	}
}

// TestSessionUARestoreRoundTrip:UA 随 Secret 落库,恢复后原样带回;
// 旧库记录(无 UA 字段)恢复时随机补一个,不留空。
func TestSessionUARestoreRoundTrip(t *testing.T) {
	mock := newPHPMock("eval")
	u := probeURL(t, mock)
	sh, _, err := Probe(context.Background(), u, "cmd", "php")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	sec := sh.Secret()
	if sec.UA != sh.ua {
		t.Fatalf("Secret.UA = %q, want %q", sec.UA, sh.ua)
	}
	got, err := RestoreHTTPShell(1, sec)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got.ua != sh.ua {
		t.Fatalf("恢复后 UA = %q, want %q(会话期间稳定含跨重启)", got.ua, sh.ua)
	}
	// 旧记录兼容:UA 为空时按新建会话处理,随机分配。
	sec.UA = ""
	got2, err := RestoreHTTPShell(2, sec)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !inUAPool(got2.ua) {
		t.Fatalf("旧记录恢复后 UA 应随机补一个池内值, got %q", got2.ua)
	}
	// 加密马恢复路径:enc 传输层也要带回同一份 UA。
	secEnc := Secret{URL: u, Lang: "php", Key: base64.StdEncoding.EncodeToString(randKey(t)), UA: sh.ua}
	got3, err := RestoreHTTPShell(3, secEnc)
	if err != nil {
		t.Fatalf("Restore(enc): %v", err)
	}
	if got3.enc == nil || got3.enc.ua != sh.ua {
		t.Fatalf("加密马恢复后 enc UA 不符: %+v", got3.enc)
	}
}
