// ca_test.go 验证批 7 P1-1：平台自签 CA 去 mitmproxy 指纹，且被 go-mitmproxy
// 真实接受——最后一个测试起完整代理 + TLS 后端，经代理抓一次 HTTPS，
// 断言证书链两端（叶子/根）都不含 mitmproxy 字样且客户端能完成校验。
package traffic

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mcert "github.com/lqqyt2423/go-mitmproxy/cert"
	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

// certChainText 把证书链的 subject/issuer 拼成一段文本，方便指纹断言。
func certChainText(certs ...*x509.Certificate) string {
	var b strings.Builder
	for _, c := range certs {
		fmt.Fprintf(&b, "subject=%s issuer=%s\n", c.Subject.String(), c.Issuer.String())
	}
	return b.String()
}

func TestStealthCAGenerationAndPersistence(t *testing.T) {
	dir := t.TempDir()
	ca1, err := newStealthCA(dir)
	if err != nil {
		t.Fatalf("newStealthCA: %v", err)
	}
	if !ca1.cert.IsCA {
		t.Fatal("根证书 IsCA 应为 true")
	}
	if txt := certChainText(ca1.cert); strings.Contains(strings.ToLower(txt), "mitmproxy") {
		t.Errorf("CA 主题含 mitmproxy 指纹： %s", txt)
	}
	if ca1.org == "" {
		t.Error("叶子 O（取自 CA 主题）为空")
	}
	// 三个持久化文件都必须落盘
	for _, name := range []string{caKeyPairFile, caCertPemFile, caCertCerFile} {
		if _, err := os.ReadFile(filepath.Join(dir, name)); err != nil {
			t.Errorf("缺持久化文件 %s: %v", name, err)
		}
	}
	// 重启后加载同一 CA（序列号一致），不重新随机
	ca2, err := newStealthCA(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if ca2.cert.SerialNumber.Cmp(ca1.cert.SerialNumber) != 0 {
		t.Error("重载后 CA 变了（持久化未生效）")
	}
}

func TestStealthCALeafChain(t *testing.T) {
	ca, err := newStealthCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.GetCert("example.com")
	if err != nil {
		t.Fatal(err)
	}
	lc, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	// 叶子 + 根整条链都不含 mitmproxy
	if txt := certChainText(lc, ca.cert); strings.Contains(strings.ToLower(txt), "mitmproxy") {
		t.Errorf("证书链含 mitmproxy 指纹：\n%s", txt)
	}
	// 叶子必须能被根验签（模拟客户端信任根后的校验）
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if _, err := lc.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: roots}); err != nil {
		t.Errorf("叶子证书链校验失败： %v", err)
	}
	if len(lc.Subject.Organization) == 0 || lc.Subject.Organization[0] != ca.org {
		t.Errorf("叶子 O=%q 与根 O=%q 不一致", lc.Subject.Organization, ca.org)
	}
	// 缓存：同名重复取应是同一张
	again, _ := ca.GetCert("example.com")
	if again != leaf {
		t.Error("GetCert 缓存未生效")
	}
}

func TestStealthCAReplacesLegacyFingerprintedCA(t *testing.T) {
	dir := t.TempDir()
	// 模拟历史版本落盘的 mitmproxy 主题 CA
	key, cert, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}
	cert.Subject.CommonName = "mitmproxy"
	cert.Subject.Organization = []string{"mitmproxy"}
	legacy := &stealthCA{key: key, cert: cert, org: "mitmproxy", cache: map[string]*tls.Certificate{}}
	if err := legacy.save(dir); err != nil {
		t.Fatal(err)
	}
	ca, err := newStealthCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if txt := certChainText(ca.cert); strings.Contains(strings.ToLower(txt), "mitmproxy") {
		t.Errorf("历史指纹 CA 未被替换： %s", txt)
	}
}

// TestStealthCAAcceptedByMitmproxy 是关键验收：起真实 go-mitmproxy 代理 + 真实
// TLS 后端，客户端经代理完成一次 HTTPS 请求。证明 NewCaFunc 注入的 CA 被库用于
// 实际拦截签发，且整条链无 mitmproxy 字样。
func TestStealthCAAcceptedByMitmproxy(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	ca, err := newStealthCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// 先占一个空闲端口再让出，供代理监听
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := ln.Addr().String()
	_ = ln.Close()

	proxy, err := mproxy.NewProxy(&mproxy.Options{
		Addr:        proxyAddr,
		SslInsecure: true,
		NewCaFunc: func() (mcert.CA, error) {
			return ca, nil
		},
	})
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	go func() { _ = proxy.Start() }()
	defer proxy.Close()
	// 等监听起来
	up := false
	for i := 0; i < 100; i++ {
		conn, err := net.DialTimeout("tcp", proxyAddr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			up = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !up {
		t.Fatal("代理监听未起")
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	// 用 localhost 访问后端（IP 直连无 SNI，库按 chi.ServerName 签发会拿不到
	// 名字；真实场景目标是域名）。localhost 平台侧可解析、客户端可验证。
	backendURL := strings.Replace(backend.URL, "127.0.0.1", "localhost", 1)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(backendURL)
	if err != nil {
		t.Fatalf("经代理 HTTPS 请求失败: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("响应体 = %q, want ok", string(body))
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("响应无 TLS 对端证书")
	}
	chain := append(append([]*x509.Certificate{}, resp.TLS.PeerCertificates...), ca.cert)
	if txt := certChainText(chain...); strings.Contains(strings.ToLower(txt), "mitmproxy") {
		t.Errorf("实际拦截证书链含 mitmproxy 指纹：\n%s", txt)
	}
	if got := resp.TLS.PeerCertificates[0].Issuer.String(); got != ca.cert.Subject.String() {
		t.Errorf("叶子 issuer = %q, want 平台 CA 主题 %q", got, ca.cert.Subject.String())
	}
	t.Logf("实际拦截链（无指纹）:\n%s", certChainText(chain...))
}
