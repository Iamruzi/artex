// ca.go 实现平台自签 MITM CA（批 7 P1-1：去 mitmproxy 指纹）。
//
// go-mitmproxy 内置 SelfSignCA 把 CN=mitmproxy、O=mitmproxy 写死在根证书与每张
// 叶子证书上——目标侧查看 HTTPS 证书链即可确认流量正被 mitmproxy 录制。这里实现
// 库的 cert.CA 接口（GetRootCA/GetCert），经 proxy.Options.NewCaFunc 注入：
// 根证书 CN/O 首次生成时随机化为企业 CA 形态，叶子 O 与根保持一致（企业 TLS
// 检查设备的常见形态），证书链任何一环都不再出现 mitmproxy 字样。
//
// 持久化布局与库保持兼容（mitmproxy-ca.pem = PKCS8 私钥 + 证书，
// mitmproxy-ca-cert.pem/.cer = 纯证书），文件名是平台侧内部细节，不出现在证书链。
// 历史安装若已落过 mitmproxy 主题的旧 CA，加载时检测到即重新生成覆盖，
// 否则指纹会随旧文件一直残留。
package traffic

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CA 主题随机化词表：通用企业/技术词，不指向任何真实厂商。
var (
	caNameWordsA = []string{"Meridian", "Northgate", "Blueridge", "Cedarpoint", "Aster", "Vantage", "Harborline", "Stonebridge", "Clearwater", "Ironwood", "Fairview", "Lakeshore"}
	caNameWordsB = []string{"Systems", "Networks", "Technologies", "Solutions", "Communications", "Digital", "Infrastructure", "Services"}
	caNameSuffix = []string{"Inc.", "Ltd.", "Corp.", "LLC"}
	caCertKinds  = []string{"Root CA", "Root Certificate Authority", "Enterprise Root CA", "Internal Root CA"}
)

// stealthCA 实现 go-mitmproxy 的 cert.CA 接口（包内不引入库的类型依赖，
// 由调用方在 NewCaFunc 里做接口断言）。叶子证书按 commonName 缓存。
type stealthCA struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
	org  string // 叶子证书 O，与根证书 O 一致

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// 持久化文件名与 go-mitmproxy 布局一致（CACertPath 等既有引用不变）。
const (
	caKeyPairFile = "mitmproxy-ca.pem"      // 私钥 + 证书
	caCertPemFile = "mitmproxy-ca-cert.pem" // 纯证书（客户端信任用）
	caCertCerFile = "mitmproxy-ca-cert.cer" // 纯证书（Windows 导入用）
)

// newStealthCA 加载 dir 下已持久化的 CA；缺失或主题仍带 mitmproxy 指纹时重新
// 生成并落盘。dir 必须已存在（Open 已建好）。
func newStealthCA(dir string) (*stealthCA, error) {
	pairFile := filepath.Join(dir, caKeyPairFile)
	if key, cert, err := loadCAPair(pairFile); err == nil {
		if !caSubjectFingerprinted(cert) {
			return &stealthCA{key: key, cert: cert, org: firstOrg(cert), cache: map[string]*tls.Certificate{}}, nil
		}
		// 历史遗留的 mitmproxy 主题 CA：重新生成覆盖，消除残留指纹。
	}
	key, cert, err := generateCA()
	if err != nil {
		return nil, err
	}
	ca := &stealthCA{key: key, cert: cert, org: firstOrg(cert), cache: map[string]*tls.Certificate{}}
	if err := ca.save(dir); err != nil {
		return nil, err
	}
	return ca, nil
}

// caSubjectFingerprinted 报告证书主题是否带 mitmproxy 指纹（CN 或任一 O）。
func caSubjectFingerprinted(c *x509.Certificate) bool {
	if strings.Contains(strings.ToLower(c.Subject.CommonName), "mitmproxy") {
		return true
	}
	for _, o := range c.Subject.Organization {
		if strings.Contains(strings.ToLower(o), "mitmproxy") {
			return true
		}
	}
	return false
}

func firstOrg(c *x509.Certificate) string {
	if len(c.Subject.Organization) > 0 {
		return c.Subject.Organization[0]
	}
	return c.Subject.CommonName
}

// generateCA 生成主题随机化的自签根证书（企业 CA 形态）。
func generateCA() (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	org := pickWord(caNameWordsA) + " " + pickWord(caNameWordsB) + " " + pickWord(caNameSuffix)
	cn := pickWord(caNameWordsA) + " " + pickWord(caNameWordsB) + " " + pickWord(caCertKinds)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	// 有效期仿真实 CA：backdate 1~30 天，总长 5~10 年，起止不落在整点。
	backdate := time.Duration(1+randIntn(30)) * 24 * time.Hour
	validity := time.Duration(5*365+randIntn(5*365)) * 24 * time.Hour
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{org}},
		NotBefore:             time.Now().Add(-backdate),
		NotAfter:              time.Now().Add(validity),
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func pickWord(list []string) string { return list[randIntn(len(list))] }

func randIntn(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// loadCAPair 按库的布局解析私钥 + 证书 PEM（PKCS8 优先，PKCS1 回退）。
func loadCAPair(path string) (*rsa.PrivateKey, *x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	keyBlock, rest := pem.Decode(data)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("%s 中不存在 PRIVATE KEY", path)
	}
	certBlock, _ := pem.Decode(rest)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("%s 中不存在 CERTIFICATE", path)
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("%s 私钥非 RSA", path)
		}
		key = rsaKey
	} else if k, err2 := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err2 == nil {
		key = k
	} else {
		return nil, nil, fmt.Errorf("%s 私钥解析失败: %v", path, err)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

// save 落盘三个文件（私钥 0600；Open 后另有 chmodCATree 兜底收紧）。
func (ca *stealthCA) save(dir string) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		return err
	}
	var pair bytes.Buffer
	if err := pem.Encode(&pair, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		return err
	}
	if err := pem.Encode(&pair, &pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, caKeyPairFile), pair.Bytes(), 0o600); err != nil {
		return err
	}
	var certPEM bytes.Buffer
	if err := pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}); err != nil {
		return err
	}
	for _, name := range []string{caCertPemFile, caCertCerFile} {
		if err := os.WriteFile(filepath.Join(dir, name), certPEM.Bytes(), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// GetRootCA 返回根证书（cert.CA 接口）。
func (ca *stealthCA) GetRootCA() *x509.Certificate { return ca.cert }

// GetCert 签发（并缓存）指定 commonName 的叶子证书。形态与库内 DummyCert 对齐，
// 差异仅在主题：CN=目标名，O=根证书机构名——链上无 mitmproxy 字样。
func (ca *stealthCA) GetCert(commonName string) (*tls.Certificate, error) {
	ca.mu.Lock()
	if c, ok := ca.cache[commonName]; ok {
		ca.mu.Unlock()
		return c, nil
	}
	ca.mu.Unlock()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{CommonName: commonName, Organization: []string{ca.org}},
		NotBefore:          time.Now().Add(-time.Hour * 48),
		NotAfter:           time.Now().Add(time.Hour * 24 * 365),
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	if ip := net.ParseIP(commonName); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{commonName}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &ca.key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: ca.key}

	ca.mu.Lock()
	ca.cache[commonName] = leaf
	ca.mu.Unlock()
	return leaf, nil
}
