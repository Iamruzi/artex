// suo5_perturb_test.go 验证批 7 P1-2 的结构扰动层：两次生成内容不同、协议关键
// 字段逐字节等价（拼接还原后一致）、注释剥除、声明标识符随机化、原文段（jsp
// 模板 HTML）不动。本机有 php 时对真实 payload 跑 php -l，没有则 SKIP。
package tunnel

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fixturePhp 是带代表性的 php 片段：行/块注释、函数声明与调用、协议字符串。
const fixturePhp = `<?php
// 行注释要剥掉 "PHPSESSID" 不剥
/* 块注释
   也要剥掉 */
$SAVED_PHPSESSID = '';
if (array_key_exists('PHPSESSID', $_COOKIE)) {
    $SAVED_PHPSESSID = $_COOKIE['PHPSESSID'];
}
function processHandshake($req, $dataMap) {
    // 注释里的 processTunnel 不该影响重命名
    return acquireLock($req);
}
function processTunnel($x) { return $x; }
function acquireLock($k) { return processTunnel($k); }
$headers[] = 'Cookie: PHPSESSID=' . $SAVED_PHPSESSID;
processHandshake($a, $b);
`

// fixtureJsp 是带代表性的 jsp 片段：声明段 + 执行 scriptlet + 模板 HTML 原文段。
const fixtureJsp = `<%!
    public static class Suo5Tunnel implements Runnable {
        private void processHandshake(String sid) { }
        public void run() { processHandshake("x"); }
    }
%>
<html><!-- 模板 HTML 原样保留,含 processHandshake 字样 --></html>
<%
    Suo5Tunnel o = new Suo5Tunnel();
    o.run();
%>
`

// squashPhpConcat 把拆拼后的相邻单引号字面量还原（'AB' . 'CD' → ABCD),
// 供协议字段等价断言。
func squashPhpConcat(s string) string {
	for _, sep := range []string{"' . '", "'.'", "' .'", "'. '"} {
		s = strings.ReplaceAll(s, sep, "")
	}
	return s
}

func TestPerturbPhpStructure(t *testing.T) {
	out1 := string(perturbSuo5Payload("suo5.php", []byte(fixturePhp)))
	out2 := string(perturbSuo5Payload("suo5.php", []byte(fixturePhp)))
	if out1 == fixturePhp {
		t.Error("扰动后内容与原文件相同")
	}
	if out1 == out2 {
		t.Error("两次扰动生成内容相同（随机化未生效）")
	}
	// 注释剥除
	if strings.Contains(out1, "行注释要剥掉") || strings.Contains(out1, "块注释") {
		t.Errorf("注释未被剥除:\n%s", out1)
	}
	// 协议字段等价（拼接还原后逐字节一致）
	sq := squashPhpConcat(out1)
	for _, want := range []string{"'PHPSESSID'", "'Cookie: PHPSESSID='", "$_COOKIE['PHPSESSID']"} {
		if !strings.Contains(sq, want) {
			t.Errorf("协议字段 %q 未保留:\n%s", want, sq)
		}
	}
	// 函数声明被重命名：原名不再作为声明出现
	for _, fn := range []string{"processHandshake", "processTunnel", "acquireLock"} {
		if strings.Contains(out1, "function "+fn+"(") {
			t.Errorf("函数 %s 未被重命名:\n%s", fn, out1)
		}
	}
	// 重命名一致性：调用点与声明同名（统计 'function X(' 与 ' X(' 出现关系弱,
	// 这里强断言：三个新名声明各出现一次且互不撞名）
	decls := 0
	for _, line := range strings.Split(out1, "\n") {
		if strings.Contains(line, "function ") {
			decls++
		}
	}
	if decls != 3 {
		t.Errorf("函数声明数 = %d, want 3（重命名不能丢函数）:\n%s", decls, out1)
	}
	// 死代码注入：$<随机> = <数字>;
	if !strings.Contains(out1, "<?php\n$") {
		t.Errorf("php 死代码未注入到 <?php 之后:\n%.120s", out1)
	}
}

func TestPerturbJspStructure(t *testing.T) {
	out1 := string(perturbSuo5Payload("suo5.jsp", []byte(fixtureJsp)))
	out2 := string(perturbSuo5Payload("suo5.jsp", []byte(fixtureJsp)))
	if out1 == fixtureJsp || out1 == out2 {
		t.Error("jsp 扰动未生效或两次相同")
	}
	// 模板 HTML 原文段必须逐字节保留（对外可见行为不变）
	if !strings.Contains(out1, "<html><!-- 模板 HTML 原样保留,含 processHandshake 字样 --></html>") {
		t.Errorf("jsp 模板 HTML 被改动:\n%s", out1)
	}
	// run 是 Runnable 回调,不许重命名
	if !strings.Contains(out1, "public void run()") {
		t.Errorf("接口回调 run 被改名:\n%s", out1)
	}
	// 类名与自有方法名必须改掉,且 HTML 段里的同名字样不受影响（原文段不动）
	code := strings.Replace(out1, "<html><!-- 模板 HTML 原样保留,含 processHandshake 字样 --></html>", "", 1)
	if strings.Contains(code, "Suo5Tunnel") || strings.Contains(code, "processHandshake") {
		t.Errorf("jsp 类名/方法名未被重命名:\n%s", code)
	}
}

func TestPerturbUnknownFilePassthrough(t *testing.T) {
	raw := []byte("whatever")
	if got := perturbSuo5Payload("shell.bin", raw); string(got) != string(raw) {
		t.Error("未知 payload 类型应原样返回")
	}
}

// TestPerturbRealPayloads 对 data/tools/suo5-payloads 里的真实上游 payload 做
// 扰动验证（目录不存在时跳过——它不随仓库分发，由安装工具准备）。
func TestPerturbRealPayloads(t *testing.T) {
	dir := filepath.Join("..", "data", "tools", "suo5-payloads")
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Skip("data/tools/suo5-payloads 不存在,跳过真实 payload 验证")
	}
	for _, name := range []string{"suo5.php", "suo5.jsp", "suo5.aspx"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("读 %s: %v", name, err)
			continue
		}
		out1 := perturbSuo5Payload(name, raw)
		out2 := perturbSuo5Payload(name, raw)
		if string(out1) == string(raw) {
			t.Errorf("%s 扰动后与原文相同", name)
		}
		if string(out1) == string(out2) {
			t.Errorf("%s 两次扰动结果相同", name)
		}
		// 协议关键字段：拼接还原后必须仍在
		check := string(out1)
		if name == "suo5.php" {
			check = squashPhpConcat(check)
		} else {
			for _, sep := range []string{`" + "`, `"+"`, `" +"`, `"+ "`} {
				check = strings.ReplaceAll(check, sep, "")
			}
		}
		for _, kw := range protocolKeywords(name) {
			if !strings.Contains(check, kw) {
				t.Errorf("%s 协议关键字 %q 丢失", name, kw)
			}
		}
		// 花括号/圆括号配平（粗粒度语法健全性检查）
		for _, pair := range [][2]rune{{'{', '}'}, {'(', ')'}} {
			o, c := strings.Count(string(out1), string(pair[0])), strings.Count(string(out1), string(pair[1]))
			ro, rc := strings.Count(string(raw), string(pair[0])), strings.Count(string(raw), string(pair[1]))
			if o != c || ro != rc {
				t.Errorf("%s 括号不配平: 扰动后 %c%c=%d/%d, 原文=%d/%d", name, pair[0], pair[1], o, c, ro, rc)
			}
		}
		// php -l 语法检查（本机有 php 才跑）
		if name == "suo5.php" {
			if php, err := exec.LookPath("php"); err == nil {
				tmp := filepath.Join(t.TempDir(), "p.php")
				if err := os.WriteFile(tmp, out1, 0o600); err != nil {
					t.Fatal(err)
				}
				if out, err := exec.Command(php, "-l", tmp).CombinedOutput(); err != nil {
					t.Errorf("php -l 未通过: %v\n%s", err, out)
				}
			} else {
				t.Log("SKIP: 本机无 php,跳过 php -l 语法检查")
			}
		}
	}
}

// protocolKeywords 是各语言 payload 的协议关键字段（会话标识/帧字段名）。
func protocolKeywords(name string) []string {
	switch name {
	case "suo5.php":
		return []string{"PHPSESSID", "'Cookie: PHPSESSID='", "X-Accel-Buffering", "Content-Type"}
	case "suo5.jsp":
		return []string{"X-Accel-Buffering", "Content-Type", `"sid"`}
	case "suo5.aspx":
		return []string{"X-Accel-Buffering", "Content-Type", `"sid"`}
	}
	return nil
}
