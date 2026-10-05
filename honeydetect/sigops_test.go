package honeydetect

// 条件操作符(_not / exists)、逐条件 trace、严格校验与加载回退的测试。
// 签名均为自拟测试数据,不对应真实产品。

import (
	"os"
	"strings"
	"testing"
	"time"
)

// 使用新操作符的测试签名库。
const testOpSigs = `{"signatures":[
  {"name":"neg_banner","product":"X","confidence":0.9,"source":"t",
   "match":{"banner_substr":"OpenSSH","banner_not_substr":"Ubuntu"}},
  {"name":"exists_structural","product":"Y","confidence":0.8,"source":"t",
   "match":{"banner_substr":"*","banner_not_substr":"SSH-2.0-"}},
  {"name":"title_exists","product":"Z","confidence":0.7,"source":"t",
   "match":{"http_title_substr":"*"}}
]}`

func TestNotOperator(t *testing.T) {
	e := NewEngine(writeSigs(t, testOpSigs))
	// 含 Ubuntu → _not 条件失败 → 不命中 neg_banner。
	if score, _ := e.Evaluate(ServiceView{Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"}); score >= 0.9 {
		t.Fatalf("banner 含 Ubuntu 应被 _not 条件否决,score=%v", score)
	}
	// 不含 Ubuntu → 双条件成立 → 命中(但同视图 banner 以 SSH-2.0- 开头,
	// exists_structural 不命中,最终只命中 neg_banner 的 0.9)。
	score, ev := e.Evaluate(ServiceView{Banner: "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"})
	if score != 0.9 || len(ev) != 1 || !strings.Contains(ev[0], "neg_banner") {
		t.Fatalf("neg_banner 应命中,score=%v ev=%v", score, ev)
	}
}

func TestExistsOperator(t *testing.T) {
	e := NewEngine(writeSigs(t, testOpSigs))
	// exists + _not 组合:"有 banner 但不是标准 SSH 版本串"。
	score, ev := e.Evaluate(ServiceView{Banner: "220 mail.example ESMTP Postfix"})
	if score != 0.8 || len(ev) != 1 || !strings.Contains(ev[0], "exists_structural") {
		t.Fatalf("exists 结构条件应命中,score=%v ev=%v", score, ev)
	}
	// banner 为空 → exists 不成立 → 不命中。
	if score, _ := e.Evaluate(ServiceView{}); score != 0 {
		t.Fatalf("空视图不应命中 exists 条件,score=%v", score)
	}
	// title 存在即命中 title_exists。
	if score, _ := e.Evaluate(ServiceView{Title: "Welcome"}); score != 0.7 {
		t.Fatalf("title exists 应命中 0.7,score=%v", score)
	}
}

func TestEvaluateWithTrace(t *testing.T) {
	e := NewEngine(writeSigs(t, testSigs))
	// 视图:端口不匹配 hfish、banner 不匹配 cowrie、证书不匹配 dionaea → 全未命中。
	_, _, trace := e.EvaluateWithTrace(ServiceView{Port: 8080, Body: "nothing relevant", Banner: "OpenSSH_8.9"})
	if len(trace) != 3 {
		t.Fatalf("trace 应覆盖全部 3 条签名,实得 %d", len(trace))
	}
	byName := map[string]SigTrace{}
	for _, tr := range trace {
		byName[tr.Name] = tr
		if tr.Matched {
			t.Errorf("本视图不应有命中,%s 误标 matched", tr.Name)
		}
	}
	// hfish:port 命中、http_body_substr 失败(且其后无条件可短路)。
	hf := byName["hfish_default_web_xjs"]
	if hf.FirstFailed() != "http_body_substr" || hf.MatchedConds() != 1 {
		t.Errorf("hfish trace 应为 port=matched + http_body_substr=not_matched,实得 %+v", hf.Conds)
	}
	// 逐条件结果枚举正确性:port=matched, body=not_matched。
	if hf.Conds[0].Field != "port" || hf.Conds[0].Result != CondMatched ||
		hf.Conds[1].Field != "http_body_substr" || hf.Conds[1].Result != CondNotMatched {
		t.Errorf("hfish 逐条件结果不符: %+v", hf.Conds)
	}

	// 命中视图:多条件签名短路——port 失败时 http_body_substr 应 not_evaluated。
	score, _, trace2 := e.EvaluateWithTrace(ServiceView{Port: 22, Banner: "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"})
	if score != 0.99 {
		t.Fatalf("cowrie 应命中 0.99,实得 %v", score)
	}
	for _, tr := range trace2 {
		switch tr.Name {
		case "cowrie_default_ssh_banner":
			if !tr.Matched || tr.Conds[0].Result != CondMatched {
				t.Errorf("cowrie trace 应为命中,实得 %+v", tr)
			}
		case "hfish_default_web_xjs":
			if tr.Matched || tr.Conds[0].Result != CondNotMatched ||
				tr.Conds[1].Result != CondNotEvaluated {
				t.Errorf("hfish 短路 trace 不符(port 失败后 body 应 not_evaluated): %+v", tr)
			}
		}
	}
}

func TestStrictValidationRejects(t *testing.T) {
	cases := map[string]string{
		"未知顶层字段":  `{"signatures":[],"typo":1}`,
		"未知 match 字段": `{"signatures":[{"name":"a","product":"p","confidence":0.9,"source":"s","match":{"banner_substrr":"x"}}]}`,
		"无条件签名":   `{"signatures":[{"name":"a","product":"p","confidence":0.9,"source":"s","match":{}}]}`,
		"无 source":  `{"signatures":[{"name":"a","product":"p","confidence":0.9,"match":{"banner_substr":"x"}}]}`,
		"confidence 越界": `{"signatures":[{"name":"a","product":"p","confidence":1.5,"source":"s","match":{"banner_substr":"x"}}]}`,
		"confidence 为零": `{"signatures":[{"name":"a","product":"p","confidence":0,"source":"s","match":{"banner_substr":"x"}}]}`,
		"port 越界":   `{"signatures":[{"name":"a","product":"p","confidence":0.9,"source":"s","match":{"port":70000}}]}`,
		"正负条件同值矛盾": `{"signatures":[{"name":"a","product":"p","confidence":0.9,"source":"s","match":{"banner_substr":"x","banner_not_substr":"x"}}]}`,
		"非 JSON":   `{not json`,
		"空文件":    ``,
	}
	for name, body := range cases {
		if _, err := parseSignaturesStrict([]byte(body)); err == nil {
			t.Errorf("用例[%s]应被严格校验拒绝", name)
		}
	}
	// 合法库照常解析(含新操作符)。
	sigs, err := parseSignaturesStrict([]byte(testOpSigs))
	if err != nil || len(sigs) != 3 {
		t.Errorf("合法签名库应解析成功,sigs=%d err=%v", len(sigs), err)
	}
}

func TestReloadFailureKeepsLastGood(t *testing.T) {
	// 先载好签名并确认命中。
	p := writeSigs(t, testSigs)
	e := NewEngine(p)
	if score, _ := e.Evaluate(ServiceView{Banner: "OpenSSH_6.0p1 Debian-4+deb7u2"}); score != 0.99 {
		t.Fatalf("好签名应命中 0.99")
	}
	// rewrite 覆写签名文件并【确定性递增】 mtime:不能取"当前文件 mtime +N"——
	// 上一次拨到未来的 mtime 会被 WriteFile 用真实墙钟回拨,再加同样的 N 恰好
	// 等于引擎缓存的 modTime,热更新不触发(Windows 上实测高频复现)。用测试内
	// 单调递增的 tick 彻底回避墙钟。
	tick := mustStat(t, p).ModTime()
	rewrite := func(body string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		tick = tick.Add(2 * time.Second)
		if err := os.Chtimes(p, tick, tick); err != nil {
			t.Fatal(err)
		}
	}
	// 改成坏文件(无条件签名)→ 整体回退到上一份好签名,判定结果不变。
	rewrite(`{"signatures":[{"name":"bad","product":"x","confidence":0.9,"source":"s","match":{}}]}`)
	if score, _ := e.Evaluate(ServiceView{Banner: "OpenSSH_6.0p1 Debian-4+deb7u2"}); score != 0.99 {
		t.Fatalf("坏文件应回退到上一份好签名,仍命中 0.99")
	}
	// 再改回合法的新签名库 → 热更新正常恢复。
	rewrite(testOpSigs)
	if score, _ := e.Evaluate(ServiceView{Title: "Welcome"}); score != 0.7 {
		t.Fatalf("坏文件修复后应恢复热更新,title exists 命中 0.7")
	}
}

func TestFirstLoadFailureFallsBackToEmbedded(t *testing.T) {
	// 首次加载就没有好签名(坏文件)→ 回退内嵌库(内嵌 cowrie 签名应可命中)。
	e := NewEngine(writeSigs(t, `{"signatures":[{"name":"bad","product":"x","confidence":0.9,"source":"s","match":{}}]}`))
	if score, _ := e.Evaluate(ServiceView{Banner: "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"}); score != 0.99 {
		t.Fatalf("首次加载失败应回退内嵌库(内嵌 cowrie 命中 0.99),实得 %v", score)
	}
}
