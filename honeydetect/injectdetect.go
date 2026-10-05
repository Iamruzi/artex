package honeydetect

// 反 AI 蜜罐「Agent 注入内容检测」信号类(HONEYPOT-DETECTION-DESIGN.md 二-B 节
// 「识别信号」行):AgentMirror 类蜜罐的恶意性全在内容语义里——页面正文诱导 agent
// 执行采集/指纹命令(uname/hostname/...)并把输出 POST 回传,静态签名(banner/title/
// 证书子串)对它们零命中。本文件对文本内容(页面正文/接口响应)做启发式评分。
//
// 规则全部数据驱动:词表与权重集中在下方模式表,后续只调表不改判定逻辑。评分按
// 命中信号加权求和,封顶 1.0;>= InjectSuspectThreshold 判疑似。页面自曝"蜜罐/
// 靶场/授权测试平台"时降分(CTF 靶场正常提示的误伤控制)。

import (
	"fmt"
	"regexp"
	"strings"
)

// InjectSuspectThreshold 是注入内容判疑似的阈值:与 evaluateHoneypot 的处置档
// 映射(score>=0.6 → medium)对齐,低于它的弱信号只作观察不标资产。
const InjectSuspectThreshold = 0.6

// injectPattern 是模式表的一条匹配模式:普通条目按大小写不敏感子串匹配;
// "re:" 前缀的条目按正则匹配(预先编译,大小写不敏感)。
type injectPattern struct {
	raw string
	re  *regexp.Regexp // 非 nil 时走正则
}

func compileInjectPatterns(raws []string) []injectPattern {
	out := make([]injectPattern, 0, len(raws))
	for _, r := range raws {
		p := injectPattern{raw: r}
		if strings.HasPrefix(r, "re:") {
			p.re = regexp.MustCompile(`(?i)` + strings.TrimPrefix(r, "re:"))
		}
		out = append(out, p)
	}
	return out
}

// match 报告该模式是否命中已小写化的文本(正则模式对原文匹配,自带 (?i))。
func (p injectPattern) match(lower, orig string) bool {
	if p.re != nil {
		return p.re.MatchString(orig)
	}
	return strings.Contains(lower, p.raw)
}

// ---------------- 模式表(数据驱动,后续可调) ----------------

// injectCollectCommands 是"要求执行采集/指纹命令"的命令清单。命令按词边界正则
// 匹配(\b 包住,防 id/pwd/env 这类短词在普通英文行文里误命中)。
var injectCollectCommands = compileInjectPatterns([]string{
	`re:\buname\b`, `re:\bhostname\b`, `re:\bwhoami\b`, `re:\bid\b`, `re:\bpwd\b`,
	`re:\bifconfig\b`, `re:\bipconfig\b`, `re:\bip\s+addr\b`, `re:\benv\b`,
	`re:\bprintenv\b`, `re:\bdate\b`, `re:\buptime\b`, `re:\bps\b`, `re:\bdf\b`,
	`re:\bnetstat\b`, `re:\blsblk\b`, `re:\bmount\b`, `re:\blscpu\b`, `re:\blsusb\b`,
	`re:\barp\b`, `re:\broute\b`, `re:\bsysteminfo\b`, `re:\btasklist\b`, `re:\bwmic\b`,
	`re:cat\s+/etc/(passwd|issue|os-release)`, `re:cat\s+/proc/(cpuinfo|meminfo|version)`,
})

// injectExecContext 是"请执行/运行以下命令"的语境话术;命令清单出现在该语境里
// 才加权(孤立地提到命令≠要求 agent 执行)。
var injectExecContext = compileInjectPatterns([]string{
	"请执行", "请运行", "执行以下", "运行以下", "执行下面", "运行下面",
	"依次执行", "依次运行", "执行命令", "运行命令",
	"run the following", "execute the following", "please run", "please execute",
	"run these commands", "execute these commands",
})

// injectPostHints 是回传信道提示(HTTP 方法词)。
var injectPostHints = compileInjectPatterns([]string{
	`re:\bPOST\b`, `re:\bPUT\b`,
})

// injectExfilSemantics 是回传语义话术(与 POST 共现才算"要求回传"信号)。
var injectExfilSemantics = compileInjectPatterns([]string{
	"回传", "回执", "上报", "提交",
	"receipt", "callback", "attestation", "attest", "submit",
	"report back", "send back", "post back",
})

// injectCallbackSlots 是明确的 callback URL 槽位(无需 POST 共现,单独成信号)。
var injectCallbackSlots = compileInjectPatterns([]string{
	"callback_url", "{{callback",
	`re:https?://[^\s"'<>]*/(callback|collect|attest|receipt|report)\b`,
})

// injectSessionFields 是会话凭证话术字段(run_id/token/nonce/receipt_id 组合)。
var injectSessionFields = compileInjectPatterns([]string{
	"run_id", "session_id", "receipt_id", "x-run-id", "x-run-token",
	`re:\btoken\b`, `re:\bnonce\b`,
})

// injectPressure 是伪装正当性的施压话术(弱信号,低分)。
var injectPressure = compileInjectPatterns([]string{
	"授权环境", "已授权", "授权测试", "验收", "合规要求", "必须执行", "必须运行", "务必执行",
	"authorized environment", "compliance", "mandatory",
	"you must execute", "you must run",
})

// injectSelfDisclosure 是自曝缓解:页面自称蜜罐/靶场/授权测试平台时降分
// (CTF 靶场的正常提示与正当说明不该被当成诱导)。
var injectSelfDisclosure = compileInjectPatterns([]string{
	"蜜罐", "honeypot", "授权测试平台", "靶场", "攻防演练平台",
})

// 信号权重表(求和封顶 1.0;阈值依据见 InjectEvaluate 注释):
const (
	wInjectCmdSingle = 0.10 // 仅 1 个采集命令
	wInjectCmdMulti  = 0.25 // ≥2 个采集命令(清单形态)
	wInjectExecCtx   = 0.15 // 命令出现在"请执行/运行以下"语境
	wInjectExfilPost = 0.35 // POST + 回传语义
	wInjectCallback  = 0.20 // 明确 callback URL 槽位
	wInjectFields2   = 0.10 // 会话凭证字段 ≥2 个
	wInjectFields3   = 0.15 // 会话凭证字段 ≥3 个
	wInjectPressure  = 0.10 // 施压话术(弱信号)
	wInjectSelfDisc  = -0.40 // 自曝缓解(降分)
)

// InjectEvaluate 对文本内容(页面正文/接口响应)做"诱导 agent 执行+回传"的
// 启发式评分,返回 0-1 分与命中证据(每条 "信号名(命中明细)");无命中返回 0 分。
//
// 阈值依据:判疑似要求"采集诱导"与"回传"两个维度至少各中一条——最典型的组合
// 命令清单(0.25)+执行语境(0.15)+POST 回传(0.35)=0.75 ≥ 0.6;只含命令不含回传
// 最高 0.25+0.15=0.40(正常 CTF 题面/文档站落档于此,不误伤);再叠自曝缓解 -0.40
// 把"自称靶场"的正当页面压回安全区。
func InjectEvaluate(content string) (score float64, evidence []string) {
	if strings.TrimSpace(content) == "" {
		return 0, nil
	}
	lower := strings.ToLower(content)

	// 采集/指纹命令:按命中命令数分档;出现在执行语境里再加权。
	cmdHits := matchInjectSet(injectCollectCommands, lower, content)
	switch {
	case len(cmdHits) >= 2:
		score += wInjectCmdMulti
		evidence = append(evidence, fmt.Sprintf("collect_commands(%s)", strings.Join(cmdHits, ",")))
	case len(cmdHits) == 1:
		score += wInjectCmdSingle
		evidence = append(evidence, fmt.Sprintf("collect_command(%s)", cmdHits[0]))
	}
	if len(cmdHits) > 0 {
		if hits := matchInjectSet(injectExecContext, lower, content); len(hits) > 0 {
			score += wInjectExecCtx
			evidence = append(evidence, fmt.Sprintf("exec_context(%s)", hits[0]))
		}
	}

	// 回传:POST 方法与回传语义共现;或出现明确的 callback URL 槽位。
	post := len(matchInjectSet(injectPostHints, lower, content)) > 0
	if exfilHits := matchInjectSet(injectExfilSemantics, lower, content); post && len(exfilHits) > 0 {
		score += wInjectExfilPost
		evidence = append(evidence, fmt.Sprintf("exfil_post(POST+%s)", exfilHits[0]))
	}
	if cbHits := matchInjectSet(injectCallbackSlots, lower, content); len(cbHits) > 0 {
		score += wInjectCallback
		evidence = append(evidence, fmt.Sprintf("callback_slot(%s)", cbHits[0]))
	}

	// 会话凭证话术:run_id/token/nonce/receipt_id 字段组合,按命中数分档。
	fieldHits := matchInjectSet(injectSessionFields, lower, content)
	switch {
	case len(fieldHits) >= 3:
		score += wInjectFields3
		evidence = append(evidence, fmt.Sprintf("session_fields(%s)", strings.Join(fieldHits, ",")))
	case len(fieldHits) == 2:
		score += wInjectFields2
		evidence = append(evidence, fmt.Sprintf("session_fields(%s)", strings.Join(fieldHits, ",")))
	}

	// 施压话术(弱信号)。
	if hits := matchInjectSet(injectPressure, lower, content); len(hits) > 0 {
		score += wInjectPressure
		evidence = append(evidence, fmt.Sprintf("pressure(%s)", hits[0]))
	}

	// 自曝缓解:自称蜜罐/靶场/授权测试平台 → 降分。
	if hits := matchInjectSet(injectSelfDisclosure, lower, content); len(hits) > 0 {
		score += wInjectSelfDisc
		evidence = append(evidence, fmt.Sprintf("self_disclosure(%s)", hits[0]))
	}

	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	if score == 0 {
		evidence = nil
	}
	return score, evidence
}

// InjectSuspected 报告该内容是否达到注入诱导疑似档(>= InjectSuspectThreshold)。
func InjectSuspected(content string) bool {
	score, _ := InjectEvaluate(content)
	return score >= InjectSuspectThreshold
}

// matchInjectSet 返回模式集中命中的模式原文(去重、按表序),用于计档与写证据。
func matchInjectSet(set []injectPattern, lower, orig string) []string {
	var hits []string
	for _, p := range set {
		if p.match(lower, orig) {
			hits = append(hits, strings.TrimPrefix(p.raw, "re:"))
		}
	}
	return hits
}
