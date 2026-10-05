package agent

// 批 6 L1(设计文档 HONEYPOT-DETECTION-DESIGN.md 二·L1 + 「处置策略」表):
// 蜜罐静态签名识别层在 agent 侧的挂点与 planner 处置纪律。
// - evaluateHoneypot:service 资产落库后跑 honeydetect 签名评估,score>0 时
//   回写资产 honeypot_score/evidence(db.SetHoneypotScore,取更高分+证据去重),
//   并写一条 fact 进探索图锚定该资产(planner 每轮态势可见)。全部 best-effort,
//   失败不影响资产登记主流程。
// - plannerHoneypotRules:处置纪律,与批 5 红线同风格的代码固定尾(不可被 DB
//   正文覆盖),plannerSystem 统一追加。

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/honeydetect"
)

// plannerHoneypotRules 是 planner 的蜜罐处置纪律(设计文档「处置策略」表):
// 双信号才封锁,单信号只降级,疑似蜜罐上不投递/不爆破/不利用。
const plannerHoneypotRules = `

**蜜罐处置纪律(不可编辑)**:
1. 态势里的 honeypot_assets 是蜜罐信号命中的疑似资产,证据分两级:【签名级】(static-sig,banner/title/证书等静态指纹)与【内容级】(content-inject,页面诱导 agent 执行采集命令并回传)。单级命中属【单信号】:对它们**降级交互**——只用被动/只读手段继续观察,**不投递工具/载荷、不爆破、不利用**;仅凭单信号不得封锁方向。
2. 只有【双信号命中】才判定确认蜜罐,**停止在该方向派意图**:证据双级同现(签名级+内容级同时命中,即高置信)比照双信号处置;或静态签名 + 行为/登录后特征(如 /proc/meminfo 连读不变、ps 时间戳固定、egress 回连声称成功却无流量到达)。涉及反制型(MySQL 读客户端文件、客户端诱导)时,连客户端连接都不发起。
3. 疑似蜜罐资产上已有意图在跑的,让它以最低交互收尾,不追加高价值动作;侦察与利用资源优先投向无蜜罐信号的方向。
4. 全阴性【不等于】非蜜罐(高交互/加固蜜罐对自动化识别免疫):对无信号目标同样不投放高价值 exploit、控制噪声。`

// honeypotConfidence 把评分映射到处置档:≥0.9 high、≥0.6 medium(其余不记录)。
func honeypotConfidence(score float64) string {
	if score >= 0.9 {
		return "high"
	}
	return "medium"
}

// evaluateHoneypot 是 service/endpoint 资产落库后的 L1 评分挂点(insert_assets 与
// httpx 回写同路径)。best-effort:任何失败都只影响蜜罐标记,不影响资产登记。
//
// 信号合并(mergeHoneypotSignals):L1 静态签名(static-sig)与 Agent 注入内容检测
// (content-inject,设计文档二-B 节)评分取高、证据合并并标注来源。注入检测对
// body/title 的内容语义评分,覆盖静态签名零命中的 AgentMirror 类蜜罐(页面诱导
// agent 执行采集命令并 POST 回传)。
func (t *ToolSet) evaluateHoneypot(assetID int64, v honeydetect.ServiceView) {
	if assetID <= 0 {
		return
	}
	score, evidence, trace := mergeHoneypotSignals(v)
	if score <= 0 {
		return
	}
	if t.as != nil {
		_ = t.as.SetHoneypotScore(assetID, score, evidence)
	}
	if t.ts == nil || t.taskID <= 0 {
		return
	}
	conf := honeypotConfidence(score)
	payload := map[string]any{
		"summary": fmt.Sprintf("疑似蜜罐资产 #%d:蜜罐信号命中(score=%.2f, %s)", assetID, score, conf),
		"detail":  honeypotFactDetail(evidence, trace),
		// 签名匹配是对 banner/title/证书的直接观察 → observed;
		// honeypot_confidence 另记处置档(high/medium,评分映射)。
		"confidence":          FactConfidenceObserved,
		"honeypot_score":      score,
		"honeypot_confidence": conf,
		"honeypot_signatures": evidence,
	}
	_, _ = t.ts.AddNode(db.KindFact, payload, 5, "confirmed", t.worker, []int64{assetID})
}

// mergeHoneypotSignals 合并两类蜜罐识别信号(纯函数,便于单测):
//   - static-sig:L1 静态签名(banner/title/body/证书子串);
//   - content-inject:Agent 注入内容检测(对 title+body 的内容语义评分,
//     只在 >= 疑似阈值时纳入,弱信号不标资产防噪声)。
//
// 评分取两者之高;证据合并并统一标注来源前缀("static-sig:" / "content-inject:");
// 另返回静态签名的逐条件 trace(供 honeypotFactDetail 写排查摘要)。
func mergeHoneypotSignals(v honeydetect.ServiceView) (score float64, evidence []string, trace []honeydetect.SigTrace) {
	score, evidence, trace = honeydetect.EvaluateWithTrace(v)
	for i := range evidence {
		evidence[i] = "static-sig:" + evidence[i]
	}
	content := v.Title
	if v.Body != "" {
		content += "\n" + v.Body
	}
	if iscore, iev := honeydetect.InjectEvaluate(content); iscore >= honeydetect.InjectSuspectThreshold {
		for _, e := range iev {
			evidence = append(evidence, "content-inject:"+e)
		}
		if iscore > score {
			score = iscore
		}
	}
	return score, evidence, trace
}

// honeypotTraceNearMissCap 是 fact detail 里"近似未命中"签名摘要的条数上限
// (trace 全量不落库,detail 只留排查误报最有用的近似项,防 detail 膨胀)。
const honeypotTraceNearMissCap = 5

// honeypotFactDetail 组装 fact 的 detail(纯函数,便于单测):
//   - 证据按级别分组列出(签名级 static-sig / 内容级 content-inject);
//   - 开头给一句综合判断(双级命中=高置信,单级=降级观察);
//   - 结尾附签名 trace 摘要:命中签名名 + 近似未命中签名(至少一个条件已命中)
//     的首个失败条件,供 planner/人排查误报;处置纪律与 plannerHoneypotRules 一致。
func honeypotFactDetail(evidence []string, trace []honeydetect.SigTrace) string {
	var sigLevel, contentLevel []string
	for _, e := range evidence {
		switch {
		case strings.HasPrefix(e, "static-sig:"):
			sigLevel = append(sigLevel, strings.TrimPrefix(e, "static-sig:"))
		case strings.HasPrefix(e, "content-inject:"):
			contentLevel = append(contentLevel, strings.TrimPrefix(e, "content-inject:"))
		}
	}
	// 综合判断:证据级别组合 → 置信结论。
	var judgment string
	switch {
	case len(sigLevel) > 0 && len(contentLevel) > 0:
		judgment = "签名级+内容级双级命中,高置信,比照双信号处置"
	case len(sigLevel) > 0:
		judgment = "仅签名级命中(单级),降级观察"
	case len(contentLevel) > 0:
		judgment = "仅内容级命中(单级),降级观察"
	default:
		judgment = "无分级证据"
	}
	var b strings.Builder
	b.WriteString("综合判断: " + judgment + "。")
	if len(sigLevel) > 0 {
		b.WriteString("签名级证据(static-sig): " + strings.Join(sigLevel, "; ") + "。")
	}
	if len(contentLevel) > 0 {
		b.WriteString("内容级证据(content-inject): " + strings.Join(contentLevel, "; ") + "。")
	}
	// 签名 trace 摘要:命中签名名 + 近似未命中的首个失败条件(至少一个条件
	// 已命中的才算近似——零命中签名对整个库都是噪声,不进摘要)。
	var hitNames, nearMiss []string
	for _, tr := range trace {
		if tr.Matched {
			hitNames = append(hitNames, tr.Name)
			continue
		}
		if tr.MatchedConds() > 0 && len(nearMiss) < honeypotTraceNearMissCap {
			nearMiss = append(nearMiss, fmt.Sprintf("%s(首失败条件 %s)", tr.Name, tr.FirstFailed()))
		}
	}
	if len(hitNames) > 0 || len(nearMiss) > 0 {
		b.WriteString("签名 trace:")
		if len(hitNames) > 0 {
			b.WriteString(" 命中 [" + strings.Join(hitNames, ", ") + "];")
		}
		if len(nearMiss) > 0 {
			b.WriteString(" 近似未命中 " + strings.Join(nearMiss, "; ") + ";")
		}
	}
	b.WriteString("处置:单信号(单证据级)只降级交互(被动/只读),不投递/不爆破/不利用;双信号或证据双级命中才封锁方向。")
	return b.String()
}

// urlPort 从 URL 取端口(缺省按 scheme),取不到返回 0。
func urlPort(raw string) int {
	u, err := url.Parse(raw)
	if err != nil {
		return 0
	}
	if p := u.Port(); p != "" {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err == nil {
			return n
		}
		return 0
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return 80
	case "https":
		return 443
	}
	return 0
}
