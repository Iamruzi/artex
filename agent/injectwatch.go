package agent

// 反 AI 蜜罐「Agent 注入内容检测」在 WebFetch 结果路径的挂点
// (HONEYPOT-DETECTION-DESIGN.md 二-B 节「识别信号」行)。
//
// worker 的 WebFetch 结果不一定会经 insert_assets 落库(读了但没登记资产),
// 那条路径上的注入诱导内容需要一个独立观察点:engine 的 steerHooks.PostToolUse
// 把每步 tool_result 喂进来(与停滞检测同观察点),命中疑似即回调写 hint 节点
// 挂探索图提示 planner(参照停滞检测写 hint 的方式)。
//
// 频率控制:同一 host 一条意图(=检测器生命周期)内只提示一次,防止对同一站点
// 的连续抓取刷屏 hint 通道。

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/Autumn-27/artex/honeydetect"
)

// injectWatchMaxContent 是喂给注入检测的正文上限(字节):检测是子串/正则扫描,
// 超大响应截断即可,诱导话术一般出现在页面头部说明区。
const injectWatchMaxContent = 64 << 10

// InjectEvent 是一次注入内容命中事件。
type InjectEvent struct {
	URL      string   // 被抓取的 URL(取不到则为空)
	Host     string   // 目标 host(频率控制的键)
	Score    float64  // 注入内容评分(>= honeydetect.InjectSuspectThreshold)
	Evidence []string // 命中信号明细
}

// InjectWatcher 是 worker 循环内的 WebFetch 结果注入内容观察器:每条意图一个,
// 非并发安全(harness 的 hook 串行调用,与 StuckDetector 的既有假设一致)。
type InjectWatcher struct {
	seen map[string]bool // 已提示过的 host(同一 host 一轮只提示一次)
}

func NewInjectWatcher() *InjectWatcher {
	return &InjectWatcher{seen: map[string]bool{}}
}

// Observe 观察一步 tool_result:仅处理 WebFetch 的成功结果;内容评分达到疑似
// 阈值且本 host 尚未提示过时,登记并返回事件,否则返回 nil。best-effort:输入
// 解析失败(拿不到 URL)时按空 host 照常检测。
func (w *InjectWatcher) Observe(tool string, input, result []byte, isErr bool) *InjectEvent {
	if tool != "WebFetch" || isErr || len(result) == 0 {
		return nil
	}
	content := result
	if len(content) > injectWatchMaxContent {
		content = content[:injectWatchMaxContent]
	}
	score, evidence := honeydetect.InjectEvaluate(string(content))
	if score < honeydetect.InjectSuspectThreshold {
		return nil
	}
	rawURL := webFetchInputURL(input)
	host := ""
	if u, err := url.Parse(rawURL); err == nil {
		host = strings.ToLower(u.Host)
	}
	// 只在命中时登记 host:先抓到的干净页面不该挡住同 host 后续恶意页的提示。
	if w.seen[host] {
		return nil
	}
	w.seen[host] = true
	return &InjectEvent{URL: rawURL, Host: host, Score: score, Evidence: evidence}
}

// webFetchInputURL 从 WebFetch 工具输入取 url 字段(取不到返回空串)。
func webFetchInputURL(input []byte) string {
	var a struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(input, &a) != nil {
		return ""
	}
	return strings.TrimSpace(a.URL)
}
