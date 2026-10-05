// Package honeydetect 是批 6 L1 蜜罐静态签名识别层(设计文档
// HONEYPOT-DETECTION-DESIGN.md 二·L1):对 service 资产已知的静态特征
// (banner/HTTP 标题/正文/TLS 证书)做子串签名匹配,产出 0-1 的蜜罐置信度
// 评分与命中证据。签名库默认内嵌在本包(go:embed signatures.json);server 启动
// 时若 dataDir/signatures/honeypot.json 存在则优先用之并按 mtime 热更新(便于
// 不落盘发版地运营签名库),不存在则用内嵌库,永不空载。
// 签名只收录有公开来源的(来源写在每条签名的 source 字段),严禁编造。
package honeydetect

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// embeddedSignatures 是内嵌签名库(与 signatures.json 同文件),作为签名文件
// 缺失时的兜底——平台任何部署形态下签名识别都可用,不依赖 dataDir 种子拷贝。
//
//go:embed signatures.json
var embeddedSignatures []byte

// ServiceView 是一次签名评估的输入视图:调用方填手头已有的字段,没有就留空。
type ServiceView struct {
	Port        int    // 服务端口(0=未知)
	Banner      string // 协议 banner / HTTP Server 头等
	Title       string // HTTP <title>
	Body        string // HTTP 正文(或其片段)
	CertSubject string // TLS 证书 subject
	CertIssuer  string // TLS 证书 issuer
}

// MatchRule 是一条签名的匹配条件:列出的条件【全部】命中才算命中;
// 一个条件都没有的签名永不命中(且加载校验直接拒收)。
//
// 条件操作符(全部大小写不敏感):
//   - *_substr:子串匹配;值为 "*" 表示【exists】——该字段存在(非空)即命中;
//   - *_not_substr:含该子串即不命中;值为 "*" 表示该字段存在即不命中。
//     exists 与 _not 组合可表达结构性条件,如
//     {"banner_substr":"*","banner_not_substr":"SSH-2.0-"} = "有 banner 但不是标准 SSH 版本串"。
type MatchRule struct {
	Port                 *int   `json:"port,omitempty"`
	BannerSubstr         string `json:"banner_substr,omitempty"`
	BannerNotSubstr      string `json:"banner_not_substr,omitempty"`
	HTTPTitleSubstr      string `json:"http_title_substr,omitempty"`
	HTTPTitleNotSubstr   string `json:"http_title_not_substr,omitempty"`
	HTTPBodySubstr       string `json:"http_body_substr,omitempty"`
	HTTPBodyNotSubstr    string `json:"http_body_not_substr,omitempty"`
	CertSubjectSubstr    string `json:"cert_subject_substr,omitempty"`
	CertSubjectNotSubstr string `json:"cert_subject_not_substr,omitempty"`
	CertIssuerSubstr     string `json:"cert_issuer_substr,omitempty"`
	CertIssuerNotSubstr  string `json:"cert_issuer_not_substr,omitempty"`
}

// Signature 是一条蜜罐静态签名。
type Signature struct {
	Name       string    `json:"name"`       // 签名标识(snake_case)
	Product    string    `json:"product"`    // 蜜罐产品名(Cowrie/OpenCanary/...)
	Confidence float64   `json:"confidence"` // 0-1,命中时贡献的评分
	Source     string    `json:"source"`     // 来源(必填,签名只收录有出处的)
	Match      MatchRule `json:"match"`
}

func (m MatchRule) empty() bool {
	return m.Port == nil && m.BannerSubstr == "" && m.BannerNotSubstr == "" &&
		m.HTTPTitleSubstr == "" && m.HTTPTitleNotSubstr == "" &&
		m.HTTPBodySubstr == "" && m.HTTPBodyNotSubstr == "" &&
		m.CertSubjectSubstr == "" && m.CertSubjectNotSubstr == "" &&
		m.CertIssuerSubstr == "" && m.CertIssuerNotSubstr == ""
}

// ruleCond 是一条已声明、可评估的匹配条件:field 是 trace/校验用的字段名,
// check 对视图求值(子串匹配大小写不敏感,见 condSubstr)。
type ruleCond struct {
	field string
	check func(ServiceView) bool
}

// conds 按固定顺序列出规则中【声明了的】条件(未声明的不参与判定、不进 trace)。
func (m MatchRule) conds() []ruleCond {
	var out []ruleCond
	if m.Port != nil {
		out = append(out, ruleCond{"port", func(v ServiceView) bool { return *m.Port == v.Port }})
	}
	// 正向子串条件。
	addSub := func(field, needle string, get func(ServiceView) string) {
		if needle != "" {
			out = append(out, ruleCond{field, func(v ServiceView) bool { return condSubstr(get(v), needle) }})
		}
	}
	// 反向条件:含(或存在)即不命中。
	addNot := func(field, needle string, get func(ServiceView) string) {
		if needle != "" {
			out = append(out, ruleCond{field, func(v ServiceView) bool { return !condSubstr(get(v), needle) }})
		}
	}
	banner := func(v ServiceView) string { return v.Banner }
	title := func(v ServiceView) string { return v.Title }
	body := func(v ServiceView) string { return v.Body }
	certS := func(v ServiceView) string { return v.CertSubject }
	certI := func(v ServiceView) string { return v.CertIssuer }
	addSub("banner_substr", m.BannerSubstr, banner)
	addNot("banner_not_substr", m.BannerNotSubstr, banner)
	addSub("http_title_substr", m.HTTPTitleSubstr, title)
	addNot("http_title_not_substr", m.HTTPTitleNotSubstr, title)
	addSub("http_body_substr", m.HTTPBodySubstr, body)
	addNot("http_body_not_substr", m.HTTPBodyNotSubstr, body)
	addSub("cert_subject_substr", m.CertSubjectSubstr, certS)
	addNot("cert_subject_not_substr", m.CertSubjectNotSubstr, certS)
	addSub("cert_issuer_substr", m.CertIssuerSubstr, certI)
	addNot("cert_issuer_not_substr", m.CertIssuerNotSubstr, certI)
	return out
}

// condSubstr 评估一条 *_substr 条件:needle 为 "*" 时是【exists】语义(字段
// 非空即命中),否则做大小写不敏感子串匹配。
func condSubstr(value, needle string) bool {
	if needle == "*" {
		return value != ""
	}
	return containsFold(value, needle)
}

// matchTrace 逐条件评估规则并返回逐条件结果(短路:首个失败条件之后已声明的
// 条件记 not_evaluated)。无条件规则永不命中。
func (m MatchRule) matchTrace(v ServiceView) (matched bool, conds []CondTrace) {
	cs := m.conds()
	if len(cs) == 0 {
		return false, nil
	}
	failed := false
	for _, c := range cs {
		switch {
		case failed:
			conds = append(conds, CondTrace{Field: c.field, Result: CondNotEvaluated})
		case c.check(v):
			conds = append(conds, CondTrace{Field: c.field, Result: CondMatched})
		default:
			conds = append(conds, CondTrace{Field: c.field, Result: CondNotMatched})
			failed = true
		}
	}
	return !failed, conds
}

func containsFold(haystack, needle string) bool {
	return haystack != "" && strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

// CondResult 是逐条件判定结果。
type CondResult string

const (
	CondMatched      CondResult = "matched"       // 条件命中
	CondNotMatched   CondResult = "not_matched"   // 条件声明了但视图不满足
	CondNotEvaluated CondResult = "not_evaluated" // 短路:前面已有条件失败,本条未评估
)

// CondTrace 是一个条件的判定记录。
type CondTrace struct {
	Field  string     `json:"field"`  // 条件字段名(如 banner_substr / banner_not_substr / port)
	Result CondResult `json:"result"` // matched / not_matched / not_evaluated
}

// SigTrace 是一条签名对某视图的逐条件判定记录(trace 不落库,供调用方/调试用)。
type SigTrace struct {
	Name    string      `json:"name"`
	Matched bool        `json:"matched"`
	Conds   []CondTrace `json:"conds"`
}

// FirstFailed 返回首个失败条件名;命中(无失败)返回空串。
func (t SigTrace) FirstFailed() string {
	for _, c := range t.Conds {
		if c.Result == CondNotMatched {
			return c.Field
		}
	}
	return ""
}

// MatchedConds 返回已命中条件数(调用方据此筛"近似命中"签名,排查误报用)。
func (t SigTrace) MatchedConds() int {
	n := 0
	for _, c := range t.Conds {
		if c.Result == CondMatched {
			n++
		}
	}
	return n
}

// Engine 是签名引擎:持有签名文件路径,按 mtime 缓存重载(热更新)。
type Engine struct {
	mu      sync.RWMutex
	path    string
	modTime time.Time
	sigs    []Signature
}

// NewEngine 以指定签名文件路径建引擎。路径缺失/损坏不报错,Evaluate 返回 0 分。
func NewEngine(path string) *Engine { return &Engine{path: path} }

// signatures 返回当前生效签名:签名文件存在时按 mtime 热更新;文件缺失/读不到时
// 回落内嵌签名库(只解析一次,后续命中缓存);文件【解析或校验失败】时整体回退到
// 上一份好签名(没有好签名就用内嵌库),并记录失败原因——坏文件只报一次,文件再
// 变动(mtime 变化)才重试加载。
func (e *Engine) signatures() []Signature {
	fi, err := os.Stat(e.path)
	if err != nil {
		e.mu.Lock()
		if e.sigs == nil {
			e.sigs = loadEmbedded()
		}
		e.modTime = time.Time{}
		sigs := e.sigs
		e.mu.Unlock()
		return sigs
	}
	e.mu.RLock()
	if !e.needsReload(fi.ModTime()) {
		sigs := e.sigs
		e.mu.RUnlock()
		return sigs
	}
	e.mu.RUnlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	sigs, err := parseSignaturesStrict(mustRead(e.path))
	if err != nil {
		// 整体回退:保留上一份好签名;首次加载就没有好签名 → 内嵌库兜底。
		fallback := "上一份好签名"
		if e.sigs == nil {
			e.sigs = loadEmbedded()
			fallback = "内嵌签名库"
		}
		log.Printf("[honeydetect] 签名库 %s 加载失败,回退到%s: %v", e.path, fallback, err)
		e.modTime = fi.ModTime()
		return e.sigs
	}
	e.sigs, e.modTime = sigs, fi.ModTime()
	return e.sigs
}

func mustRead(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}

// loadEmbedded 解析内嵌签名库(严格校验;内嵌库由 TestBundledSignaturesLoad
// 保证合法,此处失败属构建事故,返回 nil 即空载)。
func loadEmbedded() []Signature {
	sigs, err := parseSignaturesStrict(embeddedSignatures)
	if err != nil {
		log.Printf("[honeydetect] 内嵌签名库校验失败(构建事故): %v", err)
		return nil
	}
	return sigs
}

// parseSignaturesStrict 严格解析并校验签名库:
//   - 未知字段拒绝(json.DisallowUnknownFields,字段名笔误直接报出来而不是静默忽略);
//   - 无条件签名拒绝(match 一个条件都没有的签名);
//   - 非法值拒绝(name/source 为空、confidence 不在 (0,1]、port 越界、同字段正负
//     条件同值矛盾)。
//
// 任一失败返回 error,由调用方整体回退(见 Engine.signatures)。
func parseSignaturesStrict(data []byte) ([]Signature, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("签名文件为空")
	}
	var file struct {
		Comment    string      `json:"_comment"`
		Signatures []Signature `json:"signatures"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("签名 JSON 解析失败: %w", err)
	}
	for i, s := range file.Signatures {
		if err := validateSignature(s); err != nil {
			return nil, fmt.Errorf("签名 #%d(%s): %w", i, s.Name, err)
		}
	}
	return file.Signatures, nil
}

// validateSignature 校验单条签名(见 parseSignaturesStrict 的校验清单)。
func validateSignature(s Signature) error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("name 为空")
	}
	if strings.TrimSpace(s.Source) == "" {
		return fmt.Errorf("source 为空(签名只收录有出处的,来源必填)")
	}
	if s.Confidence <= 0 || s.Confidence > 1 {
		return fmt.Errorf("confidence %.2f 非法,须在 (0,1] 区间", s.Confidence)
	}
	m := s.Match
	if m.Port != nil && (*m.Port < 1 || *m.Port > 65535) {
		return fmt.Errorf("port %d 非法,须在 1-65535", *m.Port)
	}
	if m.empty() {
		return fmt.Errorf("match 没有任何匹配条件(无条件签名永不命中,属配置错误)")
	}
	// 同字段正负条件同值 = 永假矛盾(含即不命中与含即命中同值,签名永不命中)。
	for _, pair := range []struct{ field, pos, neg string }{
		{"banner", m.BannerSubstr, m.BannerNotSubstr},
		{"http_title", m.HTTPTitleSubstr, m.HTTPTitleNotSubstr},
		{"http_body", m.HTTPBodySubstr, m.HTTPBodyNotSubstr},
		{"cert_subject", m.CertSubjectSubstr, m.CertSubjectNotSubstr},
		{"cert_issuer", m.CertIssuerSubstr, m.CertIssuerNotSubstr},
	} {
		if pair.pos != "" && pair.pos == pair.neg {
			return fmt.Errorf("%s_substr 与 %s_not_substr 同值 %q,条件自相矛盾", pair.field, pair.field, pair.pos)
		}
	}
	return nil
}

// needsReload 报告缓存的签名是否落后于该 mtime(读锁内快速路径)。
func (e *Engine) needsReload(mt time.Time) bool { return !mt.Equal(e.modTime) }

// Evaluate 对视图 v 跑全部签名,返回命中签名中的最高置信度与命中证据
// (每条 "name(product, confidence)");无命中返回 0 分、空证据。
// 兼容原签名:内部调 EvaluateWithTrace 并丢弃 trace。
func (e *Engine) Evaluate(v ServiceView) (score float64, evidence []string) {
	score, evidence, _ = e.EvaluateWithTrace(v)
	return score, evidence
}

// EvaluateWithTrace 与 Evaluate 同判定,另返回逐签名逐条件的判定 trace
// (不落库,供调用方写排查信息/调试用)。
func (e *Engine) EvaluateWithTrace(v ServiceView) (score float64, evidence []string, trace []SigTrace) {
	for _, s := range e.signatures() {
		matched, conds := s.Match.matchTrace(v)
		trace = append(trace, SigTrace{Name: s.Name, Matched: matched, Conds: conds})
		if s.Confidence <= 0 || !matched {
			continue
		}
		evidence = append(evidence, fmt.Sprintf("%s(%s, %.2f)", s.Name, s.Product, s.Confidence))
		if s.Confidence > score {
			score = s.Confidence
		}
	}
	return score, evidence, trace
}

// defaultSignaturesPath 是默认签名文件相对路径(开发态从仓库根运行即生效);
// server 启动时用 dataDir 绝对路径经 SetSignaturesPath 覆盖。
const defaultSignaturesPath = "data/signatures/honeypot.json"

var defaultEngine = NewEngine(defaultSignaturesPath)

// SetSignaturesPath 覆盖默认引擎的签名文件路径并清空缓存(server 启动时装配)。
func SetSignaturesPath(path string) {
	defaultEngine.mu.Lock()
	defaultEngine.path = path
	defaultEngine.sigs = nil
	defaultEngine.modTime = time.Time{}
	defaultEngine.mu.Unlock()
}

// Evaluate 用默认引擎评估(见 Engine.Evaluate)。
func Evaluate(v ServiceView) (score float64, evidence []string) {
	return defaultEngine.Evaluate(v)
}

// EvaluateWithTrace 用默认引擎评估并返回逐条件 trace(见 Engine.EvaluateWithTrace)。
func EvaluateWithTrace(v ServiceView) (score float64, evidence []string, trace []SigTrace) {
	return defaultEngine.EvaluateWithTrace(v)
}
