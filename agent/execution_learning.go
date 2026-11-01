package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/runtimeinfo"
	actool "github.com/Autumn-27/norma/tool"
)

const learningFile = "execution-learning.json"
const learningMarker = "【执行环境与任务经验】"

var learningMu sync.Mutex
var learningURL = regexp.MustCompile(`https?://[^\s"'<>]+`)

type executionLesson struct {
	Category       string `json:"category"`
	Count          int    `json:"count"`
	RetryAfterUnix int64  `json:"retry_after_unix,omitempty"`
}
type executionLearning struct {
	Operations map[string]executionLesson `json:"operations"`
	Challenges map[string]int             `json:"challenges"`
}

func shellEnvironment(goos string) string {
	if goos == "windows" {
		return "本地 Bash 工具实际使用 Windows PowerShell，不是 Bash。HTTP 请求明确使用 curl.exe，避免 curl 的 Invoke-WebRequest 别名；不要使用 &&、||、Bash heredoc、export、head、/dev/null。用 PowerShell 原生语法；有前后依赖时检查 $LASTEXITCODE 或异常，不用分号掩盖失败。复杂引号或 JSON 先用 Write 写脚本/请求文件再执行。每次调用是独立进程，变量和 cd 不跨调用保留。"
	}
	return "本地 Bash 工具使用 bash -c；不要混用 PowerShell 语法，也不要假定额外命令已安装。每次调用的变量和 cd 不跨进程保留。"
}

// Only the trusted host work directory and task attribution select the ledger.
// Different roles and intents in the same task share it; other tasks never do.
func learningRoot(dir string, taskID int64) string {
	if dir == "" || taskID <= 0 {
		return ""
	}
	for i := 0; i < 2; i++ {
		if filepath.Base(dir) == strconv.FormatInt(taskID, 10) && filepath.Base(filepath.Dir(dir)) == "tasks" {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	return ""
}

func loadLearning(root string) executionLearning {
	s := executionLearning{Operations: map[string]executionLesson{}, Challenges: map[string]int{}}
	if root == "" {
		return s
	}
	path := filepath.Join(root, learningFile)
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 65536 {
		return s
	}
	f, err := os.Open(path)
	if err != nil {
		return s
	}
	defer f.Close()
	var candidate executionLearning
	if json.NewDecoder(io.LimitReader(f, 65537)).Decode(&candidate) != nil {
		return s
	}
	for key, item := range candidate.Operations {
		if len(s.Operations) >= 64 {
			break
		}
		if len(key) == 64 && lessonAdvice(item.Category) != "" && item.Count > 0 {
			item.Count = min(item.Count, 2)
			s.Operations[key] = item
		}
	}
	for key, count := range candidate.Challenges {
		if len(s.Challenges) >= 32 {
			break
		}
		if len(key) == 64 && count > 0 {
			s.Challenges[key] = min(count, 2)
		}
	}
	return s
}

func saveLearning(root string, s executionLearning) {
	path := filepath.Join(root, learningFile)
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return
	}
	f, err := os.CreateTemp(root, ".learning-*.tmp")
	if err != nil {
		return
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_ = f.Chmod(0600)
	err = json.NewEncoder(f).Encode(s)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		_ = os.Rename(tmp, path)
	}
}

func learningHash(value string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(value))) }

func operationKey(tool string, raw json.RawMessage) string {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return learningHash(tool + string(raw))
	}
	canonical, _ := json.Marshal(value)
	return learningHash(tool + "\x00" + string(canonical))
}

// Only explicit HTTP tools/commands participate in host challenge budgets.
func requestHost(tool string, raw json.RawMessage) string {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return ""
	}
	var target string
	switch tool {
	case "WebFetch":
		_ = json.Unmarshal(fields["url"], &target)
	case "Bash":
		var command string
		_ = json.Unmarshal(fields["command"], &command)
		lower := strings.ToLower(command)
		if !strings.Contains(lower, "curl") && !strings.Contains(lower, "invoke-webrequest") && !strings.Contains(lower, "invoke-restmethod") {
			return ""
		}
		target = learningURL.FindString(command)
	default:
		return ""
	}
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return learningHash(strings.ToLower(u.Hostname()))
}

func lessonAdvice(category string) string {
	switch category {
	case "shell_syntax":
		return "本地语法错误：修正实际 Shell 的语法并验证一个最小命令；不要重复原命令，也不能据此判断目标无漏洞。"
	case "command_missing":
		return "本地缺少命令：先核对已安装工具，选现有等价工具；不要反复调用缺失命令或自动下载安装。"
	case "powershell_alias":
		return "PowerShell 的 curl 别名发生参数错误：使用 curl.exe 与 PowerShell 正确引号；复杂命令先写脚本。"
	case "http_challenge":
		return "已观察到明确的 Cloudflare/Turnstile/验证码挑战：停止使用 Bash、curl 或 WebFetch 换 UA、参数和请求方式重试。下一步加载 browser-challenge-testing 技能并使用 browser_navigate 打开目标，复用该任务的可见持久浏览器会话；先等待普通 JS challenge 完成，再读取页面。只有浏览器实际显示必须人工点选的交互挑战时才等待用户，不能把挑战页当成目标正文。"
	case "tool_failure":
		return "该相同调用已失败：先检查执行记录和前置条件，给出实际改变及预期信号再行动，不原样重试。"
	case "tool_arguments":
		return "工具参数校验失败：必须修正实际 JSON。已有 HTML 时，改用 insert_assets 的 html_path + base_url 模式，由程序按导航/表单声明生成 url/method；不再手写整批缺失 method 的 assets。也可只提交一条带正确 method 的已确认接口；未确认的方法不要编造。"
	}
	return ""
}

func classifyExecution(tool, text string, failed bool) string {
	lower := strings.ToLower(text)
	if tool == "WebFetch" || tool == "Bash" {
		if strings.Contains(lower, "cf-mitigated: challenge") || strings.Contains(lower, "cf-chl-") || (strings.Contains(lower, "cloudflare") && (strings.Contains(lower, "captcha") || strings.Contains(lower, "challenge"))) {
			return "http_challenge"
		}
	}
	if !failed {
		return ""
	}
	if tool == "insert_assets" && strings.Contains(lower, "method is required") {
		return "tool_arguments"
	}
	if tool == "Bash" {
		if strings.Contains(lower, "invoke-webrequest") && (strings.Contains(lower, "parameterbinding") || strings.Contains(lower, "categoryinfo")) {
			return "powershell_alias"
		}
		for _, marker := range []string{"parsererror", "unexpectedtoken", "not a valid statement separator", "不是此版本中的有效语句分隔符", "syntax error near unexpected token"} {
			if strings.Contains(lower, marker) {
				return "shell_syntax"
			}
		}
		if strings.Contains(lower, "commandnotfoundexception") || strings.Contains(lower, "command not found") {
			return "command_missing"
		}
	}
	return "tool_failure"
}

func learnsExecution(tool string) bool {
	return tool == "Bash" || tool == "WebFetch" || tool == "insert_assets" || tool == "extract_local_html"
}

func checkExecutionLearning(ctx context.Context, tool string, raw json.RawMessage, tc *actool.ToolContext) string {
	if tc == nil || ctx.Err() != nil || !learnsExecution(tool) {
		return ""
	}
	root := learningRoot(tc.WorkingDir, RunInfoFrom(ctx).TaskID)
	if root == "" {
		return ""
	}
	learningMu.Lock()
	defer learningMu.Unlock()
	s := loadLearning(root)
	if host := requestHost(tool, raw); host != "" && s.Challenges[host] >= 2 {
		return "execution_repeat_blocked: " + lessonAdvice("http_challenge") + " 本次 HTTP 请求未发送；浏览器路径仍可继续，不需要先重置挑战记录。"
	}
	if prior := s.Operations[operationKey(tool, raw)]; prior.Count >= 2 && (prior.Category != "tool_failure" || prior.RetryAfterUnix > time.Now().Unix()) {
		return "execution_repeat_blocked: " + lessonAdvice(prior.Category) + " 此调用已失败两次，本次未执行。"
	}
	return ""
}

func observeExecutionLearning(ctx context.Context, tool string, raw json.RawMessage, tc *actool.ToolContext, text string, failed bool) string {
	if tc == nil || ctx.Err() != nil || !learnsExecution(tool) {
		return ""
	}
	root := learningRoot(tc.WorkingDir, RunInfoFrom(ctx).TaskID)
	if root == "" {
		return ""
	}
	category := classifyExecution(tool, text, failed)
	if category == "http_challenge" && requestHost(tool, raw) == "" {
		category = ""
	}
	learningMu.Lock()
	defer learningMu.Unlock()
	s := loadLearning(root)
	key := operationKey(tool, raw)
	if category == "" {
		if !failed {
			_, changed := s.Operations[key]
			delete(s.Operations, key)
			if host := requestHost(tool, raw); host != "" {
				changed = changed || s.Challenges[host] > 0
				delete(s.Challenges, host)
			}
			if changed {
				saveLearning(root, s)
			}
		}
		return ""
	}
	if len(s.Operations) < 64 || s.Operations[key].Count > 0 {
		prior := s.Operations[key]
		if prior.Category == "tool_failure" && prior.RetryAfterUnix <= time.Now().Unix() {
			prior.Count = 0
		}
		lesson := executionLesson{Category: category, Count: min(prior.Count+1, 2)}
		if category == "tool_failure" {
			lesson.RetryAfterUnix = time.Now().Add(2 * time.Minute).Unix()
		}
		s.Operations[key] = lesson
	}
	if category == "http_challenge" {
		if host := requestHost(tool, raw); host != "" && (len(s.Challenges) < 32 || s.Challenges[host] > 0) {
			s.Challenges[host] = min(s.Challenges[host]+1, 2)
		}
	}
	saveLearning(root, s)
	return "\n【已保存任务经验】" + lessonAdvice(category)
}

func executionLearningPrompt(dir string) string {
	message := "\n\n" + learningMarker + "\n" + shellEnvironment(runtime.GOOS) + runtimeinfo.Prompt() + " 以上仅适用于本地工具，不代表远端环境。\n调用失败后总结原因、实际改变和下一步预期信号；优先复用任务文件和已采集流量。同一请求若仅换 UA/措辞而条件未改变，不视为新路径。规划器应尽快派发可执行的小意图，由 Worker 验证，不要自己长时间反复下载或调试命令。遇到 Cloudflare/Turnstile 时必须切换到 browser-challenge-testing 的可见持久浏览器会话，不再派发 curl/WebFetch 重试；未验证保持未验证。"
	// The trusted directory is selected by the caller; no target output becomes instructions.
	root := dir
	if strings.HasPrefix(filepath.Base(root), "i") {
		root = filepath.Dir(root)
	}
	if filepath.Base(filepath.Dir(root)) != "tasks" {
		return message
	}
	learningMu.Lock()
	defer learningMu.Unlock()
	s := loadLearning(root)
	counts := map[string]int{}
	for _, item := range s.Operations {
		counts[item.Category] += item.Count
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		message += fmt.Sprintf("\n已记录 %s（%d 次）：%s", key, counts[key], lessonAdvice(key))
	}
	return message
}
