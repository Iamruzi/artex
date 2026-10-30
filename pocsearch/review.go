package pocsearch

import (
	"regexp"
	"strings"
)

// SourceReview is bounded text triage, not a security verdict or execution gate.
// Absence of a literal pattern never certifies a PoC as safe or applicable.
type SourceReview struct {
	Status         string   `json:"status"`
	CVEMention     string   `json:"cve_mention"`
	Observations   []string `json:"observations"`
	RequiredChecks []string `json:"required_checks"`
}

var sourceCVEs = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,8}\b`)

func ReviewSource(text, cve string) SourceReview {
	out := SourceReview{Status: "needs_review", CVEMention: "not_mentioned", Observations: []string{}, RequiredChecks: []string{"核对实际产品、版本、补丁和功能配置", "确认身份、权限和请求前置对象", "检查依赖、参数、外连与写入副作用", "验证结果必须引用当前目标的实际证据"}}
	// Source retrieval is capped at 48KiB; keep this helper bounded even when
	// called independently. Examine all CVE mentions within that budget.
	if len(text) > 48<<10 {
		text = text[:48<<10]
	}
	matches := sourceCVEs.FindAllString(text, -1)
	if cve == "" {
		out.CVEMention = "not_evaluated"
		matches = nil
	}
	for _, match := range matches {
		if strings.EqualFold(match, cve) {
			out.CVEMention = "mentioned"
			break
		}
		out.CVEMention = "other_cve_only"
	}
	lower := strings.ToLower(text)
	patterns := []struct {
		label  string
		tokens []string
	}{
		{"包含下载/动态执行相关字样，需核对来源与调用链", []string{"curl ", "wget ", "downloadstring(", "invoke-expression", "eval(", "exec("}},
		{"包含进程或 shell 调用相关字样，需核对实际命令与作用域", []string{"subprocess.", "os.system(", "shell=true", "/bin/sh", "powershell"}},
		{"包含凭据/密钥路径字样，需核对是否会访问本机敏感信息", []string{".ssh/", "id_rsa", "aws_secret_access_key", ".env", "api_key"}},
		{"包含删除/持久化相关字样，需检查副作用与清理", []string{"rm -rf", "rmtree(", "crontab", "authorized_keys", "schtasks"}},
		{"包含编码转换字样，需检查解码后内容", []string{"b64decode(", "frombase64string(", "base64 -d"}},
	}
	for _, pattern := range patterns {
		for _, token := range pattern.tokens {
			if strings.Contains(lower, token) {
				out.Observations = append(out.Observations, pattern.label)
				break
			}
		}
	}
	return out
}
