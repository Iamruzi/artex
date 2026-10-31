// Package runtimeinfo provides bounded, verified host capabilities; Python is optional.
package runtimeinfo

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Python struct {
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
	Version   string `json:"version,omitempty"`
}
type Capabilities struct {
	OS         string `json:"os"`
	Python     Python `json:"python"`
	NativeHTML bool   `json:"native_html"`
}

var once sync.Once
var snapshot Capabilities
var pythonVersion = regexp.MustCompile(`^Python 3\.[0-9]+(?:\.[0-9]+)?`)

func detectPython(override string, lookup func(string) (string, error), probe func(string) (string, error)) Python {
	candidates := []string{}
	if override != "" {
		candidates = append(candidates, override)
	} else {
		for _, name := range []string{"python3", "python"} {
			if path, err := lookup(name); err == nil {
				candidates = append(candidates, path)
			}
		}
	}
	seen := map[string]bool{}
	for _, path := range candidates {
		if seen[path] || strings.Contains(strings.ToLower(path), "windowsapps") {
			continue
		}
		seen[path] = true
		version, err := probe(path)
		if err == nil {
			if clean := pythonVersion.FindString(strings.TrimSpace(version)); clean != "" {
				return Python{true, path, clean}
			}
		}
	}
	return Python{}
}

func Snapshot() Capabilities {
	once.Do(func() {
		snapshot = Capabilities{OS: runtime.GOOS, NativeHTML: true}
		snapshot.Python = detectPython(os.Getenv("ARTEX_PYTHON"), exec.LookPath, func(path string) (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			raw, err := exec.CommandContext(ctx, path, "--version").Output()
			return string(raw), err
		})
	})
	return snapshot
}

func Prompt() string {
	raw, _ := json.Marshal(Snapshot())
	return "\n【已验证的本机能力】" + string(raw) + "\n优先用 extract_local_html 解析任务内已保存的 HTML，无需 Python、pip 或浏览器。仅在 python.available=true 且确有脚本需求时，使用给出的绝对路径；Windows 用 & '路径' script.py。若 unavailable，不再搜索磁盘、试猜 python/python3/py，也不自动安装；改用原生工具，无法替代的工作明确报告缺少依赖。Python 路径只代表解释器可用，不代表第三方包已安装。"
}
