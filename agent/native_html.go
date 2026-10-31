package agent

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"golang.org/x/net/html"
)

func nativeHTMLTool() actool.CoreTool {
	return actool.Build(actool.Spec{Name: "extract_local_html", Description: "用内置解析器读取本任务工作目录中已保存的 HTML，返回标题、链接、脚本地址、表单 action/method 及输入字段名/类型。不需要 Python，不联网，不执行脚本，不返回表单 value。", Schema: obj(map[string]any{"path": str("已有 HTML 文件路径；相对当前工作目录，或本任务目录内的绝对路径")}, "path"), ReadOnly: func(json.RawMessage) bool { return true }, Concurrent: func(json.RawMessage) bool { return true }, Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
		return permission.Allowed()
	}, Run: func(ctx context.Context, raw json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
		var in struct {
			Path string `json:"path"`
		}
		if json.Unmarshal(raw, &in) != nil || in.Path == "" || tc == nil {
			return actool.Errorf("需要任务内已有 HTML 的 path"), nil
		}
		root := learningRoot(tc.WorkingDir, RunInfoFrom(ctx).TaskID)
		if root == "" {
			return actool.Errorf("仅支持当前任务工作目录内的文件"), nil
		}
		path := in.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(tc.WorkingDir, path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return actool.Errorf("文件不在当前任务目录内"), nil
		}
		confined, err := os.OpenRoot(root)
		if err != nil {
			return actool.Errorf("任务目录不可读"), nil
		}
		defer confined.Close()
		file, err := confined.Open(rel)
		if err != nil {
			return actool.Errorf("文件不存在、不可读或链接指向任务目录外"), nil
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
			return actool.Errorf("仅支持不超过 4 MiB 的普通 HTML 文件"), nil
		}
		out, err := extractHTML(ctx, io.LimitReader(file, 4<<20))
		if err != nil {
			return actool.Errorf("HTML 解析未完成"), err
		}
		encoded, _ := json.Marshal(out)
		for len(encoded) > 65536 {
			out.Truncated = true
			out.Links = out.Links[:len(out.Links)/2]
			out.Scripts = out.Scripts[:len(out.Scripts)/2]
			out.Forms = out.Forms[:len(out.Forms)/2]
			encoded, _ = json.Marshal(out)
		}
		return actool.Text(string(encoded)), nil
	}})
}

type htmlInput struct {
	Name string `json:"name"`
	Type string `json:"type"`
}
type htmlForm struct {
	Action string      `json:"action"`
	Method string      `json:"method"`
	Inputs []htmlInput `json:"inputs"`
}
type htmlSummary struct {
	Base      string     `json:"base,omitempty"`
	Title     string     `json:"title"`
	Links     []string   `json:"links"`
	Scripts   []string   `json:"scripts"`
	Forms     []htmlForm `json:"forms"`
	Truncated bool       `json:"truncated"`
}

func extractHTML(ctx context.Context, reader io.Reader) (htmlSummary, error) {
	out := htmlSummary{Links: []string{}, Scripts: []string{}, Forms: []htmlForm{}}
	tokenizer := html.NewTokenizer(reader)
	title := false
	form := -1
	budget := 60000
	clip := func(s string) string {
		if len(s) > 512 {
			out.Truncated = true
			return strings.ToValidUTF8(s[:512], "")
		}
		return s
	}
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		kind := tokenizer.Next()
		if kind == html.ErrorToken {
			if tokenizer.Err() == io.EOF {
				return out, nil
			}
			return out, tokenizer.Err()
		}
		tok := tokenizer.Token()
		if kind == html.StartTagToken || kind == html.SelfClosingTagToken {
			attrs := map[string]string{}
			for _, a := range tok.Attr {
				attrs[a.Key] = a.Val
			}
			title = tok.Data == "title"
			add := func(dst *[]string, s string) {
				if s == "" {
					return
				}
				s = clip(s)
				if len(*dst) >= 100 || budget < len(s) {
					out.Truncated = true
					return
				}
				*dst = append(*dst, s)
				budget -= len(s)
			}
			switch tok.Data {
			case "base":
				if out.Base == "" {
					out.Base = clip(attrs["href"])
				}
			case "a":
				add(&out.Links, attrs["href"])
			case "script":
				add(&out.Scripts, attrs["src"])
			case "form":
				if len(out.Forms) < 50 {
					method := strings.ToUpper(attrs["method"])
					if method == "" {
						method = "GET"
					}
					out.Forms = append(out.Forms, htmlForm{clip(attrs["action"]), clip(method), []htmlInput{}})
					form = len(out.Forms) - 1
				} else {
					out.Truncated = true
					form = -1
				}
			case "input", "select", "textarea", "button":
				if form >= 0 {
					f := &out.Forms[form]
					if len(f.Inputs) < 100 && budget > 1024 {
						f.Inputs = append(f.Inputs, htmlInput{clip(attrs["name"]), clip(attrs["type"])})
						budget -= 1024
					} else {
						out.Truncated = true
					}
				}
			}
		} else if kind == html.EndTagToken {
			if tok.Data == "title" {
				title = false
			}
			if tok.Data == "form" {
				form = -1
			}
		} else if kind == html.TextToken && title {
			out.Title = clip(strings.TrimSpace(out.Title + tok.Data))
		}
	}
}
