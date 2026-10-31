package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// InsertAssetsTool exposes the same gated, task-attributed handler to local
// maintenance helpers; it does not send HTTP requests or mark endpoints tested.
func (t *ToolSet) InsertAssetsTool() actool.CoreTool { return t.insertAssets() }

func htmlImportScopeAllows(scopes []db.TaskScope, host string) bool {
	for _, scope := range scopes {
		switch scope.Kind {
		case "root_domain":
			if strings.EqualFold(host, scope.Domain) || strings.HasSuffix(strings.ToLower(host), "."+strings.ToLower(scope.Domain)) {
				return scope.Domain != ""
			}
		case "subdomain":
			if strings.EqualFold(host, scope.Domain) {
				return true
			}
		case "ip", "cidr":
			if _, network, err := net.ParseCIDR(scope.Net); err == nil && network.Contains(net.ParseIP(host)) {
				return true
			}
		}
	}
	return false
}

func (t *ToolSet) endpointsFromTaskHTML(ctx context.Context, path, source string, tc *actool.ToolContext) ([]assetInputItem, error) {
	if t.taskID <= 0 || RunInfoFrom(ctx).TaskID != t.taskID {
		return nil, errors.New("需要当前任务归属")
	}
	base, err := url.Parse(source)
	if err != nil || base.Hostname() == "" || base.User != nil || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, errors.New("base_url 必须为 HTML 的 HTTP(S) 来源 URL")
	}
	scopes, err := t.as.ListTaskScopeContext(ctx, t.taskID)
	if err != nil || !htmlImportScopeAllows(scopes, base.Hostname()) {
		return nil, errors.New("HTML 来源不在当前任务已授权域名/IP 范围内")
	}
	raw, _ := json.Marshal(map[string]string{"path": path})
	result, err := nativeHTMLTool().Call(ctx, raw, tc)
	if err != nil {
		return nil, err
	}
	if result.IsError {
		return nil, errors.New(result.Flatten())
	}
	var summary htmlSummary
	if json.Unmarshal([]byte(result.Flatten()), &summary) != nil {
		return nil, errors.New("无法解析内置 HTML 结果")
	}
	return htmlEndpointCandidates(summary, base), nil
}

func htmlEndpointCandidates(summary htmlSummary, source *url.URL) []assetInputItem {
	base := source
	if b, err := url.Parse(summary.Base); summary.Base != "" && err == nil {
		base = source.ResolveReference(b)
	}
	seen := map[string]bool{}
	out := []assetInputItem{}
	add := func(target, method string, form bool) {
		target = strings.TrimSpace(target)
		if len(target) >= 512 {
			return
		} // clipped attributes cannot establish a complete URL
		if !form && (target == "" || strings.HasPrefix(target, "#")) {
			return
		}
		ref, err := url.Parse(target)
		if err != nil {
			return
		}
		u := base.ResolveReference(ref)
		if form && target == "" {
			copy := *source
			u = &copy
		}
		if u.User != nil || u.Scheme != source.Scheme || !strings.EqualFold(u.Host, source.Host) {
			return
		}
		u.Fragment = ""
		u.RawFragment = ""
		if u.Path == "" {
			u.Path = "/"
		}
		key := method + " " + u.String()
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, assetInputItem{Type: "endpoint", URL: u.String(), Method: method})
	}
	for _, link := range summary.Links {
		add(link, "GET", false)
	}
	for _, form := range summary.Forms {
		method := strings.ToUpper(form.Method)
		if method == "" {
			method = "GET"
		}
		if method == "GET" || method == "POST" {
			add(form.Action, method, true)
		}
	}
	return out
}
