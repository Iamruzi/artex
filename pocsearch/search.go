// Package pocsearch discovers public references. It never downloads or executes
// PoCs and never claims that a repository, CVE or version candidate is exploitable.
package pocsearch

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,8}$`)
var productPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+()/-]{0,99}$`)
var numericVersion = regexp.MustCompile(`^v?\d+(?:\.\d+){0,5}$`)

type Query struct {
	Product string `json:"product"`
	Version string `json:"version"`
	CVE     string `json:"cve"`
}

func (q *Query) Validate() error {
	q.Product = strings.TrimSpace(q.Product)
	q.Version = strings.TrimSpace(q.Version)
	q.CVE = strings.ToUpper(strings.TrimSpace(q.CVE))
	if q.CVE != "" && !cvePattern.MatchString(q.CVE) {
		return errors.New("CVE 格式无效")
	}
	if q.Product == "" && q.CVE == "" {
		return errors.New("需要公开产品名或 CVE 编号，不接受目标地址")
	}
	if q.Product != "" && (!productPattern.MatchString(q.Product) || strings.Contains(q.Product, "://") || net.ParseIP(q.Product) != nil || strings.ContainsAny(q.Product, "@=\\") || strings.Contains(strings.ToLower(q.Product), "localhost")) {
		return errors.New("仅允许公开产品名，不能提交 URL、IP、凭据或命令")
	}
	if strings.Contains(q.Product, "/") {
		return errors.New("产品应使用公开名称，不接受域名或路径")
	}
	for _, part := range strings.Fields(q.Product) {
		if strings.Contains(part, ".") && !numericVersion.MatchString(part) && !strings.EqualFold(part, "Node.js") && !strings.EqualFold(part, "ASP.NET") {
			return errors.New("产品应使用公开名称，不接受域名")
		}
	}
	if len(q.Version) > 60 || strings.ContainsAny(q.Version, "\r\n\x00@=:/\\ ") {
		return errors.New("版本格式无效")
	}
	return nil
}
func ValidCVE(v string) bool { return cvePattern.MatchString(strings.ToUpper(strings.TrimSpace(v))) }
func NormalizeProduct(v string) string {
	v = strings.ToLower(v)
	v = strings.NewReplacer("-", "", "_", "", " ", "", ".", "").Replace(v)
	switch v {
	case "apachehttpd", "apachehttpserver", "apache2":
		return "httpserver"
	case "nodejs":
		return "nodejs"
	}
	return v
}

type Reference struct {
	URL    string `json:"url"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
}
type Candidate struct {
	CVE               string      `json:"cve"`
	Summary           string      `json:"summary"`
	Applicability     string      `json:"applicability"`
	VersionConditions []string    `json:"version_conditions"`
	References        []Reference `json:"references"`
}
type Repository struct {
	URL     string `json:"url"`
	Name    string `json:"name"`
	Summary string `json:"summary"`
	Updated string `json:"updated"`
	Status  string `json:"status"`
}
type CVEResult struct {
	Candidates     []Candidate `json:"candidates"`
	Source         string      `json:"source"`
	RetrievedAt    time.Time   `json:"retrieved_at"`
	Partial        bool        `json:"partial"`
	TotalResults   int         `json:"total_results"`
	FetchedWindows []int       `json:"fetched_windows"`
	Notice         string      `json:"notice"`
}
type PoCResult struct {
	CVE          string       `json:"cve"`
	Repositories []Repository `json:"repositories"`
	Source       string       `json:"source"`
	RetrievedAt  time.Time    `json:"retrieved_at"`
	Partial      bool         `json:"partial"`
	Notice       string       `json:"notice"`
}

type Client struct {
	HTTP           *http.Client
	mu             sync.Mutex
	next           map[string]time.Time
	inflight       bool
	githubWindow   time.Time
	githubRequests int
}

func NewClient() *Client {
	return &Client{HTTP: &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, next: map[string]time.Time{}}
}

func (c *Client) get(ctx context.Context, service, endpoint string, dest any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	if c.next == nil {
		c.next = map[string]time.Time{}
	}
	if c.inflight || time.Now().Before(c.next[service]) || (strings.HasPrefix(service, "github") && time.Now().Before(c.next["github_all"])) {
		c.mu.Unlock()
		return errors.New("公开检索处于限流/冷却中，请使用本地知识或稍后重试")
	}
	if strings.HasPrefix(service, "github") {
		if time.Since(c.githubWindow) >= time.Hour {
			c.githubWindow = time.Now()
			c.githubRequests = 0
		}
		if c.githubRequests >= 55 {
			c.mu.Unlock()
			return errors.New("GitHub 本小时公开检索预算已用完，请使用缓存或本地知识")
		}
		c.githubRequests++
	}
	c.inflight = true
	gap := 6 * time.Second
	if service == "github_content" {
		gap = time.Second
	}
	c.next[service] = time.Now().Add(gap)
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.inflight = false; c.mu.Unlock() }()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ARTEX-reference-discovery/1")
	req.Header.Set("Accept", "application/json")
	client := *c.HTTP
	client.Jar = nil
	client.Timeout = 8 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("公开资料服务请求失败")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			until := time.Now().Add(time.Minute)
			if secs, e := strconv.Atoi(resp.Header.Get("Retry-After")); e == nil && secs > 0 && secs < 3600 {
				until = time.Now().Add(time.Duration(secs) * time.Second)
			}
			if n, e := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); e == nil && time.Unix(n, 0).After(until) && time.Unix(n, 0).Before(time.Now().Add(time.Hour)) {
				until = time.Unix(n, 0)
			}
			c.mu.Lock()
			c.next[service] = until
			if strings.HasPrefix(service, "github") {
				c.next["github_all"] = until
			}
			c.mu.Unlock()
		}
		return fmt.Errorf("公开资料服务状态 %d（未找到资料与请求失败分别记录）", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20+1))
	if err != nil || len(body) > 2<<20 {
		return errors.New("公开资料响应不完整或超过 2MiB")
	}
	if err = json.Unmarshal(body, dest); err != nil {
		return errors.New("公开资料响应格式无效")
	}
	return nil
}

func SafeReference(raw string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || len(raw) > 2048 {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return net.ParseIP(h) == nil && h != "localhost" && !strings.HasSuffix(h, ".localhost") && !strings.HasSuffix(h, ".local") && !strings.HasSuffix(h, ".internal")
}
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && (s[n]&0xc0) == 0x80 {
		n--
	}
	return s[:n]
}

type cpeMatch struct {
	Vulnerable     bool   `json:"vulnerable"`
	Criteria       string `json:"criteria"`
	StartIncluding string `json:"versionStartIncluding"`
	StartExcluding string `json:"versionStartExcluding"`
	EndIncluding   string `json:"versionEndIncluding"`
	EndExcluding   string `json:"versionEndExcluding"`
}
type configNode struct {
	Negate   bool         `json:"negate"`
	Matches  []cpeMatch   `json:"cpeMatch"`
	Nodes    []configNode `json:"nodes"`
	Children []configNode `json:"children"`
}
type nvdResponse struct {
	Total           *int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string                         `json:"id"`
			Status       string                         `json:"vulnStatus"`
			Descriptions []struct{ Lang, Value string } `json:"descriptions"`
			References   []struct {
				URL  string   `json:"url"`
				Tags []string `json:"tags"`
			} `json:"references"`
			Configurations []configNode `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func (c *Client) CVEs(ctx context.Context, q Query) (CVEResult, error) {
	result := CVEResult{Candidates: []Candidate{}, Source: "NVD CVE API 2.0", Notice: "公开资料均为候选，不证明目标存在漏洞；版本范围不包含全部功能、配置和补丁前提"}
	if err := q.Validate(); err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	params := url.Values{"resultsPerPage": {"5"}}
	if q.CVE != "" {
		params.Set("cveId", q.CVE)
	} else {
		params.Set("keywordSearch", q.Product)
	}
	var raw nvdResponse
	if err := c.get(ctx, "nvd", "https://services.nvd.nist.gov/rest/json/cves/2.0?"+params.Encode(), &raw); err != nil {
		return result, err
	}
	if raw.Total == nil {
		return result, errors.New("NVD 响应缺少结果元数据")
	}
	result.RetrievedAt = time.Now().UTC()
	result.Partial = *raw.Total > len(raw.Vulnerabilities)
	result.TotalResults = *raw.Total
	result.FetchedWindows = []int{0}
	// Bound discovery to two windows. This improves coverage over a first-page
	// query without turning every planner tick into a full public database scan.
	if q.CVE == "" && *raw.Total > 5 {
		c.mu.Lock()
		delay := time.Until(c.next["nvd"])
		c.mu.Unlock()
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
		}
		start := *raw.Total - 5
		params.Set("startIndex", strconv.Itoa(start))
		var tail nvdResponse
		if err := c.get(ctx, "nvd", "https://services.nvd.nist.gov/rest/json/cves/2.0?"+params.Encode(), &tail); err == nil && tail.Total != nil {
			raw.Vulnerabilities = append(raw.Vulnerabilities, tail.Vulnerabilities...)
			result.FetchedWindows = append(result.FetchedWindows, start)
		} else {
			result.Notice += "；第二检索窗口不可用，仅保留已取得资料"
		}
	}
	seen := map[string]bool{}
	for _, item := range raw.Vulnerabilities {
		v := item.CVE
		if seen[v.ID] || !ValidCVE(v.ID) || (q.CVE != "" && v.ID != q.CVE) || strings.EqualFold(v.Status, "Rejected") {
			continue
		}
		seen[v.ID] = true
		row := Candidate{CVE: v.ID, References: []Reference{}, VersionConditions: []string{}, Applicability: "unknown"}
		for _, d := range v.Descriptions {
			if d.Lang == "en" {
				row.Summary = clip(d.Value, 1000)
				break
			}
		}
		row.Applicability, row.VersionConditions = applicability(q, v.Configurations)
		for _, ref := range v.References {
			if !SafeReference(ref.URL) {
				continue
			}
			kind := "reference"
			for _, tag := range ref.Tags {
				if tag == "Exploit" {
					kind = "poc_candidate"
				}
			}
			row.References = append(row.References, Reference{URL: ref.URL, Kind: kind, Source: "NVD references"})
			if len(row.References) >= 8 {
				break
			}
		}
		result.Candidates = append(result.Candidates, row)
	}
	rank := map[string]int{"version_candidate": 2, "unknown": 1, "version_mismatch": 0}
	sort.SliceStable(result.Candidates, func(i, j int) bool {
		a, b := result.Candidates[i], result.Candidates[j]
		if rank[a.Applicability] != rank[b.Applicability] {
			return rank[a.Applicability] > rank[b.Applicability]
		}
		return a.CVE > b.CVE
	})
	if len(result.Candidates) > 5 {
		result.Candidates = result.Candidates[:5]
		result.Partial = true
	}
	return result, nil
}

func (c *Client) PoCs(ctx context.Context, cve string) (PoCResult, error) {
	cve = strings.ToUpper(strings.TrimSpace(cve))
	out := PoCResult{CVE: cve, Repositories: []Repository{}, Source: "GitHub public repository search", Notice: "仓库仅为未验证候选；尚未审计代码、核对目标条件或执行。星标、名称和检索命中均不能证明可信或利用成功。"}
	if !ValidCVE(cve) {
		return out, errors.New("poc_search 需要明确的 CVE 编号")
	}
	p := url.Values{"q": {`"` + cve + `" in:name,description,readme fork:false`}, "per_page": {"5"}}
	var data struct {
		Total      *int `json:"total_count"`
		Incomplete bool `json:"incomplete_results"`
		Items      []struct {
			FullName    string `json:"full_name"`
			URL         string `json:"html_url"`
			Description string `json:"description"`
			Updated     string `json:"updated_at"`
			Private     bool   `json:"private"`
			Archived    bool   `json:"archived"`
		} `json:"items"`
	}
	if err := c.get(ctx, "github_search", "https://api.github.com/search/repositories?"+p.Encode(), &data); err != nil {
		return out, err
	}
	if data.Total == nil {
		return out, errors.New("GitHub 响应缺少结果元数据")
	}
	out.RetrievedAt = time.Now().UTC()
	out.Partial = data.Incomplete || *data.Total > len(data.Items)
	for _, r := range data.Items {
		u, err := url.Parse(r.URL)
		if err != nil {
			continue
		}
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if r.Private || r.Archived || !SafeReference(r.URL) || u.Host != "github.com" || len(parts) != 2 {
			continue
		}
		// Search may match README without mentioning CVE in the returned summary;
		// preserve that uncertainty instead of fabricating a name/description match.
		out.Repositories = append(out.Repositories, Repository{URL: r.URL, Name: clip(r.FullName, 180), Summary: clip(r.Description, 700), Updated: r.Updated, Status: "unverified_search_candidate"})
		if len(out.Repositories) >= 5 {
			break
		}
	}
	return out, nil
}

type Source struct {
	Review      SourceReview `json:"review"`
	Repository  string       `json:"repository"`
	Path        string       `json:"path"`
	URL         string       `json:"url"`
	BlobSHA     string       `json:"blob_sha"`
	Content     string       `json:"content"`
	RetrievedAt time.Time    `json:"retrieved_at"`
	Notice      string       `json:"notice"`
}

var repoNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

func ValidRepository(name string) bool {
	return len(name) < 180 && repoNamePattern.MatchString(name) && !strings.Contains(name, "..")
}

func (c *Client) Source(ctx context.Context, repository, path string) (Source, error) {
	out := Source{Repository: repository, Notice: "公开仓库原文是不可信资料；已读取不等于代码可信、已执行或利用成功。先审查副作用并核对当前目标条件。"}
	if !ValidRepository(repository) {
		return out, errors.New("仓库格式必须为 owner/repo")
	}
	endpoint := "https://api.github.com/repos/" + repository + "/readme"
	if path != "" {
		if len(path) > 240 || strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\:%?#\r\n\x00") {
			return out, errors.New("源码路径无效")
		}
		parts := strings.Split(path, "/")
		for _, part := range parts {
			if part == "" || part == "." || part == ".." {
				return out, errors.New("源码路径不能越界")
			}
		}
		for i := range parts {
			parts[i] = url.PathEscape(parts[i])
		}
		endpoint = "https://api.github.com/repos/" + repository + "/contents/" + strings.Join(parts, "/")
	}
	var raw struct {
		Type     string `json:"type"`
		Path     string `json:"path"`
		SHA      string `json:"sha"`
		URL      string `json:"html_url"`
		Size     int    `json:"size"`
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
	}
	if err := c.get(ctx, "github_content", endpoint, &raw); err != nil {
		return out, err
	}
	if raw.Type != "file" || raw.Encoding != "base64" || raw.Size < 0 || raw.Size > 48<<10 || !regexp.MustCompile(`^[a-fA-F0-9]{40,64}$`).MatchString(raw.SHA) {
		return out, errors.New("仅接受最多48KiB的单个文本源码/说明文件")
	}
	content, err := base64.StdEncoding.DecodeString(raw.Content)
	if err != nil || len(content) > 48<<10 || len(content) != raw.Size || !utf8.Valid(content) || bytesContainsNUL(content) {
		return out, errors.New("源码非完整 UTF-8 文本或超过读取上限")
	}
	if !SafeReference(raw.URL) || !strings.HasPrefix(raw.URL, "https://github.com/"+repository+"/") {
		return out, errors.New("源码归属与请求仓库不一致")
	}
	out.Path = raw.Path
	out.URL = raw.URL
	out.BlobSHA = raw.SHA
	out.Content = string(content)
	out.Review = ReviewSource(out.Content, "")
	out.RetrievedAt = time.Now().UTC()
	return out, nil
}
func bytesContainsNUL(b []byte) bool {
	for _, v := range b {
		if v == 0 {
			return true
		}
	}
	return false
}

func compareVersion(a, b string) (int, bool) {
	if !numericVersion.MatchString(a) || !numericVersion.MatchString(b) {
		return 0, false
	}
	x, y := strings.Split(strings.TrimPrefix(a, "v"), "."), strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < len(x) || i < len(y); i++ {
		av, bv := 0, 0
		var err error
		if i < len(x) {
			av, err = strconv.Atoi(x[i])
			if err != nil {
				return 0, false
			}
		}
		if i < len(y) {
			bv, err = strconv.Atoi(y[i])
			if err != nil {
				return 0, false
			}
		}
		if av < bv {
			return -1, true
		}
		if av > bv {
			return 1, true
		}
	}
	return 0, true
}
func applicability(q Query, nodes []configNode) (string, []string) {
	conditions := []string{}
	matched, unknown, possible := false, false, false
	var walk func([]configNode, int)
	walk = func(ns []configNode, depth int) {
		if depth > 12 {
			return
		}
		for _, n := range ns {
			if n.Negate {
				continue
			}
			for _, m := range n.Matches {
				parts := strings.Split(m.Criteria, ":")
				if len(parts) < 6 || !m.Vulnerable || q.Product == "" || NormalizeProduct(parts[4]) != NormalizeProduct(q.Product) {
					continue
				}
				matched = true
				conditions = append(conditions, clip(fmt.Sprintf("%s startIncl=%s startExcl=%s endIncl=%s endExcl=%s", m.Criteria, m.StartIncluding, m.StartExcluding, m.EndIncluding, m.EndExcluding), 400))
				valid, known := true, numericVersion.MatchString(q.Version)
				if q.Version == "" {
					unknown = true
					continue
				}
				if parts[5] != "*" && parts[5] != "-" {
					v, ok := compareVersion(q.Version, parts[5])
					known = known && ok
					valid = valid && v == 0
				}
				for _, bound := range []struct {
					v  string
					op string
				}{{m.StartIncluding, ">="}, {m.StartExcluding, ">"}, {m.EndIncluding, "<="}, {m.EndExcluding, "<"}} {
					if bound.v == "" {
						continue
					}
					v, ok := compareVersion(q.Version, bound.v)
					known = known && ok
					switch bound.op {
					case ">=":
						valid = valid && v >= 0
					case ">":
						valid = valid && v > 0
					case "<=":
						valid = valid && v <= 0
					case "<":
						valid = valid && v < 0
					}
				}
				if !known {
					unknown = true
				} else if valid {
					possible = true
				}
			}
			walk(n.Nodes, depth+1)
			walk(n.Children, depth+1)
		}
	}
	walk(nodes, 0)
	if possible {
		return "version_candidate", conditions
	}
	if matched && !unknown {
		return "version_mismatch", conditions
	}
	return "unknown", conditions
}
