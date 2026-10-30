package pocsearch

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

const nvdFixture = `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2099-90001","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"Synthetic version fixture; not a real advisory."}],"references":[{"url":"https://github.com/fixture/CVE-2099-90001","tags":["Exploit"]},{"url":"http://127.0.0.1/private","tags":["Exploit"]}],"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:fixture:pan-os:*:*:*:*:*:*:*:*","versionStartIncluding":"10.0","versionEndExcluding":"11.0"}]}]}]}}]}`

func TestCVEVersionCandidatesRemainConservative(t *testing.T) {
	for _, tc := range []struct{ version, want string }{{"10.2.3", "version_candidate"}, {"11.0", "version_mismatch"}, {"9.9", "version_mismatch"}, {"10.2.3-h1", "unknown"}, {"", "unknown"}} {
		t.Run(tc.version, func(t *testing.T) {
			c := NewClient()
			c.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host != "services.nvd.nist.gov" || r.URL.Query().Get("keywordSearch") != "PAN-OS" || r.Header.Get("Authorization") != "" {
					t.Fatal("unexpected public request", r.URL)
				}
				return response(200, nvdFixture), nil
			})
			out, err := c.CVEs(t.Context(), Query{Product: "PAN-OS", Version: tc.version})
			if err != nil || len(out.Candidates) != 1 || out.Candidates[0].Applicability != tc.want || len(out.Candidates[0].References) != 1 {
				t.Fatalf("out=%+v err=%v", out, err)
			}
			if out.Candidates[0].References[0].Kind != "poc_candidate" {
				t.Fatal("missing PoC reference")
			}
		})
	}
}

func TestCVEWindowsAreBoundedAndVersionCandidatesRankFirst(t *testing.T) {
	c := NewClient()
	calls := 0
	c.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		// Simulate the elapsed quota interval without a real six-second test wait.
		c.mu.Lock()
		c.next["nvd"] = time.Time{}
		c.mu.Unlock()
		if calls == 1 {
			if r.URL.Query().Get("startIndex") != "" {
				t.Fatal("unexpected first window")
			}
			return response(200, strings.Replace(strings.Replace(nvdFixture, `"totalResults":1`, `"totalResults":30`, 1), `"11.0"`, `"10.0"`, 1)), nil
		}
		if calls != 2 || r.URL.Query().Get("startIndex") != "25" {
			t.Fatal("unbounded or incorrect second window", r.URL)
		}
		return response(200, strings.Replace(strings.Replace(nvdFixture, `"totalResults":1`, `"totalResults":30`, 1), "CVE-2099-90001", "CVE-2099-90002", -1)), nil
	})
	out, err := c.CVEs(t.Context(), Query{Product: "PAN-OS", Version: "10.2.3"})
	if err != nil || calls != 2 || !out.Partial || out.TotalResults != 30 || len(out.FetchedWindows) != 2 || len(out.Candidates) != 2 || out.Candidates[0].Applicability != "version_candidate" || out.Candidates[1].Applicability != "version_mismatch" {
		t.Fatalf("out=%+v calls=%d err=%v", out, calls, err)
	}
}

func TestCVESecondWindowFailurePreservesPartialEvidence(t *testing.T) {
	c := NewClient()
	calls := 0
	c.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		c.mu.Lock()
		c.next["nvd"] = time.Time{}
		c.mu.Unlock()
		if calls == 1 {
			return response(200, strings.Replace(nvdFixture, `"totalResults":1`, `"totalResults":10`, 1)), nil
		}
		return response(429, ""), nil
	})
	out, err := c.CVEs(t.Context(), Query{Product: "PAN-OS", Version: "10.2.3"})
	if err != nil || calls != 2 || len(out.Candidates) != 1 || !out.Partial || !strings.Contains(out.Notice, "第二检索窗口不可用") || len(out.FetchedWindows) != 1 {
		t.Fatalf("out=%+v calls=%d err=%v", out, calls, err)
	}
}

func TestPublicLookupRejectsSensitiveShapesWithoutHTTP(t *testing.T) {
	c := NewClient()
	var calls atomic.Int32
	c.HTTP.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { calls.Add(1); return response(200, `{}`), nil })
	for _, p := range []string{"https://target.invalid", "192.168.0.1", "target.example.com", "target.example.com product", "localhost", "foo;whoami", "name@host", "token=secret", "foo/bar"} {
		if _, err := c.CVEs(t.Context(), Query{Product: p}); err == nil {
			t.Fatalf("accepted %q", p)
		}
	}
	if _, err := c.PoCs(t.Context(), "CVE-2024-3400 OR secret"); err == nil {
		t.Fatal("search query injection accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid input made network calls")
	}
}

func TestPoCRepositoryDiscoveryAndSourceAreOnlyText(t *testing.T) {
	c := NewClient()
	var calls int
	content := "# Synthetic fixture\nThis content must never execute."
	c.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "api.github.com" {
			t.Fatal("unexpected host")
		}
		if r.URL.Path == "/search/repositories" {
			if !strings.Contains(r.URL.Query().Get("q"), `"CVE-2099-90001"`) {
				t.Fatal("missing exact CVE")
			}
			return response(200, `{"total_count":2,"incomplete_results":true,"items":[{"full_name":"fixture/CVE-2099-90001","html_url":"https://github.com/fixture/CVE-2099-90001","description":"unverified fixture"},{"html_url":"https://attacker.invalid/repo","full_name":"bad/repo"}]}`), nil
		}
		if r.URL.Path != "/repos/fixture/CVE-2099-90001/readme" {
			t.Fatal("unexpected source path", r.URL.Path)
		}
		raw, _ := json.Marshal(map[string]any{"type": "file", "path": "README.md", "sha": strings.Repeat("a", 40), "html_url": "https://github.com/fixture/CVE-2099-90001/blob/main/README.md", "size": len(content), "encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(content))})
		return response(200, string(raw)), nil
	})
	list, err := c.PoCs(t.Context(), "cve-2099-90001")
	if err != nil || len(list.Repositories) != 1 || !list.Partial {
		t.Fatal(list, err)
	}
	source, err := c.Source(t.Context(), "fixture/CVE-2099-90001", "")
	if err != nil || source.Content != content || source.BlobSHA == "" || calls != 2 {
		t.Fatal(source, err)
	}
	for _, path := range []string{"../secret", "/absolute", "x/../../x", "x%2fsecret", "x\\secret"} {
		if _, err = c.Source(t.Context(), "fixture/CVE-2099-90001", path); err == nil {
			t.Fatal("unsafe source path accepted")
		}
	}
	if calls != 2 {
		t.Fatal("invalid paths made requests")
	}
}

func TestPublicFailuresAreNotEmptySuccessOrAutomaticRetries(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{{"bad-json", "{", 200}, {"missing-meta", "{}", 200}, {"redirect", "", 302}, {"rate-limit", "", 429}, {"oversize", strings.Repeat("x", (2<<20)+1), 200}} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient()
			calls := 0
			c.HTTP.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return response(tc.status, tc.body), nil })
			if _, err := c.CVEs(t.Context(), Query{CVE: "CVE-2099-90001"}); err == nil {
				t.Fatal("failure reported as success")
			}
			if calls != 1 {
				t.Fatal("retried")
			}
		})
	}
	c := NewClient()
	calls := 0
	c.HTTP.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return response(200, nvdFixture), nil })
	if _, err := c.CVEs(t.Context(), Query{CVE: "CVE-2099-90001"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CVEs(t.Context(), Query{CVE: "CVE-2099-90002"}); err == nil {
		t.Fatal("rate budget bypassed")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.PoCs(ctx, "CVE-2099-90001"); err == nil {
		t.Fatal("cancelled call admitted")
	}
	if calls != 1 {
		t.Fatal("failed budget/cancellation made request")
	}
}
