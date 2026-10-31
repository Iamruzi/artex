package agent

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestHTMLCandidatesMethodsSameOriginAndBase(t *testing.T) {
	source, _ := url.Parse("https://shop.example/dir/page.html")
	summary := htmlSummary{Base: "/base/", Links: []string{"next.html", "next.html", "https://other.example/x", "javascript:alert(1)", "#local"}, Forms: []htmlForm{{Action: "/submit", Method: "POST"}, {Action: "", Method: "GET"}, {Action: "/dialog", Method: "DIALOG"}}}
	got := htmlEndpointCandidates(summary, source)
	if len(got) != 3 || got[0].URL != "https://shop.example/base/next.html" || got[0].Method != "GET" || got[1].Method != "POST" || got[2].URL != source.String() {
		t.Fatalf("bad generated endpoints: %+v", got)
	}
	summary.Base = "https://other.example/"
	if got := htmlEndpointCandidates(summary, source); len(got) != 1 || got[0].URL != source.String() {
		t.Fatalf("cross-origin base escaped: %+v", got)
	}
}

func TestHTMLImportUsesExistingTaskScopeAndGatedInsertion(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("HTML import isolated test", "metadata only", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID := task.ID
	defer func() {
		_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, taskID)
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, task.ExplorationID)
	}()
	host := "html-import-recovery.example"
	defer d.Exec(`DELETE FROM task_scope WHERE task_id=$1`, taskID)
	defer d.Exec(`DELETE FROM task_asset_sources WHERE task_id=$1`, taskID)
	defer d.Exec(`DELETE FROM assets WHERE domain=$1`, host)
	if _, err := d.Assets().AddAgentScope(taskID, "subdomain", host, "test", "agent"); err != nil {
		t.Fatal(err)
	}
	ts := NewToolSet(nil, "")
	ts.SetTaskID(taskID)
	ts.SetAssetStore(d.Assets(), d.Companies())
	ctx, tc, _ := learningFixture(t)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID})
	root := filepath.Join(t.TempDir(), "tasks", strconv.FormatInt(taskID, 10))
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	tc.WorkingDir = root
	body := `<a href="/login">Login</a><a href="https://external.example/">external</a><form action="/submit" method="post"><input value="private-secret"></form>`
	if err := os.WriteFile(filepath.Join(root, "page.html"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{"html_path": "page.html", "base_url": "https://" + host + "/"})
	result, err := governTool(ts.insertAssets()).Call(ctx, raw, tc)
	if err != nil || result.IsError || strings.Contains(result.Flatten(), "private-secret") {
		t.Fatalf("import failed: %s %v", result.Flatten(), err)
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM assets WHERE type='endpoint' AND domain=$1 AND method IN ('GET','POST')`, host).Scan(&count); err != nil || count != 2 {
		t.Fatalf("wrong inserted endpoints: %d %v", count, err)
	}
	var external int
	d.QueryRow(`SELECT count(*) FROM assets WHERE domain='external.example'`).Scan(&external)
	if external != 0 {
		t.Fatal("external link registered")
	}
	bad, _ := json.Marshal(map[string]string{"html_path": "page.html", "base_url": "https://outside.example/"})
	result, _ = ts.insertAssets().Call(ctx, bad, tc)
	if !result.IsError {
		t.Fatal("source outside task scope allowed")
	}
	bad, _ = json.Marshal(map[string]string{"html_path": "../../escape.html", "base_url": "https://" + host + "/"})
	result, _ = ts.insertAssets().Call(ctx, bad, tc)
	if !result.IsError {
		t.Fatal("path escape allowed")
	}
	rule, err := d.Assets().CreateTaskInterceptRule(taskID, "block", "exact_domain", host, "test import gate", true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Assets().DeleteTaskInterceptRule(taskID, rule.ID)
	result, err = ts.insertAssets().Call(ctx, raw, tc)
	if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "已禁止插入") {
		t.Fatal("HTML mode bypassed existing asset gate")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := ts.insertAssets().Call(cancelled, raw, tc); err == nil {
		t.Fatal("cancel ignored")
	}
	if !htmlImportScopeAllows([]db.TaskScope{{Kind: "subdomain", Domain: host}}, host) || htmlImportScopeAllows([]db.TaskScope{{Kind: "subdomain", Domain: host}}, "sub."+host) {
		t.Fatal("exact-host scope expanded")
	}
}
