package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeHTMLWorksWithoutPythonAndOmitsValues(t *testing.T) {
	ctx, tc, root := learningFixture(t)
	body := `<title>Shop</title><a href="/products">link</a><script src="/app.js"></script><form action="/login" method="post"><input name="email" type="text" value="private-account"><input name="csrf" type="hidden" value="private-token"></form>`
	if err := os.WriteFile(filepath.Join(root, "page.html"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := nativeHTMLTool().Call(ctx, json.RawMessage(`{"path":"page.html"}`), tc)
	if err != nil || result.IsError {
		t.Fatalf("%s %v", result.Flatten(), err)
	}
	var summary htmlSummary
	if json.Unmarshal([]byte(result.Flatten()), &summary) != nil || summary.Title != "Shop" || len(summary.Forms) != 1 || summary.Forms[0].Method != "POST" || len(summary.Forms[0].Inputs) != 2 {
		t.Fatal(result.Flatten())
	}
	if strings.Contains(result.Flatten(), "private-") {
		t.Fatal("form values exposed")
	}
}
func TestNativeHTMLRejectsEscapeAndCancellation(t *testing.T) {
	ctx, tc, root := learningFixture(t)
	for _, path := range []string{"../../outside.html", filepath.Join(t.TempDir(), "outside.html")} {
		raw, _ := json.Marshal(map[string]string{"path": path})
		result, _ := nativeHTMLTool().Call(ctx, raw, tc)
		if !result.IsError {
			t.Fatal("escaped task root")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err := extractHTML(cancelled, strings.NewReader("<html></html>"))
	if err == nil {
		t.Fatal("cancellation ignored")
	}
	outside := filepath.Join(t.TempDir(), "outside.html")
	os.WriteFile(outside, []byte("secret"), 0600)
	if err := os.Symlink(outside, filepath.Join(root, "outside-link.html")); err == nil {
		result, _ := nativeHTMLTool().Call(ctx, json.RawMessage(`{"path":"outside-link.html"}`), tc)
		if !result.IsError {
			t.Fatal("symlink escaped task root")
		}
	}
}
func TestNativeHTMLSummaryIsBounded(t *testing.T) {
	summary, err := extractHTML(context.Background(), strings.NewReader(strings.Repeat(`<a href="/x">x</a>`, 150)+`<form>`+strings.Repeat(`<input name="x">`, 150)+`</form>`))
	if err != nil || len(summary.Links) != 100 || !summary.Truncated {
		t.Fatal("summary budget not enforced")
	}
	raw, _ := json.Marshal(summary)
	if len(raw) > 65536 {
		t.Fatal("oversized output")
	}
}
