package llmbridge

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestNativeBridgeConvertsAuthAndStreams(t *testing.T) {
	calls := 0
	handler := NewHandler(transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != Upstream+"/v1/messages" || r.Header.Get("Authorization") != "Bearer test-key" || r.Header.Get("x-api-key") != "" || r.Header.Get("Cookie") != "" {
			t.Fatal("bad upstream or auth")
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "{}" {
			t.Fatal("body changed")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("event: message_stop\ndata: {}\n\n"))}, nil
	}))
	request := httptest.NewRequest("POST", "http://127.0.0.1/v1/messages", strings.NewReader("{}"))
	request.Header.Set("x-api-key", "test-key")
	request.Header.Set("Cookie", "local-secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "message_stop") || calls != 1 {
		t.Fatal("stream failed")
	}
}
func TestNativeBridgeRejectsUnapprovedRoutesAndMissingAuth(t *testing.T) {
	calls := 0
	handler := NewHandler(transportFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, nil }))
	for _, path := range []string{"/v1/messages?redirect=http://other", "/v1/chat/completions", "/v1/messages"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader("{}")))
		if w.Code == 200 {
			t.Fatal("route/auth accepted")
		}
	}
	if calls != 0 {
		t.Fatal("rejected request forwarded")
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
	if !strings.Contains(w.Body.String(), "native-go") {
		t.Fatal("native health missing")
	}
}
func TestNativeBridgePreservesUpstreamAuthErrorAndCancellation(t *testing.T) {
	handler := NewHandler(transportFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 401, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("expired"))}, nil
	}))
	r := httptest.NewRequest("POST", "/v1/messages", strings.NewReader("{}"))
	r.Header.Set("x-api-key", "test-key")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 401 || w.Body.String() != "expired" {
		t.Fatal("upstream denial lost")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = r.WithContext(ctx)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Body.Len() != 0 {
		t.Fatal("cancelled request executed")
	}
}

func TestNativeBridgeRejectsOversizedBodyAndUpstreamRedirect(t *testing.T) {
	calls := 0
	handler := NewHandler(transportFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"http://unrelated.example/"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	request := httptest.NewRequest("POST", "/v1/messages", strings.NewReader("{}"))
	request.Header.Set("x-api-key", "test-key")
	request.ContentLength = MaxBody + 1
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	if w.Code != 413 || calls != 0 {
		t.Fatal("oversized body forwarded")
	}
	request.ContentLength = 2
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	if w.Code != 502 || w.Header().Get("Location") != "" {
		t.Fatal("upstream redirect escaped fixed destination")
	}
}
