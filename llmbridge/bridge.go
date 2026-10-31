// Package llmbridge is a local-only, fixed-upstream Anthropic auth adapter.
// It ships in the ARTEX binary and requires no Python or installed packages.
package llmbridge

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

const Upstream = "https://endpoint.notrackcoder.com"
const MaxBody = 8 << 20

func NewHandler(transport http.RoundTripper) http.Handler {
	target, _ := url.Parse(Upstream)
	proxy := &httputil.ReverseProxy{Transport: transport, FlushInterval: -1, Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(target)
		r.Out.URL.Path = "/v1/messages"
		r.Out.URL.RawPath = ""
		r.Out.URL.RawQuery = ""
		r.Out.Header.Set("Authorization", "Bearer "+r.In.Header.Get("x-api-key"))
		r.Out.Header.Del("x-api-key")
		r.Out.Header.Del("Cookie")
		r.Out.Header.Set("Accept-Encoding", "identity")
	}, ModifyResponse: func(r *http.Response) error {
		if r.StatusCode >= 300 && r.StatusCode < 400 {
			return errors.New("upstream redirect rejected")
		}
		return nil
	}, ErrorLog: log.New(io.Discard, "", 0), ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, "upstream connection failed", http.StatusBadGateway)
	}}
	slots := make(chan struct{}, 4)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/health" && r.URL.RawQuery == "" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "service": "artex-notrack-auth-bridge", "runtime": "native-go"})
			return
		}
		if r.Method != "POST" || r.URL.Path != "/v1/messages" || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		keys := r.Header.Values("x-api-key")
		if len(keys) != 1 || keys[0] == "" {
			http.Error(w, "one x-api-key is required", 401)
			return
		}
		if r.ContentLength < 1 || r.ContentLength > MaxBody || len(r.TransferEncoding) > 0 {
			http.Error(w, "invalid request size", 413)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "bridge concurrency limit reached", 503)
			return
		}
		if r.Context().Err() != nil {
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		proxy.ServeHTTP(w, r)
	})
}

func Run(args []string) error {
	flags := flag.NewFlagSet("anthropic-bridge", flag.ContinueOnError)
	port := flags.Int("port", 18991, "loopback port")
	outbound := flags.String("proxy", "", "optional upstream HTTP/SOCKS proxy")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *port < 1 || *port > 65535 {
		return errors.New("invalid port")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ResponseHeaderTimeout = 90 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.MaxIdleConnsPerHost = 4
	if *outbound != "" {
		p, err := url.Parse(*outbound)
		if err != nil || p.Host == "" || (p.Scheme != "http" && p.Scheme != "https" && p.Scheme != "socks5") {
			return errors.New("invalid proxy")
		}
		transport.Proxy = http.ProxyURL(p)
	}
	defer transport.CloseIdleConnections()
	server := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", *port), Handler: NewHandler(transport), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, BaseContext: nil}
	log.Printf("Local Anthropic adapter listening on %s (native Go)", server.Addr)
	return server.ListenAndServe()
}
