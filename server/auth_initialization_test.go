package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestPasswordHandlersFailClosedOnStorageError(t *testing.T) {
	kv := newMemKV()
	kv.err = errTest
	s := &Server{jwtKey: testJWTKey, authkv: kv}
	for _, tc := range []struct {
		name, method, body string
		handler            http.HandlerFunc
	}{
		{"status", "GET", "", s.authStatus},
		{"init", "POST", `{"password":"valid-password"}`, s.authInit},
		{"login", "POST", `{"username":"ARTEX","password":"valid-password"}`, s.authLogin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tc.handler(w, httptest.NewRequest(tc.method, "/api/auth/"+tc.name, strings.NewReader(tc.body)))
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var body map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &body)
			if _, ok := body["initialized"]; ok || body["token"] != nil || len(w.Result().Cookies()) != 0 {
				t.Fatal("storage error must not imply uninitialized state or issue credentials")
			}
		})
	}
}

func TestConcurrentAuthInitializationDoesNotOverwrite(t *testing.T) {
	kv := newMemKV()
	s := &Server{jwtKey: testJWTKey, authkv: kv}
	start := make(chan struct{})
	type response struct {
		code     int
		password string
	}
	results := make(chan response, 2)
	var wg sync.WaitGroup
	for _, password := range []string{"first-password", "second-password"} {
		wg.Add(1)
		go func(pw string) {
			defer wg.Done()
			<-start
			body, _ := json.Marshal(map[string]string{"password": pw})
			w := httptest.NewRecorder()
			s.authInit(w, httptest.NewRequest("POST", "/api/auth/init", strings.NewReader(string(body))))
			results <- response{w.Code, pw}
		}(password)
	}
	close(start)
	wg.Wait()
	close(results)
	var winner string
	for r := range results {
		switch r.code {
		case http.StatusOK:
			if winner != "" {
				t.Fatal("both initialization requests succeeded")
			}
			winner = r.password
		case http.StatusForbidden:
		default:
			t.Fatalf("unexpected status %d", r.code)
		}
	}
	if winner == "" {
		t.Fatal("neither initialization succeeded")
	}
	hash, _, _ := kv.GetSetting(authPassKey)
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(winner)); err != nil {
		t.Fatal("persisted password does not belong to the successful request")
	}
}

func TestValidatePasswordBoundaries(t *testing.T) {
	for _, tc := range []struct {
		pw    string
		valid bool
	}{
		{"", false}, {"1234567", false}, {"12345678", true},
		{"密码密码密码密码", true}, {"密码强", false},
		{strings.Repeat("a", 72), true}, {strings.Repeat("a", 73), false},
		{strings.Repeat("密", 25), false},
	} {
		if valid := validatePassword(tc.pw) == ""; valid != tc.valid {
			t.Errorf("password length %d: valid=%v want %v", len(tc.pw), valid, tc.valid)
		}
	}
}
