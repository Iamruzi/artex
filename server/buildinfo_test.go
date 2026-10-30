package server

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestByte2CatCannotFetchOrInstallUpstreamUpdate(t *testing.T) {
	// Deliberately no manager: disabled update paths must return before touching
	// proxy/database/network or starting a staging goroutine.
	s := &Server{}
	w := httptest.NewRecorder()
	s.updateCheck(w, httptest.NewRequest("GET", "/api/update/check", nil))
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || result["has_update"] != false || result["comparable"] != false || result["repo"] != "" {
		t.Fatal(w.Code, result)
	}
	w = httptest.NewRecorder()
	s.updateApply(w, httptest.NewRequest("POST", "/api/update/apply", nil))
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
}
