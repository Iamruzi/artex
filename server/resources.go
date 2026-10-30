package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/resourceguard"
)

const resourceProtectionSetting = "resource_protection_enabled"

func (s *Server) restoreResourceProtection() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	value, exists, err := s.m.pg.GetSetting(resourceProtectionSetting)
	if err != nil {
		log.Printf("[resources] 读取保护开关失败，保留默认开启: %v", err)
		return
	}
	if exists && value == "false" {
		s.resources.SetProtectionEnabled(false)
	}
}

func (s *Server) initResources(dataDir string) {
	if dataDir == "" {
		dataDir = "."
	}
	path, err := filepath.Abs(dataDir)
	if err != nil {
		path = dataDir
	}
	// Sample the filesystem actually used for artifacts. A missing data directory
	// is an operational error, not a reason to report the root disk as healthy.
	if err := os.MkdirAll(path, 0700); err != nil {
		log.Printf("[resources] data directory: %v", err)
	}
	s.resources = resourceguard.New(config.Load().ResourceGuard)
	s.restoreResourceProtection()
	s.engine.resources = s.resources
	agent.ResourceAdmission = func(ctx context.Context, name string) (func(), error) {
		wait, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return s.resources.Acquire(wait)
	}
	go s.resources.Run(s.ctx, resourceguard.NewSampler(path), func(a resourceguard.Alert) {
		log.Printf("[resources] %s: %s", a.State, a.Reason)
	})
}

func (s *Server) setResourceProtection(w http.ResponseWriter, r *http.Request) {
	if s.resources == nil {
		writeErr(w, http.StatusServiceUnavailable, "资源采样尚未初始化")
		return
	}
	var input struct {
		Enabled *bool `json:"enabled"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || input.Enabled == nil {
		writeErr(w, http.StatusBadRequest, "enabled 必须为 true 或 false")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeErr(w, http.StatusBadRequest, "请求只能包含一个 JSON 对象")
		return
	}
	if s.m == nil || s.m.pg == nil {
		writeErr(w, http.StatusServiceUnavailable, "设置存储尚未初始化")
		return
	}
	s.resourceProtectionMu.Lock()
	defer s.resourceProtectionMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Persist first: a failed write must not change the live setting or claim
	// that the choice will survive restart.
	_, err := s.m.pg.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES ($1,$2)
ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()`, resourceProtectionSetting, strconv.FormatBool(*input.Enabled))
	if err != nil {
		log.Printf("[resources] 保存保护开关失败: %v", err)
		writeErr(w, http.StatusInternalServerError, "资源保护设置保存失败，请重试")
		return
	}
	s.resources.SetProtectionEnabled(*input.Enabled)
	log.Printf("[resources] 自动资源保护 enabled=%t", *input.Enabled)
	writeJSON(w, http.StatusOK, s.resources.Snapshot())
}

func (s *Server) resourceStatus(w http.ResponseWriter, r *http.Request) {
	if s.resources == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "资源采样尚未初始化"})
		return
	}
	writeJSON(w, http.StatusOK, s.resources.Snapshot())
}

// Custom tools also have an editor test endpoint outside agent assembly.
func (s *Server) admitCustomTool(ctx context.Context) (func(), error) {
	if s.resources == nil || agent.HasResourceLease(ctx) {
		return func() {}, nil
	}
	wait, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.resources.Acquire(wait)
}
