package server

import (
	"context"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/resourceguard"
)

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
