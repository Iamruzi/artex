package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/norma/agentcore"
)

func TestNoaDisabledPreservesBuiltInCompaction(t *testing.T) {
	for _, enabled := range []func() bool{nil, func() bool { return false }} {
		original := compactionConfig(10000)
		opts := agentcore.Options{Compaction: original, SystemPrompt: []string{"keep fork rules"}, DynamicBoundary: 5}
		enableNoa(&opts, enabled, t.TempDir(), "disabled", nil)
		if opts.Compaction != original || opts.Compactor != nil || len(opts.Tools) != 0 || opts.DynamicBoundary != 5 {
			t.Fatal("disabled noa changed existing context management")
		}
	}
}

func TestNoaEnabledUsesOneContextManager(t *testing.T) {
	opts := agentcore.Options{Compaction: compactionConfig(10000), SystemPrompt: []string{"keep fork rules"}}
	enableNoa(&opts, func() bool { return true }, t.TempDir(), "enabled", nil)
	if opts.Compactor == nil || opts.Compaction != nil || len(opts.Tools) != 1 || len(opts.AppendSystemPrompt) == 0 {
		t.Fatal("noa must attach its tool, prompt and context manager together")
	}
	if len(opts.SystemPrompt) != 1 || opts.SystemPrompt[0] != "keep fork rules" {
		t.Fatal("noa replaced fork system rules")
	}
}

func TestNoaArchiveFailureKeepsBuiltInCompaction(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	original := compactionConfig(10000)
	opts := agentcore.Options{Compaction: original}
	warned := false
	enableNoa(&opts, func() bool { return true }, blocked, "failure", func(string) { warned = true })
	if !warned || opts.Compactor != nil || opts.Compaction != original || len(opts.Tools) != 0 {
		t.Fatal("noa archive failure did not preserve the original context manager")
	}
}
