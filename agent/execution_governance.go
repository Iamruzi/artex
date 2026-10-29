package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/norma/agentcore"
	actool "github.com/Autumn-27/norma/tool"
)

// ResourceAdmission is installed once at server startup. Embedding the original
// CoreTool preserves its permission/schema/deferred-skill checks. Call executes
// only after the harness's existing PreToolUse hooks have approved it.
var ResourceAdmission func(context.Context, string) (func(), error)

type resourceLeaseKey struct{}

// HasResourceLease avoids taking a second slot when a governed adapter delegates
// to a custom executor. The outer call retains its lease until delegation ends.
func HasResourceLease(ctx context.Context) bool {
	held, _ := ctx.Value(resourceLeaseKey{}).(bool)
	return held
}

// ExecutionRecord describes a tool invocation, not a finding or goal verdict.
// Arguments and output are deliberately excluded (may contain credentials).
type ExecutionRecord struct {
	At        time.Time `json:"at"`
	Tool      string    `json:"tool"`
	CallID    string    `json:"call_id,omitempty"`
	TaskID    int64     `json:"task_id,omitempty"`
	IntentID  int64     `json:"intent_id,omitempty"`
	Status    string    `json:"status"`
	ElapsedMS int64     `json:"elapsed_ms"`
}

type governedTool struct{ actool.CoreTool }

func governTool(t actool.CoreTool) actool.CoreTool { return &governedTool{t} }

func costlyTool(name string) bool {
	switch name {
	case "Bash", "shell_open", "shell_send", "WebFetch", "WebSearch":
		return true
	}
	// Custom executors also gate their editor test endpoint in the server.
	return strings.HasPrefix(name, "mcp__")
}

func (g *governedTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (res actool.Result, err error) {
	start := time.Now()
	status := "returned" // tool return only; background completion is not asserted
	defer func() {
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			status = "timeout"
		case ctx.Err() != nil:
			status = "cancelled"
		case res.IsError && strings.HasPrefix(res.Flatten(), "resource_blocked:"):
			status = "resource_blocked"
		case err != nil || res.IsError:
			if status != "resource_blocked" {
				status = "failed"
			}
		}
		ri := RunInfoFrom(ctx)
		r := ExecutionRecord{At: start.UTC(), Tool: g.Name(), TaskID: ri.TaskID, IntentID: ri.IntentID, Status: status, ElapsedMS: time.Since(start).Milliseconds()}
		if tc != nil {
			r.CallID = tc.ToolUseID
			writeExecutionRecord(tc.WorkingDir, r)
		}
	}()
	costly := costlyTool(g.Name())
	if costly && ResourceAdmission != nil {
		release, e := ResourceAdmission(ctx, g.Name())
		if e != nil {
			status = "resource_blocked"
			return actool.Errorf("resource_blocked: " + e.Error() + "。资源恢复后再试；本次未执行工具。"), nil
		}
		defer release()
		ctx = context.WithValue(ctx, resourceLeaseKey{}, true)
	}
	if err = ctx.Err(); err != nil {
		return actool.Result{}, err
	}
	return g.CoreTool.Call(ctx, in, tc)
}

// Each run has at most two 2 MiB journals. Serialization avoids concurrent tool
// calls interleaving JSON; records contain no raw request/response material.
var executionJournalMu sync.Mutex

func writeExecutionRecord(dir string, r ExecutionRecord) {
	if dir == "" {
		return
	}
	if len(r.Tool) > 200 {
		r.Tool = r.Tool[:200]
	}
	if len(r.CallID) > 200 {
		r.CallID = r.CallID[:200]
	}
	executionJournalMu.Lock()
	defer executionJournalMu.Unlock()
	path := filepath.Join(dir, "execution-events.jsonl")
	// Reject symlinks, including a malicious pre-existing journal. Artifact roots
	// are supplied by the host, never by model parameters.
	if fi, e := os.Lstat(path); e == nil {
		if !fi.Mode().IsRegular() {
			return
		}
		if fi.Size() > 2<<20 {
			_ = os.Remove(path + ".1")
			if os.Rename(path, path+".1") != nil {
				return
			}
		}
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(r)
}

// Norma appends optional network tools inside NewSession, after host assembly.
// Materialize them here to avoid silently bypassing the governor and ledger.
func governSessionOptions(opts *agentcore.Options) {
	if opts.Tools == nil {
		opts.Tools = actool.DefaultTools()
	}
	if opts.EnableWebFetch {
		opts.Tools = append(opts.Tools, actool.NewWebFetch(actool.WebFetchConfig{Proxy: opts.WebFetchProxy, CACert: opts.WebFetchCACert, InsecureTLS: opts.WebFetchInsecureTLS}))
		opts.EnableWebFetch = false
	}
	if opts.EnableWebSearch {
		if ws, err := actool.NewWebSearch(actool.WebSearchConfig{Backend: opts.WebSearchBackend, BraveAPIKey: opts.BraveSearchAPIKey, TavilyAPIKey: opts.TavilySearchAPIKey, DeepSeekBaseURL: opts.DeepSeekSearchBaseURL, DeepSeekAPIKey: opts.DeepSeekSearchAPIKey, DeepSeekModel: opts.DeepSeekSearchModel, Proxy: opts.WebSearchProxy, CACert: opts.WebSearchCACert, InsecureTLS: opts.WebSearchInsecureTLS}); err == nil {
			opts.Tools = append(opts.Tools, ws)
		}
		opts.EnableWebSearch = false
	}
	for i, t := range opts.Tools {
		if _, ok := t.(*governedTool); !ok {
			opts.Tools[i] = governTool(guardPanic(t))
		}
	}
}
