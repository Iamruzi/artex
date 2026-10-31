package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// hasSkillTool reports whether the packed tool set contains the Skill meta-tool.
func hasSkillTool(tools []actool.CoreTool) bool {
	for _, t := range tools {
		if t.Name() == "Skill" {
			return true
		}
	}
	return false
}

func TestBrowserRunProfilePathIsolation(t *testing.T) {
	dataDir := t.TempDir()
	taskOne := browserRunProfilePath(dataDir, "worker", agent.RunInfo{TaskID: 1})
	taskTwo := browserRunProfilePath(dataDir, "worker", agent.RunInfo{TaskID: 2})
	if taskOne == taskTwo || !strings.HasPrefix(filepath.Base(taskOne), "task-1-agent-") || !strings.HasPrefix(filepath.Base(taskTwo), "task-2-agent-") {
		t.Fatalf("task profiles are not isolated: %q %q", taskOne, taskTwo)
	}
	intentOne := browserRunProfilePath(dataDir, "worker", agent.RunInfo{TaskID: 1, IntentID: 10})
	intentTwo := browserRunProfilePath(dataDir, "worker", agent.RunInfo{TaskID: 1, IntentID: 11})
	if intentOne == intentTwo || !strings.Contains(filepath.Base(intentOne), "intent-10") {
		t.Fatalf("parallel worker intents must not contend for one Chrome profile: %q %q", intentOne, intentTwo)
	}

	sessionOne := browserRunProfilePath(dataDir, "mainagent", agent.RunInfo{SessionID: "conversation-one"})
	sessionTwo := browserRunProfilePath(dataDir, "mainagent", agent.RunInfo{SessionID: "conversation-two"})
	if sessionOne == sessionTwo || filepath.Base(sessionOne) == "conversation-one" {
		t.Fatalf("chat profiles must be isolated and must not expose raw session ids: %q %q", sessionOne, sessionTwo)
	}
	unsafeAgent := browserRunProfilePath(dataDir, `..\outside/profile`, agent.RunInfo{})
	if strings.Contains(filepath.Base(unsafeAgent), "outside") || filepath.Dir(unsafeAgent) != filepath.Join(dataDir, "browser-profiles") {
		t.Fatalf("agent key escaped or leaked into profile path: %q", unsafeAgent)
	}
}

// TestAssembleVisibleSkill verifies a filesystem skill made visible to an agent is
// packed into that agent's tool set (as the single Skill meta-tool) via the wired
// ToolAugment hook. Skills live on disk under skillDir; visibility is a per-agent
// (agent × skill_name) row keyed by the skill's directory name.
func TestAssembleVisibleSkill(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()

	// Filesystem skill fixture: <skillDir>/t-assemble/SKILL.md. The directory name
	// (t-assemble) is the visibility key matched against AgentSkillNames.
	skillDir := t.TempDir()
	const skillName = "t-assemble"
	if err := os.MkdirAll(filepath.Join(skillDir, skillName), 0o755); err != nil {
		t.Fatal(err)
	}
	md := "---\nname: t-assemble\ndescription: do the thing\n---\ndo the thing"
	if err := os.WriteFile(filepath.Join(skillDir, skillName, "SKILL.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}

	wireAgentAugment(pg, skillDir, t.TempDir(), nil)
	t.Cleanup(func() { agent.ToolAugment = nil })

	ag, _ := pg.GetAgentByKey("planner")
	if ag == nil {
		t.Fatal("planner agent missing")
	}

	// Isolate this test from whatever skill visibility the planner already has in the
	// shared DB: clear it now, restore it on cleanup.
	orig, _ := pg.AgentSkillNames(ag.ID)
	if err := pg.SetAgentSkillVisibility(ag.ID, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.SetAgentSkillVisibility(ag.ID, orig) })

	// before: skill not visible → no Skill meta-tool
	extra, _, cleanup := agent.ToolAugment(context.Background(), "planner")
	cleanup()
	if hasSkillTool(extra) {
		t.Fatalf("expected no Skill meta-tool before the skill is made visible")
	}

	// make the skill visible to planner
	if err := pg.ToggleSkillVisibility(ag.ID, skillName, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.ToggleSkillVisibility(ag.ID, skillName, false) })

	// after: the Skill meta-tool is packed in
	extra, _, cleanup = agent.ToolAugment(context.Background(), "planner")
	defer cleanup()
	if !hasSkillTool(extra) {
		t.Fatalf("expected the Skill meta-tool after making the skill visible")
	}

	// AugmentTools appends extra to base without filtering base
	combined, _, c2 := agent.AugmentTools(context.Background(), "planner", nil)
	defer c2()
	if !hasSkillTool(combined) {
		t.Fatalf("AugmentTools should surface the Skill meta-tool")
	}
}
