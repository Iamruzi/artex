package agent

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestGoalToolsCannotBypassStoredProof(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("explicit isolated ARTEX_PG_DSN required")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	id, err := d.CreateExploration("goal tool fixture", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, id)
	s := d.Exploration(id)
	ts := &ToolSet{ts: s} // deliberately no AssetStore: must not skip finding checks
	callMet := func(input string, wantError bool) {
		t.Helper()
		res, err := ts.goalMet().Call(t.Context(), json.RawMessage(input), nil)
		if err != nil || res.IsError != wantError {
			t.Fatalf("result=%s err=%v", res.Flatten(), err)
		}
	}
	callMet(`{"reason":"扫描完成"}`, true)
	if ts.GoalMet {
		t.Fatal("no goals marked successful")
	}
	goal, err := s.AddGoal(map[string]any{"text": "fixture acceptance"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := s.AddNode(db.KindFinding, map[string]any{"summary": "fixture"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"goal_id": goal, "evidence_id": ev, "reason": "fixture"})
	res, err := ts.proveGoal().Call(t.Context(), raw, nil)
	if err != nil || !res.IsError || ts.GoalMet {
		t.Fatal("legacy finding bypassed status check", err)
	}
	fid, err := d.AddFinding(0, ev, "fixture", "fixture", db.SeverityLow, "fixture", "fixture", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM findings WHERE id=$1`, fid)
	if _, err = d.SetFindingStatus(fid, db.FindingConfirmed); err != nil {
		t.Fatal(err)
	}
	res, err = ts.proveGoal().Call(t.Context(), raw, nil)
	if err != nil || res.IsError || !ts.GoalMet {
		t.Fatal("valid positive rejected", res.Flatten(), err)
	}
	callMet(`{"reason":"全部证明已保存"}`, false)
	if !ts.GoalMet {
		t.Fatal("valid final check rejected")
	}
	callMet(`{"reason":" "}`, true)
	if ts.GoalMet {
		t.Fatal("invalid request retained stale success")
	}
	if _, err = d.SetFindingStatus(fid, db.FindingFalsePositive); err != nil {
		t.Fatal(err)
	}
	callMet(`{"reason":"早先成功过"}`, true)
	if ts.GoalMet {
		t.Fatal("revoked evidence accepted")
	}
	closed, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ts.ts = closed.Exploration(id)
	if err = closed.Close(); err != nil {
		t.Fatal(err)
	}
	callMet(`{"reason":"数据库故障"}`, true)
	res, err = ts.proveGoal().Call(t.Context(), raw, nil)
	if err != nil || !res.IsError || ts.GoalMet {
		t.Fatal("DB failure reported success", err)
	}
}

func TestGoalMetRequiresTaskContext(t *testing.T) {
	ts := &ToolSet{}
	res, err := ts.goalMet().Call(t.Context(), json.RawMessage(`{"reason":"完成"}`), nil)
	if err != nil || !res.IsError || ts.GoalMet {
		t.Fatal("taskless completion accepted", err)
	}
}
