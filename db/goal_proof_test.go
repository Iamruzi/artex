package db

import (
	"context"
	"fmt"
	"os"
	"testing"
)

func goalProofDB(t *testing.T) *DB {
	t.Helper()
	if os.Getenv("ARTEX_PG_DSN") == "" {
		t.Skip("explicit isolated ARTEX_PG_DSN required")
	}
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func goalProofStore(t *testing.T, d *DB) *ExplorationStore {
	t.Helper()
	id, err := d.CreateExploration("goal proof fixture", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM explorations WHERE id=$1`, id) })
	return d.Exploration(id)
}

func TestGoalProofEligibilityAndAtomicity(t *testing.T) {
	d := goalProofDB(t)
	s := goalProofStore(t, d)
	goal, err := s.AddGoal(map[string]any{"text": "fixture acceptance"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		kind, state, status string
		valid               bool
	}{
		{KindHint, "active", "", false},
		{KindIntent, "done", "", false},
		{KindFact, "origin", "", false},
		{KindFact, "dismissed", "", false},
		{KindFinding, "confirmed", "", false},
		{KindFinding, "confirmed", FindingPending, false},
		{KindFinding, "confirmed", FindingFalsePositive, false},
		{KindFinding, "dismissed", FindingConfirmed, false},
		{KindFinding, "confirmed", FindingConfirmed, true},
		{KindFact, "confirmed", "", true},
	} {
		t.Run(tc.kind+"_"+tc.state+"_"+tc.status, func(t *testing.T) {
			if err := s.SetNodeState(goal, "open"); err != nil {
				t.Fatal(err)
			}
			ev, err := s.AddNode(tc.kind, map[string]any{"summary": "fixture"}, 0, tc.state, "test", nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.status != "" {
				fid, err := d.AddFinding(0, ev, "fixture", "fixture", SeverityLow, "fixture", "fixture", "test", nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { d.Exec(`DELETE FROM findings WHERE id=$1`, fid) })
				if _, err = d.SetFindingStatus(fid, tc.status); err != nil {
					t.Fatal(err)
				}
			}
			err = s.ProveGoal(t.Context(), goal, ev)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			n, err := s.GetNode(goal)
			if err != nil {
				t.Fatal(err)
			}
			var edges int
			if err = d.QueryRow(`SELECT count(*) FROM exploration_edges WHERE src_id=$1 AND dst_id=$2 AND rel='proves'`, ev, goal).Scan(&edges); err != nil {
				t.Fatal(err)
			}
			if tc.valid {
				if n.State != "met" || edges != 1 {
					t.Fatal("proof not committed")
				}
			} else if n.State != "open" || edges != 0 {
				t.Fatal("rejected proof changed graph")
			}
		})
	}
	// A write that passes evidence checks but fails the final state constraint
	// must roll back its preceding edge insertion as well.
	ev, err := s.AddNode(KindFact, map[string]any{"summary": "rollback fixture"}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	constraint := fmt.Sprintf("goal_proof_fixture_%d", goal)
	if _, err = d.Exec(fmt.Sprintf(`ALTER TABLE exploration_nodes ADD CONSTRAINT %s CHECK (id<>%d OR state<>'met') NOT VALID`, constraint, goal)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`ALTER TABLE exploration_nodes DROP CONSTRAINT IF EXISTS ` + constraint) })
	if err = s.SetNodeState(goal, "open"); err != nil {
		t.Fatal(err)
	}
	if err = s.ProveGoal(t.Context(), goal, ev); err == nil {
		t.Fatal("constraint failure reported success")
	}
	var edges int
	if err = d.QueryRow(`SELECT count(*) FROM exploration_edges WHERE src_id=$1 AND dst_id=$2`, ev, goal).Scan(&edges); err != nil || edges != 0 {
		t.Fatalf("partial edge left behind: %d %v", edges, err)
	}
	n, err := s.GetNode(goal)
	if err != nil || n.State != "open" {
		t.Fatal("failed write changed goal", err)
	}
}

func TestGoalProofCompletionChecksEveryGoalAndLiveEvidence(t *testing.T) {
	d := goalProofDB(t)
	s := goalProofStore(t, d)
	check := func(want bool) {
		t.Helper()
		got, err := s.AllGoalsProven(t.Context())
		if err != nil || got != want {
			t.Fatalf("met=%v want=%v err=%v", got, want, err)
		}
	}
	check(false) // zero goals cannot mean success
	goal, err := s.AddGoal(map[string]any{"text": "first"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := s.AddNode(KindFact, map[string]any{"summary": "positive"}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetNodeState(goal, "met"); err != nil {
		t.Fatal(err)
	}
	check(false) // a bare met label has no proof
	if pending, err := s.NeedsGoalReview(t.Context()); err != nil || !pending {
		t.Fatal("bare met label bypasses planner review", err)
	}
	if err = s.ProveGoal(t.Context(), goal, ev); err != nil {
		t.Fatal(err)
	}
	check(true)
	if err = s.SetNodeState(ev, "dismissed"); err != nil {
		t.Fatal(err)
	}
	check(false) // evidence invalidated after submission
	if err = s.SetNodeState(ev, "confirmed"); err != nil {
		t.Fatal(err)
	}
	if err = s.SetNodeState(goal, "abandoned"); err != nil {
		t.Fatal(err)
	}
	if err = s.ProveGoal(t.Context(), goal, ev); err == nil {
		t.Fatal("abandoned goal revived by proof")
	}
	check(false)
	if err = s.SetNodeState(goal, "open"); err != nil {
		t.Fatal(err)
	}
	// The old newest-1000 check could hide this open goal behind newer met ones.
	if _, err = d.Exec(`INSERT INTO exploration_nodes(exploration_id,kind,payload,state)
SELECT $1,'goal','{}','met' FROM generate_series(1,1001)`, s.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id)
SELECT $1,$2,'proves',id FROM exploration_nodes WHERE exploration_id=$1 AND kind='goal' AND state='met'`, s.ID(), ev); err != nil {
		t.Fatal(err)
	}
	check(false)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = s.AllGoalsProven(ctx); err == nil {
		t.Fatal("cancelled check succeeded")
	}
	if err = s.ProveGoal(ctx, goal, ev); err == nil {
		t.Fatal("cancelled proof succeeded")
	}
}

func TestGoalProofDrainedExecutionDoesNotBypassAcceptance(t *testing.T) {
	d := goalProofDB(t)
	row, err := d.CreateTask("drained proof fixture", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.Exec(`DELETE FROM tasks WHERE id=$1`, row.ID)
		d.Exec(`DELETE FROM explorations WHERE id=$1`, row.ExplorationID)
	})
	s := d.Exploration(row.ExplorationID)
	check := func(want bool) {
		t.Helper()
		if _, err := d.Exec(`UPDATE tasks SET status='running',completed_at=NULL WHERE id=$1`, row.ID); err != nil {
			t.Fatal(err)
		}
		won, err := d.CompleteDrainedTask(t.Context(), row.ID, row.ExplorationID)
		if err != nil || won != want {
			t.Fatalf("won=%v want=%v err=%v", won, want, err)
		}
	}
	check(true) // no goals: execution may end, it is not a goal-success proof
	goal, err := s.AddGoal(map[string]any{"text": "fixture"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	check(false)
	if err = s.SetNodeState(goal, "met"); err != nil {
		t.Fatal(err)
	}
	check(false) // even the drain shortcut must validate a met label
	if err = s.SetNodeState(goal, "abandoned"); err != nil {
		t.Fatal(err)
	}
	check(true) // explicit abandonment can finish execution without goal success
	met, err := s.AllGoalsProven(t.Context())
	if err != nil || met {
		t.Fatal("abandonment counted as goal success", err)
	}
	intent, err := s.AddIntent(map[string]any{"summary": "new work"}, 1, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	check(false)
	if err = s.SetNodeState(intent, "running"); err != nil {
		t.Fatal(err)
	}
	check(false)
	if err = s.SetNodeState(intent, "stopped"); err != nil {
		t.Fatal(err)
	}
	check(true)
}

func TestGoalProofTaskCompletionPreservesLifecycle(t *testing.T) {
	d := goalProofDB(t)
	for _, state := range []string{"running", "paused", "queued", "timeout", "failed", "done", "deleted", "missing_proof", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			row, err := d.CreateTask("proof completion fixture", "fixture", nil, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				d.Exec(`DELETE FROM tasks WHERE id=$1`, row.ID)
				d.Exec(`DELETE FROM explorations WHERE id=$1`, row.ExplorationID)
			})
			s := d.Exploration(row.ExplorationID)
			goal, err := s.AddGoal(map[string]any{"text": "fixture"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			ev, err := s.AddNode(KindFact, map[string]any{"summary": "fixture"}, 0, "confirmed", "test", nil)
			if err != nil {
				t.Fatal(err)
			}
			if state != "missing_proof" {
				if err = s.ProveGoal(t.Context(), goal, ev); err != nil {
					t.Fatal(err)
				}
			}
			query := `UPDATE tasks SET status='running' WHERE id=$1`
			switch state {
			case "paused":
				query = `UPDATE tasks SET status='running',paused=true WHERE id=$1`
			case "queued":
				query = `UPDATE tasks SET status='running',queued=true WHERE id=$1`
			case "deleted":
				query = `UPDATE tasks SET status='running',deleted_at=now() WHERE id=$1`
			case "timeout", "failed", "done":
				query = fmt.Sprintf(`UPDATE tasks SET status='%s' WHERE id=$1`, state)
			}
			if _, err = d.Exec(query, row.ID); err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			if state == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			won, err := d.CompleteTaskWithGoals(ctx, row.ID, row.ExplorationID)
			if state == "cancelled" {
				if err == nil || won {
					t.Fatal("cancelled completion succeeded")
				}
				return
			}
			if err != nil || won != (state == "running") {
				t.Fatalf("won=%v err=%v", won, err)
			}
			var status string
			if err = d.QueryRow(`SELECT status FROM tasks WHERE id=$1`, row.ID).Scan(&status); err != nil {
				t.Fatal(err)
			}
			want := "running"
			if state == "running" || state == "done" {
				want = "done"
			}
			if state == "timeout" || state == "failed" {
				want = state
			}
			if status != want {
				t.Fatalf("status=%s want=%s", status, want)
			}
		})
	}
}

func TestGoalProofSourceVisibilityIsRechecked(t *testing.T) {
	d := goalProofDB(t)
	newTask := func(sources ...int64) *Task {
		t.Helper()
		row, err := d.CreateTaskWithOptions("proof source fixture", "fixture", TaskCreateOptions{SourceTaskIDs: sources})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			d.Exec(`DELETE FROM tasks WHERE id=$1`, row.ID)
			d.Exec(`DELETE FROM explorations WHERE id=$1`, row.ExplorationID)
		})
		return row
	}
	grand := newTask()
	source := newTask(grand.ID)
	current := newTask(source.ID)
	s := d.Exploration(current.ExplorationID)
	goal, err := s.AddGoal(map[string]any{"text": "fixture"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	makeFact := func(exp int64) int64 {
		t.Helper()
		id, err := d.Exploration(exp).AddNode(KindFact, map[string]any{"summary": "source"}, 0, "confirmed", "test", nil)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	if err = s.ProveGoal(t.Context(), goal, makeFact(grand.ExplorationID)); err == nil {
		t.Fatal("transitive source accepted")
	}
	ev := makeFact(source.ExplorationID)
	if err = s.ProveGoal(t.Context(), goal, ev); err != nil {
		t.Fatal("direct source rejected", err)
	}
	met, err := s.AllGoalsProven(t.Context())
	if err != nil || !met {
		t.Fatal("direct proof not accepted", err)
	}
	if _, err = d.Exec(`DELETE FROM task_relations WHERE task_id=$1 AND source_task_id=$2`, current.ID, source.ID); err != nil {
		t.Fatal(err)
	}
	met, err = s.AllGoalsProven(t.Context())
	if err != nil || met {
		t.Fatal("removed source still proves goal", err)
	}
	if err = s.ProveGoal(t.Context(), goal, ev); err == nil {
		t.Fatal("unrelated source accepted")
	}
	if err = s.ProveGoal(t.Context(), makeFact(current.ExplorationID), ev); err == nil {
		t.Fatal("non-goal accepted")
	}
	foreignGoal, err := d.Exploration(source.ExplorationID).AddGoal(map[string]any{"text": "foreign"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ProveGoal(t.Context(), foreignGoal, ev); err == nil {
		t.Fatal("foreign goal mutated")
	}
}
