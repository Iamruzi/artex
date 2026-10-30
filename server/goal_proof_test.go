package server

import (
	"context"
	"strconv"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestGoalCompletionUpdatesLiveHandleOnlyAfterAcceptance(t *testing.T) {
	s, task, _ := measurementFixture(t)
	task.updateLifecycle(func(state *taskLifecycleState) { state.Status = "running" })
	goal, err := task.Store.AddGoal(map[string]any{"text": "fixture"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := task.Store.AddNode(db.KindFact, map[string]any{"summary": "fixture"}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	won, err := s.m.CompleteTaskWithGoals(t.Context(), task)
	if err != nil || won || task.lifecycleSnapshot().Status != "running" {
		t.Fatal("unproven task completed", err)
	}
	if err = task.Store.ProveGoal(t.Context(), goal, ev); err != nil {
		t.Fatal(err)
	}
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	if err = s.m.pg.SetPaused(id, true); err != nil {
		t.Fatal(err)
	}
	won, err = s.m.CompleteTaskWithGoals(t.Context(), task)
	if err != nil || won || task.lifecycleSnapshot().Status != "running" {
		t.Fatal("paused task completed", err)
	}
	if err = s.m.pg.SetPaused(id, false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if won, err = s.m.CompleteTaskWithGoals(ctx, task); err == nil || won {
		t.Fatal("cancelled completion accepted")
	}
	won, err = s.m.CompleteTaskWithGoals(t.Context(), task)
	if err != nil || !won || task.lifecycleSnapshot().Status != "done" || task.lifecycleSnapshot().CompletedAt == 0 {
		t.Fatal("accepted completion missing live state", err)
	}
	won, err = s.m.CompleteTaskWithGoals(t.Context(), task)
	if err != nil || won {
		t.Fatal("terminal status rewritten", err)
	}
}
