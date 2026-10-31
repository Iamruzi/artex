package agent

import (
	"context"
	"sync"
)

type repeatBudgetKey struct{}
type repeatBudget struct {
	mu     sync.Mutex
	counts map[string]int
	cancel context.CancelCauseFunc
}

func withRepeatBudget(ctx context.Context) (context.Context, context.CancelCauseFunc) {
	run, cancel := context.WithCancelCause(ctx)
	return context.WithValue(run, repeatBudgetKey{}, &repeatBudget{counts: map[string]int{}, cancel: cancel}), cancel
}

func noteRepeatBlocked(ctx context.Context, key string) {
	budget, _ := ctx.Value(repeatBudgetKey{}).(*repeatBudget)
	if budget == nil {
		return
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if len(budget.counts) >= 64 && budget.counts[key] == 0 {
		return
	}
	budget.counts[key]++
	if budget.counts[key] >= 2 {
		budget.cancel(AbortRepeatedToolFailure)
	}
}
