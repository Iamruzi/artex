package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
)

func TestNewTaskChatContextDeadline(t *testing.T) {
	ctx, cancel, release := newTaskChatContext(context.Background(), 20*time.Millisecond, 20*time.Millisecond)
	defer cancel(agent.AbortChatTurnFinished)
	defer release()

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("task chat deadline did not fire")
	}
	if !errors.Is(context.Cause(ctx), agent.AbortRunHardTimeout) {
		t.Fatalf("cause = %v, want AbortRunHardTimeout", context.Cause(ctx))
	}
}

func TestNewTaskChatContextManualStop(t *testing.T) {
	ctx, cancel, release := newTaskChatContext(context.Background(), time.Hour, time.Minute)
	defer release()

	cancel(agent.AbortChatStoppedByUser)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("manual stop did not cancel task chat")
	}
	if !errors.Is(context.Cause(ctx), agent.AbortChatStoppedByUser) {
		t.Fatalf("cause = %v, want AbortChatStoppedByUser", context.Cause(ctx))
	}
}

func TestNewTaskChatContextUnlimited(t *testing.T) {
	ctx, cancel, release := newTaskChatContext(context.Background(), 0, time.Minute)
	defer release()

	select {
	case <-ctx.Done():
		t.Fatal("unlimited task chat was cancelled")
	default:
	}
	cancel(agent.AbortChatTurnFinished)
}
