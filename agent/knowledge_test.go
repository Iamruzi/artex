package agent

import (
	"context"
	"github.com/Autumn-27/norma/llm"
	"testing"
)

func TestKnowledgeReceiptRequiresActualCompleteBlockAndConsumedStream(t *testing.T) {
	before := KnowledgeReceipt
	t.Cleanup(func() { KnowledgeReceipt = before })
	count := 0
	const block = "reference fixture\nwith \"quoted\" data"
	KnowledgeReceipt = func(_ context.Context, role, got string) {
		if role != "planner" || got != block {
			t.Fatal("receipt lost exact content")
		}
		count++
	}
	inner := &promptCapture{}
	p := withKnowledgeReceipt(inner, "planner", block)
	missing := llm.CompletionRequest{Messages: []llm.Message{{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock("reference fixture")}}}}
	p.Complete(t.Context(), missing)
	if count != 0 {
		t.Fatal("partial reference produced receipt")
	}
	req := llm.CompletionRequest{Messages: []llm.Message{{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock("before " + block + " after")}}}}
	stream := p.Stream(t.Context(), req)
	if count != 0 {
		t.Fatal("unconsumed stream produced receipt")
	}
	for range stream {
	}
	if count != 1 {
		t.Fatal("consumed stream lacked receipt")
	}
	p.Complete(t.Context(), req)
	if count != 1 || len(inner.requests) != 3 {
		t.Fatal("receipt repeated or provider call lost")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	p = withKnowledgeReceipt(inner, "planner", block)
	p.Complete(ctx, req)
	if count != 1 {
		t.Fatal("cancelled request produced receipt")
	}
}
