package agent

import (
	"context"
	"encoding/json"
	"iter"
	"strings"
	"sync"

	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

// KnowledgePreflight is installed by the host. It receives the final resolved
// tool list so disabling/unbinding retrieval tools also disables automatic use.
// The returned reference block belongs in the run's user input, not system rules.
var KnowledgePreflight func(context.Context, string, []actool.CoreTool) string
var KnowledgeReceipt func(context.Context, string, string)

type knowledgeProvider struct {
	llm.Provider
	block, role string
	receipt     func(context.Context, string, string)
	once        sync.Once
}

func withKnowledgeReceipt(provider llm.Provider, role, block string) llm.Provider {
	if block == "" || KnowledgeReceipt == nil {
		return provider
	}
	return &knowledgeProvider{Provider: provider, block: block, role: role, receipt: KnowledgeReceipt}
}
func (p *knowledgeProvider) observe(ctx context.Context, r llm.CompletionRequest) {
	if ctx.Err() != nil {
		return
	}
	raw, _ := json.Marshal(r.Messages)
	encoded, _ := json.Marshal(p.block)
	if len(encoded) > 2 && strings.Contains(string(raw), string(encoded[1:len(encoded)-1])) {
		p.once.Do(func() { p.receipt(ctx, p.role, p.block) })
	}
}
func (p *knowledgeProvider) Complete(ctx context.Context, r llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.observe(ctx, r)
	return p.Provider.Complete(ctx, r)
}
func (p *knowledgeProvider) Stream(ctx context.Context, r llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		p.observe(ctx, r)
		for event, err := range p.Provider.Stream(ctx, r) {
			if !yield(event, err) {
				return
			}
		}
	}
}

func knowledgePreflight(ctx context.Context, role string, tools []actool.CoreTool) string {
	if KnowledgePreflight == nil || ctx.Err() != nil {
		return ""
	}
	return KnowledgePreflight(ctx, role, tools)
}
