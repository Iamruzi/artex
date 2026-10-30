package agent

import (
	"context"
	"iter"

	"github.com/Autumn-27/artex/modelprompt"
	"github.com/Autumn-27/norma/llm"
)

type modelPromptProvider struct {
	llm.Provider
	supplement string
}

// WithModelPrompt attaches a validated supplement without replacing host tools.
func WithModelPrompt(p llm.Provider, config modelprompt.Config) (llm.Provider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if config.Mode == "" {
		return p, nil
	}
	return &modelPromptProvider{Provider: p, supplement: config.Render()}, nil
}

func (p *modelPromptProvider) request(req llm.CompletionRequest) llm.CompletionRequest {
	// Copy System: providers are shared and a resumed request may reuse its slice.
	// Appending beyond DynamicBoundary preserves the host's cache-prefix meaning.
	return modelprompt.Apply(req, p.supplement)
}

func (p *modelPromptProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return p.Provider.Stream(ctx, p.request(req))
}

func (p *modelPromptProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return p.Provider.Complete(ctx, p.request(req))
}
