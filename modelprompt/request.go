package modelprompt

import "github.com/Autumn-27/norma/llm"

// Apply preserves the caller's slice and dynamic/cache boundary. The recorder
// uses this same transformation for its normalized view of the actual wire call.
func Apply(req llm.CompletionRequest, supplement string) llm.CompletionRequest {
	if supplement != "" {
		req.System = append(append([]string{}, req.System...), supplement)
	}
	return req
}
