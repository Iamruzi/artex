package agent

import (
	"context"
	actool "github.com/Autumn-27/norma/tool"
	"time"
)

// The SDK soft budget is checked at turn/tool boundaries. A separate child
// deadline also bounds an in-flight model response and the settlement grace.
func plannerRoundContext(ctx context.Context, budget, grace time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeoutCause(ctx, budget+grace, AbortRunHardTimeout)
}

// The planner's existing contract is coordination, not target execution. Keep
// local evidence reads and dispatch tools; workers own shell and HTTP probes.
func plannerCoordinationTools(tools []actool.CoreTool) []actool.CoreTool {
	out := make([]actool.CoreTool, 0, len(tools))
	for _, tool := range tools {
		switch tool.Name() {
		case "Bash", "WebFetch", "shell_open", "shell_send":
			continue
		}
		out = append(out, tool)
	}
	return out
}
