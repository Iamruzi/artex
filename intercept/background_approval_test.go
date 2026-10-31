package intercept

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestBackgroundTaskAskAutoApprovesAndAudits(t *testing.T) {
	d := openTestDB(t)
	ic := New(d)
	resetAutoAllow(t, ic)

	marker := fmt.Sprintf("background-auto-allow-%d", time.Now().UnixNano())
	input := []byte(fmt.Sprintf(`{"command":%q}`, marker))
	ctx := WithTaskContext(context.Background(), "1", "worker#1", nil)
	start := time.Now()
	if !ic.HandleAsk(ctx, 0, Decision{Action: "ask", Message: "需要审批"}, "Bash", input) {
		t.Fatal("background task ask should be auto-approved")
	}
	if time.Since(start) > time.Second {
		t.Fatal("background task ask should not wait for a human decision")
	}

	var status, source, taskID string
	if err := d.QueryRow(`SELECT status, decision_source, task_id FROM intercept_pending
		WHERE tool_name='Bash' AND tool_input::text LIKE '%' || $1 || '%'`, marker).Scan(&status, &source, &taskID); err != nil {
		t.Fatalf("background approval must be audited: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM intercept_pending WHERE tool_input::text LIKE '%' || $1 || '%'`, marker)
	})
	if status != "allowed" || source != "background_auto_allow" || taskID != "1" {
		t.Fatalf("history=(%s,%s,%s), want (allowed,background_auto_allow,1)", status, source, taskID)
	}
}
