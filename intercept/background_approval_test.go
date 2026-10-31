package intercept

import "testing"

func TestBackgroundApprovalDeadlineDoesNotStallOrGrant(t *testing.T) {
	base := Decision{Action: "ask"}
	got := backgroundApprovalDeadline(base, 0, "1")
	if !got.TimeoutEnabled || got.TimeoutSeconds != 60 || got.TimeoutAction != "deny" {
		t.Fatal("background approval must have a bounded fail-closed wait")
	}
	for _, tc := range []struct {
		conv int64
		task string
	}{{1, "1"}, {0, ""}} {
		if got := backgroundApprovalDeadline(base, tc.conv, tc.task); got.TimeoutEnabled {
			t.Fatal("interactive or unattributed call changed")
		}
	}
	configured := Decision{Action: "ask", TimeoutEnabled: true, TimeoutSeconds: 120, TimeoutAction: "deny"}
	got = backgroundApprovalDeadline(configured, 0, "1")
	if got.TimeoutSeconds != 120 || got.TimeoutAction != "deny" {
		t.Fatal("explicit policy changed")
	}
}
