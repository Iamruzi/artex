package guard

import (
	"context"
	"encoding/json"
	"testing"
)

func TestMeasurementParticipatesInScopeAndEgressHooks(t *testing.T) {
	g := roeGuard("strict", []ScopeRule{{Kind: "domain", Value: "allowed.example"}})
	raw, _ := json.Marshal(map[string]any{"baseline_url": "https://allowed.example/a", "test_url": "https://outside.example/a"})
	if blocked, _, _ := g.Hooks().PreToolUse(context.Background(), "measure_http_pair", raw); !blocked {
		t.Fatal("measurement skipped RoE hook")
	}
	e := NewEgressGuard()
	e.AddFingerprint("platform", "fixture-platform-secret")
	g = New()
	g.SetEgress(e)
	for _, key := range []string{"baseline_body", "test_body", "headers"} {
		in := map[string]any{"baseline_url": "https://allowed.example/a", "test_url": "https://allowed.example/a"}
		if key == "headers" {
			in[key] = map[string]string{"Authorization": "fixture-platform-secret"}
		} else {
			in[key] = "fixture-platform-secret"
		}
		encoded, _ := json.Marshal(in)
		if blocked, _, _ := g.Hooks().PreToolUse(context.Background(), "measure_http_pair", encoded); !blocked {
			t.Fatalf("egress omitted %s", key)
		}
	}
}
