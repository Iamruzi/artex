package db

import (
	"fmt"
	"testing"
	"time"
)

func TestSecuritySkillSeedPreservesUserChoices(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	worker, err := d.GetAgentByKey("worker")
	if err != nil || worker == nil {
		t.Fatalf("worker: %v", err)
	}
	var on bool
	if err = d.QueryRow(`SELECT enabled FROM agent_skill_visibility WHERE agent_id=$1 AND skill_name='code-semgrep-audit'`, worker.ID).Scan(&on); err != nil || !on {
		t.Fatalf("new worker skill not seeded: enabled=%v err=%v", on, err)
	}
	// A disabled old skill and a disabled new skill are both explicit user choices.
	for _, name := range []string{"api-recon", "code-semgrep-audit"} {
		var initial bool
		if err = d.QueryRow(`SELECT enabled FROM agent_skill_visibility WHERE agent_id=$1 AND skill_name=$2`, worker.ID, name).Scan(&initial); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := d.Exec(`UPDATE agent_skill_visibility SET enabled=$3 WHERE agent_id=$1 AND skill_name=$2`, worker.ID, name, initial); err != nil {
				t.Errorf("restore %s: %v", name, err)
			}
		})
		if _, err = d.Exec(`UPDATE agent_skill_visibility SET enabled=false WHERE agent_id=$1 AND skill_name=$2`, worker.ID, name); err != nil {
			t.Fatal(err)
		}
	}
	custom := fmt.Sprintf("test-security-skill-%d", time.Now().UnixNano())
	if _, err = d.Exec(`INSERT INTO agent_skill_visibility(agent_id,skill_name,enabled) VALUES ($1,$2,true) ON CONFLICT (agent_id,skill_name) DO UPDATE SET enabled=true`, worker.ID, custom); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := d.Exec(`DELETE FROM agent_skill_visibility WHERE agent_id=$1 AND skill_name=$2`, worker.ID, custom); err != nil {
			t.Errorf("remove custom test skill: %v", err)
		}
	})
	for range 2 {
		if err = d.seedBuiltinSkillVisibility(); err != nil {
			t.Fatal(err)
		}
	}
	for name, want := range map[string]bool{"api-recon": false, "code-semgrep-audit": false, custom: true} {
		if err = d.QueryRow(`SELECT enabled FROM agent_skill_visibility WHERE agent_id=$1 AND skill_name=$2`, worker.ID, name).Scan(&on); err != nil || on != want {
			t.Errorf("seed overwrote %s: enabled=%v want=%v err=%v", name, on, want, err)
		}
	}
}
