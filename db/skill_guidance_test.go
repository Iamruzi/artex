package db

import "testing"

func TestModelJailbreakSkillVisibilityAndOptOut(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	const name = "model-jailbreak-assist"
	var workerID int64
	for _, role := range []string{"planner", "mainagent", "auto", "pentest", "worker"} {
		agent, err := d.GetAgentByKey(role)
		if err != nil || agent == nil {
			t.Fatalf("missing role %s: %v", role, err)
		}
		var enabled bool
		if err = d.QueryRow(`SELECT enabled FROM agent_skill_visibility WHERE agent_id=$1 AND skill_name=$2`, agent.ID, name).Scan(&enabled); err != nil || !enabled {
			t.Fatalf("skill unavailable to %s: %v", role, err)
		}
		if role == "worker" {
			workerID = agent.ID
		}
	}
	t.Cleanup(func() {
		d.Exec(`UPDATE agent_skill_visibility SET enabled=true WHERE agent_id=$1 AND skill_name=$2`, workerID, name)
	})
	if _, err = d.Exec(`UPDATE agent_skill_visibility SET enabled=false WHERE agent_id=$1 AND skill_name=$2`, workerID, name); err != nil {
		t.Fatal(err)
	}
	if err = d.seedBuiltinSkillVisibility(); err != nil {
		t.Fatal(err)
	}
	var enabled bool
	if err = d.QueryRow(`SELECT enabled FROM agent_skill_visibility WHERE agent_id=$1 AND skill_name=$2`, workerID, name).Scan(&enabled); err != nil || enabled {
		t.Fatal("manual opt-out resurrected")
	}
}
