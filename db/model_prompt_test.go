package db

import (
	"github.com/Autumn-27/artex/modelprompt"
	"testing"
)

func TestModelPromptProfileRoundTripAndUpdate(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func(){d.Close()})
	p := &LLMProfile{Name: "model-prompt-test", Format: "openai", Model: "fixture", APIKey: "fixture-key", PoolExclude: true, ModelPrompt: modelprompt.Config{Mode: "custom", Text: "fixture instructions"}}
	id, err := d.SaveProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id) })
	got, err := d.ProfileByID(id)
	if err != nil || got == nil {
		t.Fatalf("read: %+v %v", got, err)
	}
	if got.ModelPrompt != p.ModelPrompt || got.IsDefault {
		t.Fatalf("mismatched profile %+v", got)
	}
	got.APIKey = ""
	got.ModelPrompt = modelprompt.Config{Mode: "compact-tools"}
	if _, err = d.SaveProfile(got); err != nil {
		t.Fatal(err)
	}
	got, err = d.ProfileByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.APIKey != "fixture-key" || got.ModelPrompt.Mode != "compact-tools" {
		t.Fatal("key or prompt update lost")
	}
	got.APIKey = "replacement-key"
	got.ModelPrompt = modelprompt.Config{}
	if _, err = d.SaveProfile(got); err != nil {
		t.Fatal(err)
	}
	got, err = d.ProfileByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.APIKey != "replacement-key" || got.ModelPrompt.Mode != "" {
		t.Fatal("keyed update or disabling failed")
	}
	got.ModelPrompt = modelprompt.Config{Mode: "invalid"}
	if _, err = d.SaveProfile(got); err == nil {
		t.Fatal("invalid config saved")
	}
	profiles, err := d.ListProfiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range profiles {
		if profile.ID == id && profile.ModelPrompt.Mode != "" {
			t.Fatal("invalid edit mutated storage")
		}
	}
}
