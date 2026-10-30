package modelprompt

import (
	"strings"
	"testing"
)

func TestModelPromptConfig(t *testing.T) {
	if (Config{}).Render() != "" || (Config{}).Digest() != "" {
		t.Fatal("disabled instructions must be a no-op")
	}
	for _, mode := range []string{"authorized-testing", "compact-tools", "custom"} {
		c := Config{Mode: mode, Text: "fixture instructions"}
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		if len(c.Digest()) != 64 || !strings.Contains(c.Render(), c.Digest()) {
			t.Fatal("rendered text must carry the actual digest")
		}
	}
	if (Config{Mode: "custom", Text: "A"}).Digest() == (Config{Mode: "custom", Text: "B"}).Digest() {
		t.Fatal("changed instructions reused digest")
	}
	for _, c := range []Config{{Mode: "unknown"}, {Mode: "custom"}, {Text: strings.Repeat("x", MaxTextBytes+1)}, {Text: "bad\x00text"}, {Text: string([]byte{255})}} {
		if c.Validate() == nil {
			t.Fatalf("accepted invalid config %+v", c)
		}
	}
}
