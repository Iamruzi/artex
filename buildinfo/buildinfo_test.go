package buildinfo

import (
	"os"
	"strings"
	"testing"
)

func TestReleaseVersionMatchesDefaultBuild(t *testing.T) {
	version, err := os.ReadFile("../VERSION")
	if err != nil || strings.TrimSpace(string(version)) != Version {
		t.Fatal("VERSION and default build version disagree", err)
	}
}

func TestDisplaySeparatesVersionRevisionAndUncommittedChanges(t *testing.T) {
	info := format(Info{Version: "0.1.0", Edition: Edition, Revision: "0123456789abcdef", Dirty: true})
	if info.Display != "Byte2Cat v0.1.0 · 0123456789ab-dirty" || info.Version != "0.1.0" || info.Revision != "0123456789abcdef" {
		t.Fatal(info)
	}
	if got := format(Info{Edition: Edition, Version: "dev"}); got.Display != "Byte2Cat vdev · unknown" {
		t.Fatal(got)
	}
}
