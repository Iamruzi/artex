package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArtifactContinuationBudgetsAndMetadataChanges(t *testing.T) {
	root := t.TempDir()
	run := filepath.Join(root, "i1")
	if e := os.Mkdir(run, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(run, "response.txt"), []byte("SECRET_RESPONSE_BODY"), 0600); e != nil {
		t.Fatal(e)
	}
	text := artifactContinuation(root, run)
	if !strings.Contains(text, "response.txt") || strings.Contains(text, "SECRET_RESPONSE_BODY") {
		t.Fatal("missing reference or leaked content")
	}
	saveArtifactCheckpoint(run, nil)
	text = artifactContinuation(root, run)
	if !strings.Contains(text, `"metadata_changed_since_checkpoint":[]`) {
		t.Fatal("unchanged artifact treated as progress")
	}
	if !strings.Contains(text, `"last_run_metadata_changes":["response.txt"]`) {
		t.Fatal("previous run's concrete changes were lost")
	}
	if e := os.WriteFile(filepath.Join(run, "response.txt"), []byte("updated"), 0600); e != nil {
		t.Fatal(e)
	}
	text = artifactContinuation(root, run)
	if !strings.Contains(text, `"metadata_changed_since_checkpoint":["response.txt"]`) {
		t.Fatal("actual metadata change lost")
	}
	for i := range 60 {
		_ = os.WriteFile(filepath.Join(run, fmt.Sprintf("file-%02d-%s", i, strings.Repeat("x", 150))), nil, 0600)
	}
	if len(artifactInventory(root)) > 24 {
		t.Fatal("unbounded inventory")
	}
	if len(artifactContinuation(root, run)) > 6500 {
		t.Fatal("unbounded prompt")
	}
}

func TestArtifactInventorySkipsLinksAndLimitsDepth(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	_ = os.WriteFile(filepath.Join(outside, "outside-secret.txt"), []byte("secret"), 0600)
	// Creating symlinks may require developer mode/admin on Windows. Still test
	// depth limits when that OS capability is unavailable.
	_ = os.Symlink(outside, filepath.Join(root, "linked-dir"))
	_ = os.Symlink(filepath.Join(outside, "outside-secret.txt"), filepath.Join(root, "linked-file"))
	deep := filepath.Join(root, "one", "two", "three", "four")
	_ = os.MkdirAll(deep, 0700)
	_ = os.WriteFile(filepath.Join(deep, "too-deep.txt"), nil, 0600)
	for _, entry := range artifactInventory(root) {
		if strings.Contains(entry.Path, "linked") || strings.Contains(entry.Path, "too-deep") {
			t.Fatalf("followed a link or exceeded depth: %+v", entry)
		}
	}
}
