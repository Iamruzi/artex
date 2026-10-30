package evidence

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestEvidenceBodyWriteFlushAndReadback(t *testing.T) {
	store := New(nil, nil, t.TempDir())
	body := []byte("retained evidence fixture")
	want := fmt.Sprintf("%x", sha256.Sum256(body))
	hash, err := store.writeBody(bytes.NewReader(body), int64(len(body)), want)
	if err != nil || hash != want {
		t.Fatal(hash, err)
	}
	path, err := hashPath(store.Dir, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyFile(path, hash, int64(len(body))); err != nil {
		t.Fatal(err)
	}
	if _, err = store.writeBody(bytes.NewReader(body), int64(len(body))+1, want); err == nil {
		t.Fatal("accepted incomplete body")
	}
}
