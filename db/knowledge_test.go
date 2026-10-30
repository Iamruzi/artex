package db

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestKnowledgeVisibilityProvenanceAndSearch(t *testing.T) {
	d := goalProofDB(t)
	row, err := d.CreateTask("knowledge visibility fixture", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.Exec(`DELETE FROM tasks WHERE id=$1`, row.ID)
		d.Exec(`DELETE FROM explorations WHERE id=$1`, row.ExplorationID)
	})
	marker := fmt.Sprintf("knowledge-fixture-%d", row.ID)
	makeEntry := func(state string, scope *int64, expires *time.Time) *KnowledgeEntry {
		t.Helper()
		e, err := d.SaveKnowledge(t.Context(), KnowledgeEntry{Title: marker, Kind: "negative", Product: "Fixture", CVEs: []string{"cve-2099-90001"}, Summary: "synthetic negative reference", Content: "Reference is not a goal proof.", SourceRef: marker, State: state, ScopeTaskID: scope, ExpiresAt: expires})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { d.Exec(`DELETE FROM knowledge_entries WHERE id=$1`, e.ID) })
		return e
	}
	global := makeEntry("active", nil, nil)
	private := makeEntry("active", &row.ID, nil)
	draft := makeEntry("draft", nil, nil)
	past := time.Now().Add(-time.Hour)
	expired := makeEntry("active", nil, &past)
	for _, tc := range []struct {
		task int64
		want int
	}{{0, 1}, {row.ID, 2}, {row.ID + 99999, 1}} {
		entries, err := d.SearchKnowledge(t.Context(), KnowledgeQuery{Query: marker, TaskID: tc.task})
		if err != nil || len(entries) != tc.want {
			t.Fatalf("task=%d entries=%d err=%v", tc.task, len(entries), err)
		}
		for _, e := range entries {
			if e.Content != "" || e.SHA256 == "" || e.SourceRef == "" {
				t.Fatal("summary leaked body or lost provenance")
			}
		}
	}
	if e, err := d.GetKnowledge(t.Context(), private.ID, 0, false); err != nil || e != nil {
		t.Fatal("cross-task private knowledge leak")
	}
	for _, id := range []int64{draft.ID, expired.ID} {
		if e, err := d.GetKnowledge(t.Context(), id, row.ID, false); err != nil || e != nil {
			t.Fatal("inactive knowledge readable")
		}
	}
	e, err := d.GetKnowledge(t.Context(), global.ID, 0, false)
	if err != nil || e.Content == "" {
		t.Fatal("full reference unavailable")
	}
	before := e.SHA256
	e.Content += " Updated reference."
	e, err = d.SaveKnowledge(t.Context(), *e)
	if err != nil || e.SHA256 == before {
		t.Fatal("changed body retained hash")
	}
	entries, err := d.SearchKnowledge(t.Context(), KnowledgeQuery{CVE: "CVE-2099-90001", Product: "Fixture", TaskID: row.ID})
	if err != nil || len(entries) < 2 {
		t.Fatal("CVE/product lookup failed", err)
	}
	if _, err = d.Exec(`UPDATE tasks SET deleted_at=now() WHERE id=$1`, row.ID); err != nil {
		t.Fatal(err)
	}
	if e, err = d.GetKnowledge(t.Context(), private.ID, row.ID, false); err != nil || e != nil {
		t.Fatal("deleted task still exposes references")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = d.SearchKnowledge(ctx, KnowledgeQuery{}); err == nil {
		t.Fatal("cancelled read ignored")
	}
}

func TestKnowledgeLookupCacheHasExpiryAndSizeBudget(t *testing.T) {
	d := goalProofDB(t)
	key := fmt.Sprintf("fixture/%d", time.Now().UnixNano())
	t.Cleanup(func() { d.Exec(`DELETE FROM knowledge_lookup_cache WHERE key=$1`, key) })
	if err := d.SaveKnowledgeCache(t.Context(), key, []byte(`{"candidate":true}`)); err != nil {
		t.Fatal(err)
	}
	if raw, err := d.KnowledgeCache(t.Context(), key); err != nil || len(raw) == 0 {
		t.Fatal("cache missing", err)
	}
	if _, err := d.Exec(`UPDATE knowledge_lookup_cache SET expires_at=now()-interval '1 second' WHERE key=$1`, key); err != nil {
		t.Fatal(err)
	}
	if raw, err := d.KnowledgeCache(t.Context(), key); err != nil || len(raw) != 0 {
		t.Fatal("expired cache returned", err)
	}
	if err := d.SaveKnowledgeCache(t.Context(), key+"-replacement", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM knowledge_lookup_cache WHERE key=$1`, key+"-replacement") })
	var stale int
	if err := d.QueryRow(`SELECT count(*) FROM knowledge_lookup_cache WHERE key=$1`, key).Scan(&stale); err != nil || stale != 0 {
		t.Fatal("expired cache not reclaimed", err)
	}
	if err := d.SaveKnowledgeCache(t.Context(), key, make([]byte, (1<<20)+1)); err == nil {
		t.Fatal("unbounded cache accepted")
	}
}
