package db

import (
	"fmt"
	"testing"
)

func TestNodesPageSearchPagingAndIsolation(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	first, err := d.CreateExploration("test", "broadcast first")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, first)
	second, err := d.CreateExploration("test", "broadcast second")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, second)
	es := d.Exploration(first)
	a, err := es.AddNode("fact", map[string]any{"summary": "needle-alpha"}, 0, "confirmed", "worker-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := es.AddNode("fact", map[string]any{"summary": "unrelated-beta"}, 0, "confirmed", "worker-b", nil)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := d.Exploration(second).AddNode("fact", map[string]any{"summary": "needle-alpha"}, 0, "confirmed", "worker-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := es.Link(a, "yields", b); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{fmt.Sprint(a), "#" + fmt.Sprint(a), "needle-alpha"} {
		nodes, total, err := es.NodesPage(NodeFilter{Query: query}, 1, 50)
		if err != nil || total != 1 || len(nodes) != 1 || nodes[0].ID != a {
			t.Fatalf("query=%q total=%d nodes=%v err=%v", query, total, nodes, err)
		}
	}
	for page, want := range []int64{b, a} {
		nodes, total, err := es.NodesPage(NodeFilter{}, page+1, 1)
		if err != nil || total != 2 || len(nodes) != 1 || nodes[0].ID != want {
			t.Fatalf("page %d: total=%d nodes=%v err=%v", page+1, total, nodes, err)
		}
	}
	nodes, err := es.NodesByIDs([]int64{a, foreign})
	if err != nil || len(nodes) != 1 || nodes[0].ID != a {
		t.Fatalf("cross-task nodes: %v %v", nodes, err)
	}
	edges, err := es.EdgesTouching([]int64{a})
	if err != nil || len(edges) != 1 || edges[0].From != a || edges[0].To != b {
		t.Fatalf("edges: %v %v", edges, err)
	}
}
