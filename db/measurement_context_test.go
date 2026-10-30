package db

import (
	"context"
	"testing"
)

func TestMeasurementMetadataHonorsCancelledDBContext(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	exp, err := d.CreateExploration("measurement cancelled metadata", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, exp)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = d.Exploration(exp).AddNodeContext(ctx, KindHint, map[string]any{"measurement": "not executed"}, 0, "active", "http-measurement/v1", nil); err == nil {
		t.Fatal("cancelled metadata write succeeded")
	}
	if _, err = d.Assets().ListTaskScopeContext(ctx, 1); err == nil {
		t.Fatal("cancelled scope query ignored context")
	}
	nodes, err := d.Exploration(exp).ListByKind(KindHint, 10)
	if err != nil || len(nodes) != 0 {
		t.Fatal("cancelled write left a hint", err)
	}
}
