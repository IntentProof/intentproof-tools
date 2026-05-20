package localloop

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestUpsertFlowClosedDB(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "upsertclosed.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	now := time.Now().UTC()
	err = UpsertFlow(context.Background(), db, FlowSnapshot{
		Schema: "intentproof.flow.v1", FlowID: "f", TenantID: "tnt",
		CorrelationID: "c",
		Window:        SnapshotWindow{OpenedAt: now, ClosedAt: now, ClosureReason: "event_committed"},
	})
	if err == nil {
		t.Fatal("expected upsert error on closed db")
	}
}
