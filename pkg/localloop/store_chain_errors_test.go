package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreEventRejectsBadPrevHashFormat(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "badprev.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := mustSignedEvent(t, priv, "tnt_bad", "inst_bad", "corr_bad", 1,
		"not-a-hash", "demo.action")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	if _, err := StoreEvent(ctx, db, ev, h[:]); err == nil {
		t.Fatal("expected prev hash error")
	}
}

func TestLoadFlowEventsEmptyCorrelation(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "load.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := LoadFlowEvents(context.Background(), db, "tnt_x", "corr_missing")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("rows=%d", len(rows))
	}
}

func TestUpsertFlowAndGetSnapshot(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "upsert.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_up"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC)
	snap := FlowSnapshot{
		Schema:        "intentproof.flow.v1",
		FlowID:        "flow_up",
		TenantID:      "tnt_up",
		CorrelationID: "corr_up",
		Window: SnapshotWindow{
			OpenedAt:      now,
			ClosedAt:      now.Add(time.Second),
			ClosureReason: "event_committed",
		},
		InstrumentationMode: "operational",
		FlowMerkleRoot:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SnapshotURI:         "local://snapshot/flow_up",
	}
	if err := UpsertFlow(ctx, db, snap); err != nil {
		t.Fatal(err)
	}
	got, err := GetFlowByCorrelationID(ctx, db, "tnt_up", "corr_up")
	if err != nil {
		t.Fatal(err)
	}
	if got.FlowID != "flow_up" {
		t.Fatalf("flow=%s", got.FlowID)
	}
}
