package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestUpsertFlowUpdatesExistingRecord(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "upsert_upd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_upd"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC)
	snap := FlowSnapshot{
		Schema:        "intentproof.flow.v1",
		FlowID:        "flow_upd",
		TenantID:      "tnt_upd",
		CorrelationID: "corr_upd",
		Window: SnapshotWindow{
			OpenedAt:      now,
			ClosedAt:      now.Add(time.Second),
			ClosureReason: "event_committed",
		},
		InstrumentationMode: "operational",
		FlowMerkleRoot:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SnapshotURI:         "local://snapshot/flow_upd",
	}
	if err := UpsertFlow(ctx, db, snap); err != nil {
		t.Fatal(err)
	}
	snap.Window.ClosedAt = now.Add(2 * time.Second)
	snap.FlowMerkleRoot = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := UpsertFlow(ctx, db, snap); err != nil {
		t.Fatal(err)
	}
	got, err := GetFlowByCorrelationID(ctx, db, "tnt_upd", "corr_upd")
	if err != nil {
		t.Fatal(err)
	}
	if got.FlowMerkleRoot != snap.FlowMerkleRoot {
		t.Fatalf("root=%s", got.FlowMerkleRoot)
	}
}

func TestStoreEventForkAtCurrentPosition(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "forkcur.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_fc"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP INDEX ux_events_chain_slot`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	body := `{"schema":"intentproof.event.v1"}`
	for _, eid := range []string{"evt_a", "evt_b"} {
		_, err := db.ExecContext(ctx, `
INSERT INTO execution_events (
  tenant_id, event_id, correlation_id, instance_id, chain_position,
  prev_event_hash, event_hash, action, status, started_at, completed_at,
  duration_ms, spec_version, body, signature
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			"tnt_fc", eid, "corr_fc", "inst_fc", 2,
			"sha256:0000000000000000000000000000000000000000000000000000000000000000",
			[]byte{1}, "demo.action", "ok", now, now, 1, "v1", body, `{}`,
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := mustSignedEventWithID(t, priv, "tnt_fc", "inst_fc", "corr_fc", 2,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"demo.action", "evt_c")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	_, err = StoreEvent(ctx, db, ev, h[:])
	if err == nil {
		t.Fatal("expected fork at current position")
	}
	if !errors.Is(err, ErrChainConflict) {
		t.Fatalf("got %v", err)
	}
}

func TestValidateTenantIDRejectsIllegalCharacters(t *testing.T) {
	for _, tenant := range []string{"", "bad.tenant", "bad*tenant", "bad>tenant"} {
		if err := validateTenantID(tenant); err == nil {
			t.Fatalf("tenant=%q expected error", tenant)
		}
	}
	if err := validateTenantID(LocalTenantID); err != nil {
		t.Fatal(err)
	}
}
