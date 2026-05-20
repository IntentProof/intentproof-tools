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

func TestStoreEventRejectsOccupiedChainPosition(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "occ.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	ev1 := mustSignedEventWithID(t, priv, "tnt_occ", "inst_occ", "corr_occ", 1, sentinel, "a1", "evt_a")
	c1, err := canonicalizeWithoutSignature(ev1)
	if err != nil {
		t.Fatal(err)
	}
	h1 := sha256.Sum256(c1)
	if _, err := StoreEvent(ctx, db, ev1, h1[:]); err != nil {
		t.Fatal(err)
	}

	ev2 := mustSignedEventWithID(t, priv, "tnt_occ", "inst_occ", "corr_occ", 1, sentinel, "a2", "evt_b")
	c2, err := canonicalizeWithoutSignature(ev2)
	if err != nil {
		t.Fatal(err)
	}
	h2 := sha256.Sum256(c2)
	_, err = StoreEvent(ctx, db, ev2, h2[:])
	if err == nil {
		t.Fatal("expected chain conflict")
	}
	if !errors.Is(err, ErrChainConflict) {
		t.Fatalf("got %v", err)
	}
}

func TestStoreEventForkedChainAtPreviousPosition(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "forkprev.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_fork"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP INDEX ux_events_chain_slot`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	// Insert two events at chain_position 1 to trigger fork at previous position lookup.
	for i, eid := range []string{"evt_1a", "evt_1b"} {
		_, err := db.ExecContext(ctx, `
			INSERT INTO execution_events (
			  tenant_id, event_id, correlation_id, instance_id, chain_position,
			  prev_event_hash, event_hash, action, status, started_at, completed_at,
			  duration_ms, spec_version, body, signature
			) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			"tnt_fork", eid, "corr_fork", "inst_fork", 1,
			"sha256:0000000000000000000000000000000000000000000000000000000000000000",
			[]byte{byte(i)}, "demo.action", "ok", now, now, 1, "v1", "{}", "{}",
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := mustSignedEventWithID(t, priv, "tnt_fork", "inst_fork", "corr_fork", 2,
		"sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"demo.action", "evt_2")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	_, err = StoreEvent(ctx, db, ev, h[:])
	if err == nil {
		t.Fatal("expected fork at previous position")
	}
	if !errors.Is(err, ErrChainConflict) {
		t.Fatalf("got %v", err)
	}
}

func TestStoreEventIdempotentDuplicate(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "idem.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	ev := mustSignedEvent(t, priv, "tnt_idem", "inst_idem", "corr_idem", 1, sentinel, "demo.action")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	inserted, err := StoreEvent(ctx, db, ev, h[:])
	if err != nil || !inserted {
		t.Fatalf("first insert inserted=%v err=%v", inserted, err)
	}
	inserted2, err := StoreEvent(ctx, db, ev, h[:])
	if err != nil {
		t.Fatal(err)
	}
	if inserted2 {
		t.Fatal("expected idempotent no-op")
	}
}

func TestFlowModeRankUnknown(t *testing.T) {
	if modeRank("unknown-mode") != 1 {
		t.Fatalf("rank=%d", modeRank("unknown-mode"))
	}
}

func TestQueryEventsScanError(t *testing.T) {
	// Exercise rows.Err after broken query via closed db.
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "closedq.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	_, err = LoadEventsJSONL(context.Background(), db, "tnt", "corr")
	if err == nil {
		t.Fatal("expected query error")
	}
}

func TestBuildVerifierFlowJSONWithEvents(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "build.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_bv"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC)
	snap := FlowSnapshot{
		Schema: "intentproof.flow.v1", FlowID: "flow_bv", TenantID: "tnt_bv",
		CorrelationID:       "corr_bv",
		Window:              SnapshotWindow{OpenedAt: now, ClosedAt: now.Add(time.Second), ClosureReason: "event_committed"},
		InstrumentationMode: "operational",
		FlowMerkleRoot:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SnapshotURI:         "local://snapshot/flow_bv",
	}
	if err := UpsertFlow(ctx, db, snap); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterSDKInstance(ctx, db, "tnt_bv", "inst_bv", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	sentinel := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	ev := mustSignedEvent(t, priv, "tnt_bv", "inst_bv", "corr_bv", 1, sentinel, "demo.action")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	if _, err := StoreEvent(ctx, db, ev, h[:]); err != nil {
		t.Fatal(err)
	}
	raw, err := BuildVerifierFlowJSON(ctx, db, "tnt_bv", "corr_bv")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("expected flow json")
	}
}
