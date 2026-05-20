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

func TestCheckChainQueryCancelledContext(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "ctxcancel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	cancel()

	ev := ExecutionEvent{
		TenantID: "tnt", InstanceID: "inst", CorrelationID: "corr",
		EventID: "e2", ChainPosition: 2,
		PrevEventHash: chainSentinelHash(),
	}
	if err := checkChain(ctx, tx, ev); err == nil {
		t.Fatal("expected cancelled query error")
	}
}

func TestStoreEventBodyJSONMarshalError(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "bodymarshal.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_bm"); err != nil {
		t.Fatal(err)
	}
	ev := ExecutionEvent{
		Schema:        "intentproof.event.v1",
		EventID:       "evt_bad",
		TenantID:      "tnt_bm",
		InstanceID:    "inst",
		CorrelationID: "corr",
		ChainPosition: 1,
		PrevEventHash: chainSentinelHash(),
		Action:        "demo.action",
		Status:        "ok",
		SpecVersion:   "v1",
		Attributes:    map[string]any{"bad": make(chan int)},
		Signature:     Signature{Alg: "ed25519", Value: "AA=="},
	}
	_, err = StoreEvent(ctx, db, ev, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected marshal error")
	}
}

func TestBuildVerifierFlowJSONInvalidStoredBody(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "badbody.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_bb"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	snap := FlowSnapshot{
		Schema: "intentproof.flow.v1", FlowID: "flow_bb", TenantID: "tnt_bb",
		CorrelationID: "corr_bb",
		Window: SnapshotWindow{
			OpenedAt: now, ClosedAt: now.Add(time.Second), ClosureReason: "event_committed",
		},
		InstrumentationMode: "operational",
		FlowMerkleRoot:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SnapshotURI:         "local://snapshot/flow_bb",
	}
	if err := UpsertFlow(ctx, db, snap); err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO execution_events (
  tenant_id, event_id, correlation_id, instance_id, chain_position,
  prev_event_hash, event_hash, action, status, started_at, completed_at,
  duration_ms, spec_version, body, signature
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"tnt_bb", "evt_bb", "corr_bb", "inst_bb", 1,
		chainSentinelHash(), []byte{1}, "demo.action", "ok",
		now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano),
		1, "v1", "{not-json", `{}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = BuildVerifierFlowJSON(ctx, db, "tnt_bb", "corr_bb")
	if err == nil {
		t.Fatal("expected decode event body error")
	}
}

func TestLoadFlowEventsScanErrorViaClosedDB(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "loadclosed.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	_, err = LoadFlowEvents(context.Background(), db, "tnt", "corr")
	if err == nil {
		t.Fatal("expected query error")
	}
}

func TestUpsertFlowBeginTxOnClosedDB(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "upsertbegin.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	now := time.Now().UTC()
	err = UpsertFlow(context.Background(), db, FlowSnapshot{
		Schema: "intentproof.flow.v1", FlowID: "f", TenantID: "tnt", CorrelationID: "c",
		Window: SnapshotWindow{OpenedAt: now, ClosedAt: now, ClosureReason: "event_committed"},
	})
	if err == nil {
		t.Fatal("expected begin tx error")
	}
}

func TestStoreEventOccupiedPositionConflict(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "occupied.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_oc"); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev1 := mustSignedEventWithID(t, priv, "tnt_oc", "inst", "corr_oc", 1, chainSentinelHash(), "demo.action", "evt_a")
	canon, err := canonicalizeWithoutSignature(ev1)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	if _, err := StoreEvent(ctx, db, ev1, h[:]); err != nil {
		t.Fatal(err)
	}
	ev2 := mustSignedEventWithID(t, priv, "tnt_oc", "inst", "corr_oc", 1, chainSentinelHash(), "demo.action", "evt_b")
	canon2, err := canonicalizeWithoutSignature(ev2)
	if err != nil {
		t.Fatal(err)
	}
	h2 := sha256.Sum256(canon2)
	_, err = StoreEvent(ctx, db, ev2, h2[:])
	if err == nil {
		t.Fatal("expected occupied chain position error")
	}
}

func chainSentinelHash() string {
	return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}
