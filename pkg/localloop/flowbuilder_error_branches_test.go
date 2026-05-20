package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreEventIdempotentNoRowsInserted(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "idempotent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := mustSignedEvent(t, priv, "tnt_idem", "inst_idem", "corr_idem", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"demo.action")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	inserted, err := StoreEvent(ctx, db, ev, h[:])
	if err != nil {
		t.Fatal(err)
	}
	if !inserted {
		t.Fatal("expected first insert")
	}
	inserted, err = StoreEvent(ctx, db, ev, h[:])
	if err != nil {
		t.Fatal(err)
	}
	if inserted {
		t.Fatal("expected idempotent replay")
	}
}

func TestFlowBuilderHandleLoadEventsError(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "fbload.db"))
	if err != nil {
		t.Fatal(err)
	}
	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()

	fb := NewFlowBuilder(db, nw)
	env := CommitEnvelope{TenantID: "tnt", CorrelationID: "corr", EventID: "e1"}
	raw, _ := json.Marshal(env)
	_ = db.Close()
	if err := fb.handle(context.Background(), raw); err == nil {
		t.Fatal("expected load events error")
	}
}

func TestFlowBuilderRunSubscribeError(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "fbsub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	nw := &NATSWrapper{Client: nil, js: nil}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := NewFlowBuilder(db, nw).Run(ctx); err == nil {
		t.Fatal("expected subscribe error")
	}
}

func TestFlowBuilderHandleBoundsError(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "fbbounds.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	body := `{"schema":"intentproof.event.v1","event_id":"e1"}`
	_, err = db.ExecContext(ctx, `
INSERT INTO execution_events (
  tenant_id, event_id, correlation_id, instance_id, chain_position,
  prev_event_hash, event_hash, action, status, started_at, completed_at,
  duration_ms, spec_version, body, signature
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"tnt_b", "e1", "corr_b", "inst", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		[]byte{1}, "demo.action", "ok", "bad-ts", "bad-ts", 1, "1.0.0", body, `{}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = now

	nw, err := StartEmbeddedNATS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Shutdown()

	fb := NewFlowBuilder(db, nw)
	env := CommitEnvelope{TenantID: "tnt_b", CorrelationID: "corr_b", EventID: "e1"}
	raw, _ := json.Marshal(env)
	if err := fb.handle(ctx, raw); err == nil {
		t.Fatal("expected bounds error")
	}
}
