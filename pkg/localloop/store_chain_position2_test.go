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

func TestCheckChainGapAtPositionTwo(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "gap2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	ev := ExecutionEvent{
		TenantID: "tnt", InstanceID: "inst", CorrelationID: "corr",
		EventID: "e2", ChainPosition: 2,
		PrevEventHash: chainSentinelHash(),
	}
	if err := checkChain(ctx, tx, ev); err == nil {
		t.Fatal("expected chain gap error")
	}
}

func TestCheckChainPrevHashMismatchAtPositionTwo(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "mis2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_m2"); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev1 := mustSignedEventWithID(t, priv, "tnt_m2", "inst", "corr_m2", 1, chainSentinelHash(), "demo.action", "evt_1")
	canon, err := canonicalizeWithoutSignature(ev1)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	if _, err := StoreEvent(ctx, db, ev1, h[:]); err != nil {
		t.Fatal(err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	ev2 := ExecutionEvent{
		TenantID: "tnt_m2", InstanceID: "inst", CorrelationID: "corr_m2",
		EventID: "evt_2", ChainPosition: 2,
		PrevEventHash: chainSentinelHash(),
	}
	if err := checkChain(ctx, tx, ev2); err == nil {
		t.Fatal("expected prev hash mismatch")
	}
}

func TestFlowBoundsAndModeBadCompletedAt(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "bad_completed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_bc"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_, err = db.ExecContext(ctx, `
INSERT INTO execution_events (
  tenant_id, event_id, correlation_id, instance_id, chain_position,
  prev_event_hash, event_hash, action, status, started_at, completed_at,
  duration_ms, spec_version, body, signature
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"tnt_bc", "evt_bc", "corr_bc", "inst", 1,
		chainSentinelHash(), []byte{1}, "demo.action", "ok",
		now.Format(time.RFC3339Nano), "bad-completed", 1, "v1", `{}`, `{}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = FlowBoundsAndMode(ctx, db, "tnt_bc", "corr_bc")
	if err == nil {
		t.Fatal("expected completed_at parse error")
	}
}
