package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
)

func TestCheckChainRejectsWrongFirstPrevHash(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "chain1.db"))
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
		EventID: "e1", ChainPosition: 1,
		PrevEventHash: "sha256:deadbeef",
	}
	err = checkChain(ctx, tx, ev)
	if err == nil || !errors.Is(err, ErrChainConflict) {
		t.Fatalf("err=%v", err)
	}
}

func TestCheckChainRejectsMissingPreviousEvent(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "chain_gap.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_gap"); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	ev := ExecutionEvent{
		TenantID: "tnt_gap", InstanceID: "inst", CorrelationID: "corr",
		EventID: "e2", ChainPosition: 2,
		PrevEventHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
	err = checkChain(ctx, tx, ev)
	if err == nil || !errors.Is(err, ErrChainConflict) {
		t.Fatalf("err=%v", err)
	}
}

func TestCheckChainRejectsPrevHashMismatch(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "chain_mismatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_pm"); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	ev1 := mustSignedEvent(t, priv, "tnt_pm", "inst", "corr_pm", 1, sentinel, "demo.action")
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
		TenantID: "tnt_pm", InstanceID: "inst", CorrelationID: "corr_pm",
		EventID: "e2", ChainPosition: 2,
		PrevEventHash: sentinel,
	}
	err = checkChain(ctx, tx, ev2)
	if err == nil || !errors.Is(err, ErrChainConflict) {
		t.Fatalf("err=%v", err)
	}
}

func TestCheckChainAllowsSameEventIDReinsert(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "chain_same.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_same"); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	ev := mustSignedEvent(t, priv, "tnt_same", "inst", "corr_same", 1, sentinel, "demo.action")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	if _, err := StoreEvent(ctx, db, ev, h[:]); err != nil {
		t.Fatal(err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := checkChain(ctx, tx, ev); err != nil {
		t.Fatal(err)
	}
}
