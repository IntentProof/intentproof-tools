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

func TestStoreEventRejectsChainGap(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "gap.db"))
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
	ev := mustSignedEvent(t, priv, "tnt_gap", "inst_gap", "corr_gap", 2, sentinel, "demo.action")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	_, err = StoreEvent(ctx, db, ev, h[:])
	if err == nil {
		t.Fatal("expected chain gap error")
	}
	if !errors.Is(err, ErrChainConflict) {
		t.Fatalf("got %v", err)
	}
}

func TestStoreEventRejectsWrongFirstPrevHash(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "firstprev.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := mustSignedEvent(t, priv, "tnt_fp", "inst_fp", "corr_fp", 1,
		"sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"demo.action")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	_, err = StoreEvent(ctx, db, ev, h[:])
	if err == nil {
		t.Fatal("expected sentinel error")
	}
	if !errors.Is(err, ErrChainConflict) {
		t.Fatalf("got %v", err)
	}
}

func TestStoreEventRejectsPrevHashMismatch(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "prevmis.db"))
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
	ev1 := mustSignedEvent(t, priv, "tnt_pm", "inst_pm", "corr_pm", 1, sentinel, "a1")
	c1, err := canonicalizeWithoutSignature(ev1)
	if err != nil {
		t.Fatal(err)
	}
	h1 := sha256.Sum256(c1)
	if _, err := StoreEvent(ctx, db, ev1, h1[:]); err != nil {
		t.Fatal(err)
	}

	ev2 := mustSignedEvent(t, priv, "tnt_pm", "inst_pm", "corr_pm", 2, sentinel, "a2")
	c2, err := canonicalizeWithoutSignature(ev2)
	if err != nil {
		t.Fatal(err)
	}
	h2 := sha256.Sum256(c2)
	_, err = StoreEvent(ctx, db, ev2, h2[:])
	if err == nil {
		t.Fatal("expected prev hash mismatch")
	}
	if !errors.Is(err, ErrChainConflict) {
		t.Fatalf("got %v", err)
	}
}

func TestFlowBoundsAndModeEmptyCorrelation(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "bounds_empty.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	started, closed, mode, err := FlowBoundsAndMode(context.Background(), db, "tnt", "no_events")
	if err != nil {
		t.Fatal(err)
	}
	if !started.IsZero() || !closed.IsZero() {
		t.Fatalf("bounds=%v %v", started, closed)
	}
	if mode != defaultMode {
		t.Fatalf("mode=%s", mode)
	}
}

func TestGetFlowByCorrelationIDMissing(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "getflow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = GetFlowByCorrelationID(context.Background(), db, "tnt", "missing")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildVerifierFlowJSONMissingFlow(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "buildver.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = BuildVerifierFlowJSON(context.Background(), db, "tnt", "corr_missing")
	if err == nil {
		t.Fatal("expected error")
	}
}
