package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreEventAcceptsUppercaseHexInPrevEventHash(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "chaincase.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ev1 := mustSignedEvent(t, priv, "tnt_x", "inst_x", "corr_x", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"a1")
	c1, err := canonicalizeWithoutSignature(ev1)
	if err != nil {
		t.Fatal(err)
	}
	h1 := sha256.Sum256(c1)
	if _, err := StoreEvent(ctx, db, ev1, h1[:]); err != nil {
		t.Fatalf("store ev1: %v", err)
	}

	prevUpper := "sha256:" + strings.ToUpper(hex.EncodeToString(h1[:]))
	ev2 := mustSignedEvent(t, priv, "tnt_x", "inst_x", "corr_x", 2, prevUpper, "a2")
	c2, err := canonicalizeWithoutSignature(ev2)
	if err != nil {
		t.Fatal(err)
	}
	h2 := sha256.Sum256(c2)
	if _, err := StoreEvent(ctx, db, ev2, h2[:]); err != nil {
		t.Fatalf("store ev2 with uppercase prev hex: %v", err)
	}
}

func TestStoreEventRejectsSecondEventAtSameChainSlot(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "forkslot.db"))
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
	evA := mustSignedEventWithID(t, priv, "tnt_f", "inst_f", "corr_f", 1, sentinel, "a1", "evt_slot_a")
	cA, err := canonicalizeWithoutSignature(evA)
	if err != nil {
		t.Fatal(err)
	}
	hA := sha256.Sum256(cA)
	if _, err := StoreEvent(ctx, db, evA, hA[:]); err != nil {
		t.Fatalf("store first: %v", err)
	}

	evB := mustSignedEventWithID(t, priv, "tnt_f", "inst_f", "corr_f", 1, sentinel, "a1b", "evt_slot_b")
	cB, err := canonicalizeWithoutSignature(evB)
	if err != nil {
		t.Fatal(err)
	}
	hB := sha256.Sum256(cB)
	_, err = StoreEvent(ctx, db, evB, hB[:])
	if err == nil {
		t.Fatal("expected chain conflict for duplicate chain slot")
	}
	if !errors.Is(err, ErrChainConflict) {
		t.Fatalf("want ErrChainConflict, got %v", err)
	}
}

func TestStoreEventIdempotentSameEventID(t *testing.T) {
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

	ev1 := mustSignedEvent(t, priv, "tnt_i", "inst_i", "corr_i", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"a1")
	c1, err := canonicalizeWithoutSignature(ev1)
	if err != nil {
		t.Fatal(err)
	}
	h1 := sha256.Sum256(c1)
	inserted1, err := StoreEvent(ctx, db, ev1, h1[:])
	if err != nil || !inserted1 {
		t.Fatalf("first insert: inserted=%v err=%v", inserted1, err)
	}
	inserted2, err := StoreEvent(ctx, db, ev1, h1[:])
	if err != nil {
		t.Fatalf("second insert: %v", err)
	}
	if inserted2 {
		t.Fatal("expected inserted=false on replay")
	}
}
