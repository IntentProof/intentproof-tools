package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreLoadEventsJSONLFullChain(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "chainload.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_chain"); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterSDKInstance(ctx, db, "tnt_chain", "inst_chain", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}

	prev := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	for i, action := range []string{"a1", "a2", "a3"} {
		ev := mustSignedEvent(t, priv, "tnt_chain", "inst_chain", "corr_chain", i+1, prev, action)
		canon, err := canonicalizeWithoutSignature(ev)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(canon)
		if _, err := StoreEvent(ctx, db, ev, h[:]); err != nil {
			t.Fatal(err)
		}
		prev = FormatChainHash(h)
	}

	jsonl, err := LoadEventsJSONL(ctx, db, "tnt_chain", "corr_chain")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(jsonl), "a1") || !strings.Contains(string(jsonl), "a3") {
		t.Fatalf("jsonl=%s", jsonl)
	}
	rows, err := LoadFlowEvents(ctx, db, "tnt_chain", "corr_chain")
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
}

func TestReduceFlowModeUnknownFallsBackOperational(t *testing.T) {
	if got := reduceFlowMode([]string{"weird-mode", "full"}); got != modeOperational {
		t.Fatalf("got=%s", got)
	}
}

func TestFlowBoundsAndModeWithStoredEvents(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "bounds.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_b"); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	ev := mustSignedEvent(t, priv, "tnt_b", "inst_b", "corr_b", 1, sentinel, "demo.action")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	if _, err := StoreEvent(ctx, db, ev, h[:]); err != nil {
		t.Fatal(err)
	}

	started, closed, mode, err := FlowBoundsAndMode(ctx, db, "tnt_b", "corr_b")
	if err != nil {
		t.Fatal(err)
	}
	if started.IsZero() || closed.IsZero() {
		t.Fatal("expected bounds")
	}
	if mode == "" {
		t.Fatal("expected mode")
	}
	_ = time.Now()
}
