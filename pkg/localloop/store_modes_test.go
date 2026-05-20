package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"path/filepath"
	"testing"
)

func TestReduceFlowModeViaBounds(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "modes.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	tenant := "tnt_modes"
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	storeWithMode := func(corr, mode string) {
		t.Helper()
		ev := mustSignedEvent(t, priv, tenant, "inst_m", corr, 1, sentinel, "demo.action")
		if mode != "" {
			ev.Attributes["intentproof"] = map[string]any{"mode": mode}
		}
		canon, err := canonicalizeWithoutSignature(ev)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(canon)
		if _, err := StoreEvent(ctx, db, ev, h[:]); err != nil {
			t.Fatal(err)
		}
	}

	storeWithMode("corr_full", modeFull)
	_, _, got, err := FlowBoundsAndMode(ctx, db, tenant, "corr_full")
	if err != nil || got != modeFull {
		t.Fatalf("full: mode=%s err=%v", got, err)
	}

	storeWithMode("corr_unknown", "custom")
	_, _, got, err = FlowBoundsAndMode(ctx, db, tenant, "corr_unknown")
	if err != nil || got != defaultMode {
		t.Fatalf("unknown: mode=%s err=%v", got, err)
	}

	storeWithMode("corr_default", "")
	_, _, got, err = FlowBoundsAndMode(ctx, db, tenant, "corr_default")
	if err != nil || got != modeOperational {
		t.Fatalf("default attr: mode=%s err=%v", got, err)
	}
}

func TestComputeMerkleRootAndHexRoot(t *testing.T) {
	h1 := []byte{1, 2, 3}
	h2 := []byte{4, 5, 6}
	root := ComputeMerkleRoot([]EventRow{
		{EventID: "e1", Hash: h1},
		{EventID: "e2", Hash: h2},
	})
	if len(root) == 0 {
		t.Fatal("empty root")
	}
	if HexRoot(root) == "" {
		t.Fatal("hex root")
	}
}
