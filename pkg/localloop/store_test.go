package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
