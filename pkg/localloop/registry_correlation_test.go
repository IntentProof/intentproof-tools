package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
)

func TestLoadSDKPublicKeysForCorrelationAfterStore(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	tenant := "tnt_keys"
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if err := RegisterSDKInstance(ctx, db, tenant, "inst_k", pub); err != nil {
		t.Fatal(err)
	}

	sentinel := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	ev := mustSignedEvent(t, priv, tenant, "inst_k", "corr_keys", 1, sentinel, "act")
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	if _, err := StoreEvent(ctx, db, ev, h[:]); err != nil {
		t.Fatal(err)
	}

	keys, err := LoadSDKPublicKeysForCorrelation(ctx, db, tenant, "corr_keys")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys["inst_k:k1"]) != ed25519.PublicKeySize {
		t.Fatalf("keys=%v", keys)
	}
}

func TestVerifyEventSignatureRejectsBadBase64(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "sig.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterSDKInstance(ctx, db, "tnt_sig", "inst_sig", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}

	ev := mustSignedEvent(t, priv, "tnt_sig", "inst_sig", "corr_sig", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000", "act")
	ev.Signature.Value = "%%%not-base64%%%"
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(canon)
	err = verifyEventSignature(ctx, db, ev, d[:])
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyEventSignatureRejectsWrongSignature(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "sigbad.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterSDKInstance(ctx, db, "tnt_sb", "inst_sb", priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}

	ev := mustSignedEvent(t, priv, "tnt_sb", "inst_sb", "corr_sb", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000", "act")
	ev.Signature.Value = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	canon, err := canonicalizeWithoutSignature(ev)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(canon)
	err = verifyEventSignature(ctx, db, ev, d[:])
	if err == nil {
		t.Fatal("expected verification failure")
	}
	if !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("got %v", err)
	}
}

func TestLookupPublicKeyRejectsStoredBadLength(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "badlen.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_bl"); err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO sdk_instances (tenant_id, instance_id, public_key, registered_at, revoked_at)
VALUES (?, ?, ?, ?, NULL)`,
		"tnt_bl", "inst_bl", []byte("short"), "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	_, err = lookupPublicKey(ctx, db, "tnt_bl", "inst_bl")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrUnknownSDK) {
		t.Fatalf("got %v", err)
	}
}

func TestSignExecutionEventAttachesSignature(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := ExecutionEvent{
		Schema:        "intentproof.event.v1",
		EventID:       "evt_sign",
		TenantID:      "tnt",
		InstanceID:    "inst",
		CorrelationID: "corr",
		PrevEventHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		ChainPosition: 1,
		Action:        "act",
		Status:        "ok",
		SpecVersion:   "1.0.0",
	}
	signed, err := SignExecutionEvent(ev, priv)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Signature.Value == "" {
		t.Fatal("expected signature")
	}
}
