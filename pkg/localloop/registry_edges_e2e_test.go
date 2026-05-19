package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
)

func TestRegisterSDKInstanceRejectsBadKeyLength(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "reg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := RegisterSDKInstance(context.Background(), db, "tnt_r", "inst", []byte("short")); err == nil {
		t.Fatal("expected error")
	}
}

func TestEnsureTenantIdempotent(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := EnsureTenant(ctx, db, "tnt_a"); err != nil {
		t.Fatal(err)
	}
	if err := EnsureTenant(ctx, db, "tnt_a"); err != nil {
		t.Fatal(err)
	}
}

func TestLookupPublicKeyUnknownInstance(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "lookup.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = lookupPublicKey(context.Background(), db, "tnt_x", "missing")
	if err != ErrUnknownSDK {
		t.Fatalf("got %v", err)
	}
}

func TestBootstrapLocalRegistryMissingKeypairOK(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "boot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	home := filepath.Join(t.TempDir(), "home")
	if err := BootstrapLocalRegistry(context.Background(), db, home); err != nil {
		t.Fatal(err)
	}
}

func TestSignExecutionEventRoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := mustSignedEvent(t, priv, "tnt_s", "inst_s", "corr_s", 1,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000", "act")
	if ev.Signature.Value == "" {
		t.Fatal("expected signature")
	}
}
