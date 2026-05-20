package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureTenantFailsOnClosedDB(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "tenantclosed.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if err := EnsureTenant(context.Background(), db, "tnt"); err == nil {
		t.Fatal("expected ensure tenant error")
	}
}

func TestRegisterSDKInstanceFailsOnClosedDB(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "regclosed.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if err := RegisterSDKInstance(context.Background(), db, "tnt", "inst", priv.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("expected register error")
	}
}

func TestLoadSDKPublicKeysFailsOnClosedDB(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "keysclosed.db"))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := LoadSDKPublicKeysForCorrelation(context.Background(), db, "tnt", "corr"); err == nil {
		t.Fatal("expected load keys error")
	}
}

func TestBootstrapLocalRegistryReadError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read mode 000 files")
	}
	home := t.TempDir()
	sdkDir := filepath.Join(home, ".intentproof", "sdk-node")
	if err := os.MkdirAll(sdkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(sdkDir, "keypair.json")
	if err := os.WriteFile(keyPath, []byte(`{"privateKey":"x","instanceId":"i"}`), 0o000); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "bootread.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	err = BootstrapLocalRegistry(context.Background(), db, home)
	if err == nil {
		t.Fatal("expected read sdk keypair error")
	}
}

func TestSignExecutionEventCanonicalizeError(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := ExecutionEvent{
		Schema:        "intentproof.event.v1",
		EventID:       "e1",
		TenantID:      "tnt",
		InstanceID:    "inst",
		CorrelationID: "corr",
		ChainPosition: 1,
		PrevEventHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		Action:        "demo.action",
		Status:        "ok",
		SpecVersion:   "1.0.0",
		Attributes:    map[string]any{"bad": make(chan int)},
	}
	if _, err := SignExecutionEvent(ev, priv); err == nil {
		t.Fatal("expected canonicalize error")
	}
}
