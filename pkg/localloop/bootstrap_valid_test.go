package localloop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestBootstrapLocalRegistryRegistersValidKeypair(t *testing.T) {
	home := t.TempDir()
	sdkDir := filepath.Join(home, ".intentproof", "sdk-node")
	if err := os.MkdirAll(sdkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	kp := `{"privateKey":"` + base64.StdEncoding.EncodeToString(seed) + `","instanceId":"inst_valid"}`
	if err := os.WriteFile(filepath.Join(sdkDir, "keypair.json"), []byte(kp), 0o600); err != nil {
		t.Fatal(err)
	}

	db, err := OpenDB(filepath.Join(t.TempDir(), "boot_valid.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := BootstrapLocalRegistry(context.Background(), db, home); err != nil {
		t.Fatal(err)
	}
	pub, err := lookupPublicKey(context.Background(), db, LocalTenantID, "inst_valid")
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatal("bad pubkey")
	}
	_ = priv
}
